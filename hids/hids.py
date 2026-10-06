"""
HIDS Engine Controller.

Coordinates the end-to-end host intrusion detection pipeline:
Windows Event Collector -> Normalizer -> RuleEngine (from hids.rules) -> Correlator -> Logger (event.json + PowerShell Console).
Loads global configuration from config.yaml, supports continuous monitoring,
graceful shutdown signals, deduplication, and atomic checkpoint persistence.
"""

from collections import deque
import logging
from pathlib import Path
import time
from typing import Any, Deque, Dict, List, Optional, Set, Tuple, Union
import yaml

from hids.collector import WindowsEventCollector, DEFAULT_MONITORED_CHANNELS
from hids.correlator import EventCorrelator, CorrelatedAlert
from hids.normalizer import NormalizedEvent, normalize_event
from hids.rule_engine import RuleEngine, RuleMatch
from hids.rules_parser import RuleParser, DEFAULT_RULES_FILE
from hids.severity import Severity
from logger import (
    get_logger,
    console_event,
    console_alert,
    console_correlation,
    log_security_alert_json,
    log_correlated_alert_json,
    EVENT_JSON_FILE,
)
from paths import (
    DATA_DIR,
    HIDS_COLLECTOR_CHECKPOINT_FILE,
    HIDS_CONFIG_FILE,
    HIDS_EVENTS_FILE,
)
from stop_signal import get_stop_event

try:
    import win32event
    WIN32_EVENT_AVAILABLE = True
except ImportError:
    WIN32_EVENT_AVAILABLE = False


# Default base and config paths
BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = HIDS_CONFIG_FILE


def _data_path(value: Union[str, Path]) -> Path:
    """Config paths may be absolute or relative to the data folder."""
    path = Path(value)
    return path if path.is_absolute() else DATA_DIR / path


def load_config(config_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Load global HIDS configuration from config.yaml.
    Validates structure and provides sensible defaults if file is missing or incomplete.
    """
    cfg_file = Path(config_path) if config_path else DEFAULT_CONFIG_PATH

    defaults = {
        "hids": {
            "enabled": True,
            "channels": list(DEFAULT_MONITORED_CHANNELS),
            "polling_interval": 2,
            "checkpoint": {
                "enabled": True,
                "file": str(HIDS_COLLECTOR_CHECKPOINT_FILE),
            },
            "deduplication": {
                "enabled": True,
            },
            "logging": {
                "enabled": True,
                "json_file": str(HIDS_EVENTS_FILE),
            },
        }
    }

    if not cfg_file.exists():
        return defaults

    try:
        with open(cfg_file, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict) and "hids" in data and isinstance(data["hids"], dict):
            hids_cfg = data["hids"]
            for key, val in hids_cfg.items():
                if isinstance(val, dict) and isinstance(defaults["hids"].get(key), dict):
                    defaults["hids"][key].update(val)
                else:
                    defaults["hids"][key] = val
        return defaults
    except Exception as exc:
        logging.getLogger("IDSIPS").warning("Failed loading %s: %s. Using default config.", cfg_file, exc)
        return defaults


class AlertDeduplicator:
    """
    Bounded TTL-based Alert Deduplication Cache.
    Prevents repeated logging of identical alerts while bounding memory usage.
    """

    def __init__(self, ttl_seconds: float = 300.0, max_entries: int = 2000):
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._entries: Deque[Tuple[float, str]] = deque()
        self._keys: Set[str] = set()

    def _evict_expired(self, now_ts: float):
        """Purge entries older than TTL."""
        cutoff = now_ts - self.ttl_seconds
        while self._entries and self._entries[0][0] < cutoff:
            _, key = self._entries.popleft()
            self._keys.discard(key)

    def is_duplicate(self, fingerprint: str, now_ts: Optional[float] = None) -> bool:
        """Check if fingerprint is already in cache and not expired."""
        curr_ts = now_ts if now_ts is not None else time.time()
        self._evict_expired(curr_ts)
        return fingerprint in self._keys

    def record(self, fingerprint: str, now_ts: Optional[float] = None):
        """Record fingerprint in cache."""
        curr_ts = now_ts if now_ts is not None else time.time()
        self._evict_expired(curr_ts)

        if fingerprint in self._keys:
            return

        if len(self._entries) >= self.max_entries:
            _, old_key = self._entries.popleft()
            self._keys.discard(old_key)

        self._entries.append((curr_ts, fingerprint))
        self._keys.add(fingerprint)


class HIDSEngine:
    """
    Production-grade Windows Host-Based Intrusion Detection Engine.
    """

    def __init__(
        self,
        channels: Optional[List[str]] = None,
        checkpoint_path: Optional[Union[str, Path]] = None,
        poll_interval: Optional[float] = None,
        collector: Optional[WindowsEventCollector] = None,
        rule_engine: Optional[RuleEngine] = None,
        rules_file: Optional[Union[str, Path]] = None,
        correlator: Optional[EventCorrelator] = None,
        deduplicator: Optional[AlertDeduplicator] = None,
        logger: Optional[logging.Logger] = None,
        config_path: Optional[Union[str, Path]] = None,
        json_log_path: Optional[Union[str, Path]] = None,
    ):
        # Load global configuration
        self.config = load_config(config_path)
        hids_settings = self.config.get("hids", {})

        # Channels configuration
        selected_channels = channels or hids_settings.get("channels") or list(DEFAULT_MONITORED_CHANNELS)

        # Polling interval
        if poll_interval is not None:
            self.poll_interval = float(poll_interval)
        else:
            self.poll_interval = float(hids_settings.get("polling_interval", 2))

        # Checkpoint path
        if checkpoint_path is not None:
            resolved_checkpoint = Path(checkpoint_path)
        else:
            cp_file = hids_settings.get("checkpoint", {}).get("file") or HIDS_COLLECTOR_CHECKPOINT_FILE
            resolved_checkpoint = _data_path(cp_file)

        # Logging configuration
        if json_log_path is not None:
            self.json_log_path = Path(json_log_path)
        else:
            json_log_file = hids_settings.get("logging", {}).get("json_file") or HIDS_EVENTS_FILE
            self.json_log_path = _data_path(json_log_file)

        self.logger = logger or get_logger(component="hids")

        # Collector
        self.collector = collector or WindowsEventCollector(
            channels=selected_channels, checkpoint_path=resolved_checkpoint
        )

        # Rule Engine (loads from hids.rules)
        if rule_engine is not None:
            self.rule_engine = rule_engine
        else:
            self.rule_engine = RuleEngine(rules_file=rules_file or DEFAULT_RULES_FILE)

        # Correlator & Deduplicator
        self.correlator = correlator or EventCorrelator()
        self.deduplicator_enabled = bool(hids_settings.get("deduplication", {}).get("enabled", True))
        self.deduplicator = deduplicator or AlertDeduplicator()

        self._running = False
        self._consecutive_collector_errors = 0

    def process_raw_event(
        self, raw_event: Any
    ) -> Tuple[Optional[NormalizedEvent], List[RuleMatch], List[CorrelatedAlert]]:
        """
        Process a single raw event through the complete pipeline:
        1. Normalize
        2. Show live event telemetry on the console (not stored)
        3. Rule evaluation
        4. Correlation
        5. Structured alert logging to event.json and console
        Returns:
            (normalized_event, rule_matches, correlated_alerts)
        """
        try:
            norm_event = normalize_event(raw_event)
        except Exception as e:
            self.logger.warning("Normalizer failed for event: %s", e)
            return None, [], []

        if norm_event is None:
            return None, [], []

        # 1. Show ordinary event on the console only.
        #    Raw telemetry is NOT written to event.json;
        #    event.json stores alerts and correlated alerts only.
        try:
            console_event(norm_event)
        except Exception as e:
            self.logger.debug("Event console output error: %s", e)

        # 2. Rule evaluation
        rule_matches: List[RuleMatch] = []
        try:
            rule_matches = self.rule_engine.evaluate(norm_event)
            for match in rule_matches:
                if match.suppressed:
                    continue

                rec_id = norm_event.record_id if norm_event.record_id is not None else 0
                fingerprint = f"{match.rule_id}:{norm_event.channel}:{norm_event.event_id}:{rec_id}:{norm_event.user}"

                if not self.deduplicator_enabled or not self.deduplicator.is_duplicate(fingerprint):
                    if self.deduplicator_enabled:
                        self.deduplicator.record(fingerprint)

                    # Output colorized alert to PowerShell console
                    console_alert(match)
                       
                    # Write structured alert to event.json
                    log_security_alert_json(match, json_path=self.json_log_path)

        except Exception as e:
            self.logger.error("Rule evaluation error for EventID %s: %s", norm_event.event_id, e)

        # 3. Correlation evaluation
        correlated_alerts: List[CorrelatedAlert] = []
        try:
            correlated_alerts = self.correlator.process_event(norm_event)
            for alert in correlated_alerts:
                # Output colorized correlation alert to PowerShell console
                console_correlation(alert)

                # Write structured correlation alert to event.json
                log_correlated_alert_json(alert, json_path=self.json_log_path)

        except Exception as e:
            self.logger.error("Correlation error for EventID %s: %s", norm_event.event_id, e)

        return norm_event, rule_matches, correlated_alerts

    def monitor_step(self):
        """
        Perform a single polling cycle across all channels:
        Collect -> Process -> Advance Checkpoints for successfully processed events.
        """
        try:
            raw_events, pending_checkpoints = self.collector.collect_all_events()
            self._consecutive_collector_errors = 0
        except Exception as e:
            self._consecutive_collector_errors += 1
            backoff = min(30.0, self.poll_interval * (2 ** min(self._consecutive_collector_errors, 5)))
            self.logger.error(
                "Collector failure during poll cycle (attempt %d): %s. Backing off for %.1fs",
                self._consecutive_collector_errors,
                e,
                backoff,
            )
            time.sleep(backoff)
            return

        processed_checkpoints: Dict[str, int] = {}

        for raw_event in raw_events:
            try:
                norm_event, _, _ = self.process_raw_event(raw_event)
                if norm_event and norm_event.record_id is not None and norm_event.channel:
                    processed_checkpoints[norm_event.channel] = max(
                        processed_checkpoints.get(norm_event.channel, 0),
                        norm_event.record_id,
                    )
            except Exception as ev_err:
                self.logger.error("Failed downstream event processing: %s", ev_err)

        # Advance checkpoints only for events that successfully cleared the pipeline
        if processed_checkpoints:
            try:
                self.collector.commit_checkpoints(processed_checkpoints)
            except Exception as e:
                self.logger.error("Failed to commit checkpoints: %s", e)

        # Periodic cleanup of correlation window memory
        try:
            self.correlator.cleanup_all()
        except Exception:
            pass

    def run(self, stop_event: Any = None):
        """
        Main continuous monitoring loop.
        Gracefully handles service stop signals (win32event or threading.Event).
        """
        self.logger.info("HIDS monitoring started.")
        self._running = True

        try:
            while self._running:
                self.monitor_step()

                # Check stop signal
                if stop_event is not None:
                    if self._wait_for_stop(stop_event, self.poll_interval):
                        self.logger.info("HIDS received stop signal.")
                        break
                else:
                    time.sleep(self.poll_interval)

        except Exception as e:
            self.logger.exception("HIDS monitoring failed with unexpected exception: %s", e)
            raise
        finally:
            self._running = False
            self.logger.info("HIDS monitoring stopped.")

    def stop(self):
        """Stop the monitoring loop."""
        self._running = False

    def _wait_for_stop(self, stop_event: Any, timeout_seconds: float) -> bool:
        """
        Wait on either a threading.Event or a win32event handle.
        Returns True if stop was signaled, False if timeout expired.
        """
        if hasattr(stop_event, "wait") and hasattr(stop_event, "is_set"):
            return stop_event.wait(timeout_seconds)

        if WIN32_EVENT_AVAILABLE:
            try:
                timeout_ms = int(timeout_seconds * 1000)
                res = win32event.WaitForSingleObject(stop_event, timeout_ms)
                return res == win32event.WAIT_OBJECT_0
            except Exception:
                pass

        time.sleep(timeout_seconds)
        return False


def run_hids(stop_event: Any = None):
    """
    Top-level entry point preserving the existing interface.
    """
    engine = HIDSEngine()
    engine.run(stop_event=stop_event)


if __name__ == "__main__":
    # Under the service, stop cleanly when the service stops
    # (None when run by hand: runs until Ctrl+C).
    run_hids(stop_event=get_stop_event())