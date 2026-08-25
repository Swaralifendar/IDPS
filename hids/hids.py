"""
HIDS Engine Controller.

Coordinates the end-to-end intrusion detection pipeline:
Windows Event Collector -> Normalizer -> Rules Engine -> Correlator -> Severity Engine -> Logger.
Supports continuous background monitoring, graceful service stop events, bounded alert deduplication,
and automatic error recovery.
"""

from collections import deque
import logging
from pathlib import Path
import time
from typing import Any, Deque, Dict, List, Optional, Set, Tuple, Union

try:
    import win32event
    WIN32_EVENT_AVAILABLE = True
except ImportError:
    WIN32_EVENT_AVAILABLE = False

from hids.collector import WindowsEventCollector
from hids.correlator import EventCorrelator
from hids.normalizer import NormalizedEvent, normalize_event
from hids.rules import RuleEngine, RuleMatch
from hids.severity import Severity
from logger import get_logger, format_security_alert, format_correlated_alert


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
        checkpoint_path: Optional[Path] = None,
        poll_interval: float = 3.0,
        collector: Optional[WindowsEventCollector] = None,
        rule_engine: Optional[RuleEngine] = None,
        correlator: Optional[EventCorrelator] = None,
        deduplicator: Optional[AlertDeduplicator] = None,
        logger: Optional[logging.Logger] = None,
    ):
        self.poll_interval = poll_interval
        self.logger = logger or get_logger()
        self.collector = collector or WindowsEventCollector(
            channels=channels, checkpoint_path=checkpoint_path
        )
        self.rule_engine = rule_engine or RuleEngine()
        self.correlator = correlator or EventCorrelator()
        self.deduplicator = deduplicator or AlertDeduplicator()
        self._running = False
        self._consecutive_collector_errors = 0

    def process_raw_event(self, raw_event: Any) -> Tuple[Optional[NormalizedEvent], List[RuleMatch], List[Any]]:
        """
        Process a single raw event through the complete pipeline:
        1. Normalize
        2. Log live event telemetry
        3. Rule evaluation
        4. Correlation
        5. Structured alert logging
        Returns:
            (normalized_event, rule_matches, correlated_alerts)
        """
        try:
            norm_event = normalize_event(raw_event)
        except Exception as e:
            self.logger.warning("Normalizer failed for event: %s", e)
            return None, [], []

        # Operational telemetry logging for live event proof
        rec_id_str = f"RecordID: {norm_event.record_id}" if norm_event.record_id is not None else "RecordID: N/A"
        prov_str = f"Provider: {norm_event.provider}" if norm_event.provider else "Provider: N/A"
        self.logger.info(
            "HIDS EVENT | Channel: %s | EventID: %s | %s | %s | Time: %s",
            norm_event.channel or "Unknown",
            norm_event.event_id,
            rec_id_str,
            prov_str,
            norm_event.timestamp,
        )

        rule_matches: List[RuleMatch] = []
        try:
            rule_matches = self.rule_engine.evaluate(norm_event)
            for match in rule_matches:
                if match.suppressed:
                    self.logger.debug(
                        "Suppressed Alert | Rule: %s | Reason: %s",
                        match.rule_id,
                        match.suppression_reason,
                    )
                    continue

                rec_id = norm_event.record_id if norm_event.record_id is not None else 0
                fingerprint = f"{match.rule_id}:{norm_event.channel}:{norm_event.event_id}:{rec_id}:{norm_event.user}"

                if not self.deduplicator.is_duplicate(fingerprint):
                    self.deduplicator.record(fingerprint)
                    alert_line = format_security_alert(match)

                    if match.severity >= Severity.HIGH:
                        self.logger.warning(alert_line)
                    else:
                        self.logger.info(alert_line)

        except Exception as e:
            self.logger.error("Rule evaluation error for EventID %s: %s", norm_event.event_id, e)

        correlated_alerts = []
        try:
            correlated_alerts = self.correlator.process_event(norm_event)
            for alert in correlated_alerts:
                corr_line = format_correlated_alert(alert)
                if alert.severity >= Severity.HIGH:
                    self.logger.warning(corr_line)
                else:
                    self.logger.info(corr_line)
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
    Top-level entry point preserving the existing prototype interface.
    """
    engine = HIDSEngine()
    engine.run(stop_event=stop_event)


if __name__ == "__main__":
    run_hids()