"""
HIDS Event Correlation Engine.

Performs stateful correlation of related Windows security events across sliding
time windows with bounded memory, TTL cleanup, and contextual threat analysis.
"""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Deque, Dict, List, Optional, Set, Tuple

from hids.normalizer import NormalizedEvent
from hids.severity import Severity


@dataclass
class CorrelatedAlert:
    """
    Represents a multi-event correlated security detection.
    """
    correlation_id: str
    name: str
    severity: Severity
    description: str
    mitre_attack: str
    details: str
    events: List[NormalizedEvent] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        """Convert correlated alert to dictionary."""
        return {
            "correlation_id": self.correlation_id,
            "name": self.name,
            "severity": self.severity.value,
            "description": self.description,
            "mitre_attack": self.mitre_attack,
            "details": self.details,
            "timestamp": self.timestamp,
            "event_count": len(self.events),
            "events": [e.to_dict() for e in self.events],
        }


class BoundedTimeWindowBuffer:
    """
    Bounded sliding-window buffer that automatically evicts entries past TTL
    and limits maximum stored keys to prevent unbounded memory growth.
    """

    def __init__(self, ttl_seconds: float, max_keys: int = 1000, max_items_per_key: int = 50):
        self.ttl_seconds = ttl_seconds
        self.max_keys = max_keys
        self.max_items_per_key = max_items_per_key
        self._store: Dict[str, Deque[Tuple[float, NormalizedEvent]]] = {}

    def add(self, key: str, event: NormalizedEvent, now_ts: Optional[float] = None):
        """Add an event under key and perform automatic eviction."""
        if not key:
            return

        ts = now_ts if now_ts is not None else event.timestamp_dt.timestamp()

        # Evict oldest key if capacity exceeded
        if key not in self._store and len(self._store) >= self.max_keys:
            oldest_key = next(iter(self._store))
            del self._store[oldest_key]

        if key not in self._store:
            self._store[key] = deque()

        buffer = self._store[key]
        buffer.append((ts, event))

        # Enforce per-key capacity
        if len(buffer) > self.max_items_per_key:
            buffer.popleft()

        self._cleanup_key(key, ts)

    def get_events(self, key: str, now_ts: Optional[float] = None) -> List[NormalizedEvent]:
        """Get all valid (non-expired) events for key."""
        if key not in self._store:
            return []

        curr_ts = now_ts if now_ts is not None else datetime.now(timezone.utc).timestamp()
        self._cleanup_key(key, curr_ts)

        if key not in self._store:
            return []

        return [item[1] for item in self._store[key]]

    def clear_key(self, key: str):
        """Remove key completely (e.g. after correlation fired)."""
        self._store.pop(key, None)

    def _cleanup_key(self, key: str, curr_ts: float):
        """Remove expired entries for key."""
        if key not in self._store:
            return
        buffer = self._store[key]
        cutoff = curr_ts - self.ttl_seconds
        while buffer and buffer[0][0] < cutoff:
            buffer.popleft()
        if not buffer:
            del self._store[key]

    def cleanup_all(self, curr_ts: Optional[float] = None):
        """Purge all expired entries across all keys."""
        now = curr_ts if curr_ts is not None else datetime.now(timezone.utc).timestamp()
        expired_keys = []
        for key in list(self._store.keys()):
            self._cleanup_key(key, now)
            if key not in self._store:
                expired_keys.append(key)


class EventCorrelator:
    """
    Production-grade Windows Event Correlator.
    Detects complex multi-event attack patterns such as:
    - CORR-001: Brute-Force Password Guessing followed by Successful Logon
    - CORR-002: Service Installation followed by Suspicious Process Execution
    - CORR-003: Repeated Suspicious PowerShell Burst
    - CORR-004: Service Crash Storm
    """

    SUSPICIOUS_CMD_KEYWORDS = {
        "powershell", "cmd.exe", "vssadmin", "certutil", "mimikatz",
        "whoami", "nltest", "psexec", "procdump", "net.exe", "schtasks",
        "rundll32", "regsvr32", "nc.exe", "ncat", "bash", "wscript", "cscript"
    }

    def __init__(
        self,
        failed_logon_threshold: int = 3,
        failed_logon_window_seconds: float = 300.0,
        service_proc_window_seconds: float = 180.0,
        powershell_burst_threshold: int = 4,
        powershell_burst_window_seconds: float = 60.0,
        crash_storm_threshold: int = 3,
        crash_storm_window_seconds: float = 120.0,
    ):
        self.failed_logon_threshold = failed_logon_threshold
        self.powershell_burst_threshold = powershell_burst_threshold
        self.crash_storm_threshold = crash_storm_threshold

        # Sliding window buffers
        self.failed_logons = BoundedTimeWindowBuffer(
            ttl_seconds=failed_logon_window_seconds, max_keys=2000
        )
        self.recent_services = BoundedTimeWindowBuffer(
            ttl_seconds=service_proc_window_seconds, max_keys=500
        )
        self.powershell_activity = BoundedTimeWindowBuffer(
            ttl_seconds=powershell_burst_window_seconds, max_keys=500
        )
        self.service_crashes = BoundedTimeWindowBuffer(
            ttl_seconds=crash_storm_window_seconds, max_keys=200
        )

        # Fired correlation deduplication cache
        self._fired_correlations: Deque[Tuple[float, str]] = deque()
        self._fired_cache_ttl = 300.0
        self._max_fired_cache = 1000

    def _is_recently_fired(self, signature: str, now_ts: float) -> bool:
        """Check if identical correlation signature already fired within TTL."""
        # Evict expired signatures
        cutoff = now_ts - self._fired_cache_ttl
        while self._fired_correlations and self._fired_correlations[0][0] < cutoff:
            self._fired_correlations.popleft()

        for _, sig in self._fired_correlations:
            if sig == signature:
                return True
        return False

    def _record_fired(self, signature: str, now_ts: float):
        """Record signature in fired deduplication cache."""
        if len(self._fired_correlations) >= self._max_fired_cache:
            self._fired_correlations.popleft()
        self._fired_correlations.append((now_ts, signature))

    def process_event(self, event: NormalizedEvent) -> List[CorrelatedAlert]:
        """
        Process a normalized event and return any triggered multi-event correlation alerts.
        """
        alerts: List[CorrelatedAlert] = []
        now_ts = event.timestamp_dt.timestamp()

        # -------------------------------------------------------------
        # 1. CORR-001: Failed Logons -> Successful Logon (Brute Force)
        # -------------------------------------------------------------
        if event.event_id == 4625 and event.channel.lower() == "security":
            # Track failed logon per user and per source IP
            user_key = event.user.lower() if event.user else None
            ip_key = str(event.event_data.get("IpAddress", "")).strip()

            if user_key and user_key not in ("-", "unknown user", ""):
                self.failed_logons.add(f"user:{user_key}", event, now_ts)
            if ip_key and ip_key not in ("-", "127.0.0.1", "::1", ""):
                self.failed_logons.add(f"ip:{ip_key}", event, now_ts)

        elif event.event_id == 4624 and event.channel.lower() == "security":
            # Successful logon: check if this user or IP had preceding failed logons >= threshold
            user_key = event.user.lower() if event.user else None
            ip_key = str(event.event_data.get("IpAddress", "")).strip()

            matching_failures: List[NormalizedEvent] = []
            corr_key_used = ""

            if user_key and user_key not in ("-", "unknown user", "system", "local service", "network service"):
                user_failures = self.failed_logons.get_events(f"user:{user_key}", now_ts)
                if len(user_failures) >= self.failed_logon_threshold:
                    matching_failures = user_failures
                    corr_key_used = f"user:{user_key}"

            if not matching_failures and ip_key and ip_key not in ("-", "127.0.0.1", "::1", ""):
                ip_failures = self.failed_logons.get_events(f"ip:{ip_key}", now_ts)
                if len(ip_failures) >= self.failed_logon_threshold:
                    matching_failures = ip_failures
                    corr_key_used = f"ip:{ip_key}"

            if matching_failures:
                sig = f"CORR-001:{corr_key_used}:{event.record_id}"
                if not self._is_recently_fired(sig, now_ts):
                    self._record_fired(sig, now_ts)
                    details = (
                        f"Target '{event.user or ip_key}' had {len(matching_failures)} failed logon attempts "
                        f"within the correlation window followed by a successful authentication."
                    )
                    all_events = matching_failures + [event]
                    alert = CorrelatedAlert(
                        correlation_id="CORR-001",
                        name="Brute-Force Authentication Succeeded",
                        severity=Severity.CRITICAL,
                        description="Multiple failed logons followed by a successful login for the same account/host.",
                        mitre_attack="T1110.001 - Brute Force: Password Guessing -> T1078 - Valid Accounts",
                        details=details,
                        events=all_events,
                    )
                    alerts.append(alert)
                    # Clear buffer for this user/ip after generating correlation alert
                    self.failed_logons.clear_key(corr_key_used)

        # -------------------------------------------------------------
        # 2. CORR-002: Service Installation + Suspicious Execution
        # -------------------------------------------------------------
        if event.event_id in (7045, 4697):
            # Record newly installed service
            svc_name = str(event.event_data.get("ServiceName", "")).strip()
            image_path = str(event.event_data.get("ImagePath", "")).strip()
            key = f"{event.computer.lower()}:{svc_name.lower() or image_path.lower()}"
            self.recent_services.add(key, event, now_ts)

        elif event.event_id in (4688, 1, 7036):
            # Check process creation or service start against recently installed services
            cmd_line = (
                event.event_data.get("CommandLine")
                or event.event_data.get("ProcessCommandLine")
                or event.process
                or ""
            ).lower()

            # Inspect if command line contains known suspicious keywords or references recent service
            is_suspicious_cmd = any(kw in cmd_line for kw in self.SUSPICIOUS_CMD_KEYWORDS)

            if is_suspicious_cmd:
                # Check for any recent service on this computer
                comp_prefix = event.computer.lower()
                for key in list(self.recent_services._store.keys()):
                    if key.startswith(f"{comp_prefix}:"):
                        recent_svc_events = self.recent_services.get_events(key, now_ts)
                        if recent_svc_events:
                            sig = f"CORR-002:{key}:{event.record_id}"
                            if not self._is_recently_fired(sig, now_ts):
                                self._record_fired(sig, now_ts)
                                svc_event = recent_svc_events[-1]
                                svc_name = svc_event.event_data.get("ServiceName", "Service")
                                details = (
                                    f"New service '{svc_name}' installed followed by suspicious process execution: "
                                    f"'{event.process or cmd_line[:120]}'"
                                )
                                alert = CorrelatedAlert(
                                    correlation_id="CORR-002",
                                    name="Service Installation Followed by Suspicious Execution",
                                    severity=Severity.CRITICAL,
                                    description="A new Windows service was installed and immediately triggered suspicious process execution.",
                                    mitre_attack="T1543.003 - Windows Service Persistence -> T1059 - Command Execution",
                                    details=details,
                                    events=[svc_event, event],
                                )
                                alerts.append(alert)
                                self.recent_services.clear_key(key)
                                break

        # -------------------------------------------------------------
        # 3. CORR-003: PowerShell Burst
        # -------------------------------------------------------------
        if event.channel.lower() in (
            "microsoft-windows-powershell/operational",
            "windows powershell",
        ) and event.event_id in (4104, 4103, 400):
            ps_key = f"{event.computer.lower()}:{event.user.lower() or 'default'}"
            self.powershell_activity.add(ps_key, event, now_ts)
            recent_ps = self.powershell_activity.get_events(ps_key, now_ts)

            if len(recent_ps) >= self.powershell_burst_threshold:
                # Inspect if at least one event has suspicious flags/content
                has_suspicious_content = any(
                    any(term in (e.event_data.get("ScriptBlockText", "") or e.message).lower()
                        for term in ("download", "iex", "-enc", "bypass", "invoke-", "hidden"))
                    for e in recent_ps
                )

                sig = f"CORR-003:{ps_key}:{recent_ps[-1].record_id}"
                if not self._is_recently_fired(sig, now_ts):
                    self._record_fired(sig, now_ts)
                    severity = Severity.HIGH if has_suspicious_content else Severity.MEDIUM
                    details = (
                        f"Rapid burst of {len(recent_ps)} PowerShell script executions detected "
                        f"for user '{event.user or 'system'}' on host '{event.computer}'."
                    )
                    alert = CorrelatedAlert(
                        correlation_id="CORR-003",
                        name="PowerShell Activity Burst",
                        severity=severity,
                        description="Repeated PowerShell script executions in a short time window.",
                        mitre_attack="T1059.001 - Command and Scripting Interpreter: PowerShell",
                        details=details,
                        events=list(recent_ps),
                    )
                    alerts.append(alert)
                    self.powershell_activity.clear_key(ps_key)

        # -------------------------------------------------------------
        # 4. CORR-004: Service Crash Storm
        # -------------------------------------------------------------
        if event.event_id in (7034, 7031, 7024) and event.channel.lower() == "system":
            comp_key = event.computer.lower() or "localhost"
            self.service_crashes.add(comp_key, event, now_ts)
            recent_crashes = self.service_crashes.get_events(comp_key, now_ts)

            if len(recent_crashes) >= self.crash_storm_threshold:
                sig = f"CORR-004:{comp_key}:{recent_crashes[-1].record_id}"
                if not self._is_recently_fired(sig, now_ts):
                    self._record_fired(sig, now_ts)
                    crashed_services = [
                        c.event_data.get("param1") or c.event_data.get("ServiceName") or c.process or f"EID-{c.event_id}"
                        for c in recent_crashes
                    ]
                    details = (
                        f"Service crash storm: {len(recent_crashes)} service terminations "
                        f"detected on '{event.computer}' ({', '.join(set(crashed_services))})."
                    )
                    alert = CorrelatedAlert(
                        correlation_id="CORR-004",
                        name="Critical Service Crash Storm",
                        severity=Severity.HIGH,
                        description="Multiple Windows service crashes in a rapid succession.",
                        mitre_attack="T1489 - Service Stop / Denial of Service",
                        details=details,
                        events=list(recent_crashes),
                    )
                    alerts.append(alert)
                    self.service_crashes.clear_key(comp_key)

        return alerts

    def cleanup_all(self):
        """Purge all expired sliding windows across all correlation trackers."""
        now_ts = datetime.now(timezone.utc).timestamp()
        self.failed_logons.cleanup_all(now_ts)
        self.recent_services.cleanup_all(now_ts)
        self.powershell_activity.cleanup_all(now_ts)
        self.service_crashes.cleanup_all(now_ts)
