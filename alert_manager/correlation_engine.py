import time
import json
import hashlib
import subprocess
from pathlib import Path
from collections import defaultdict
from dataclasses import fields as dataclass_fields
from datetime import datetime, timezone

from alert_manager.adapters.hids_adapter import HIDSAdapter
from alert_manager.adapters.nids_adapter import NIDSAdapter
from alert_manager.schema.alert_schema import AlertSchema
from paths import CORRELATION_FILE
from rotation import rotate_if_needed


# ============================================================
# CORRELATION WINDOWS
# ============================================================

CORRELATION_WINDOWS = {
    "BENIGN_TEST": 10,

    "NETWORK_ANOMALY": 30,
    "DOS": 30,

    "RECON": 60,
    "EXPLOIT": 60,

    "UNAUTHORIZED_ACCESS": 120,
    "POLICY_VIOLATION": 120,
    "PRIVILEGE_ESCALATION": 120,

    "C2": 300,
    "MALWARE": 300,
    "DEFENSE_EVASION": 300,
    "LATERAL_MOVEMENT": 300,

    "PERSISTENCE": 600,
    "EXFILTRATION": 600,
}


# ============================================================
# CATEGORY-BASED CORRELATION SEVERITY
# ============================================================

CORRELATION_SEVERITY = {
    "BENIGN_TEST": {
        "LOW": (1, 1),
        "MEDIUM": (2, 3),
        "HIGH": (4, float("inf")),
    },

    "NETWORK_ANOMALY": {
        "LOW": (1, 1),
        "MEDIUM": (2, 4),
        "HIGH": (5, float("inf")),
    },

    "DOS": {
        "LOW": (1, 2),
        "MEDIUM": (3, 4),
        "HIGH": (5, float("inf")),
    },

    "RECON": {
        "LOW": (1, 2),
        "MEDIUM": (3, 5),
        "HIGH": (6, float("inf")),
    },

    "EXPLOIT": {
        "LOW": (1, 1),
        "MEDIUM": (2, 2),
        "HIGH": (3, float("inf")),
    },

    "UNAUTHORIZED_ACCESS": {
        "LOW": (1, 1),
        "MEDIUM": (2, 3),
        "HIGH": (4, float("inf")),
    },

    "POLICY_VIOLATION": {
        "LOW": (1, 2),
        "MEDIUM": (3, 4),
        "HIGH": (5, float("inf")),
    },

    "PRIVILEGE_ESCALATION": {
        "LOW": (1, 1),
        "MEDIUM": (2, 2),
        "HIGH": (3, float("inf")),
    },

    "C2": {
        "LOW": (1, 1),
        "MEDIUM": (2, 3),
        "HIGH": (4, float("inf")),
    },

    "MALWARE": {
        "LOW": (1, 1),
        "MEDIUM": (2, 2),
        "HIGH": (3, float("inf")),
    },

    "DEFENSE_EVASION": {
        "LOW": (1, 1),
        "MEDIUM": (2, 3),
        "HIGH": (4, float("inf")),
    },

    "LATERAL_MOVEMENT": {
        "LOW": (1, 1),
        "MEDIUM": (2, 3),
        "HIGH": (4, float("inf")),
    },

    "PERSISTENCE": {
        "LOW": (1, 2),
        "MEDIUM": (3, 4),
        "HIGH": (5, float("inf")),
    },

    "EXFILTRATION": {
        "LOW": (1, 1),
        "MEDIUM": (2, 2),
        "HIGH": (3, float("inf")),
    },
}


# ============================================================
# BUCKET LIMITS / STATE
# ============================================================

# A packet flood can put thousands of NIDS alerts into one
# bucket, and every correlation line carries the full bucket
# in source_events. Only the newest events are kept; every
# IPS min_events threshold (max 6) and severity threshold
# above is far below this limit.
MAX_BUCKET_EVENTS = 100

# Bucket events are saved complete (including "raw" and the
# payload), so source_events stay complete after a restart.
# Only these AlertSchema fields are accepted when loading.
STATE_EVENT_FIELDS = {
    f.name for f in dataclass_fields(AlertSchema)
}


# ============================================================
# LOCAL HOST ADDRESSES
# ============================================================

LOCAL_IP_REFRESH_SECONDS = 60

_local_ips = set()
_local_ips_refreshed_at = 0.0


def get_local_ips():
    """
    Return this machine's IP addresses (cached, refreshed
    every 60 seconds because DHCP can change them).
    """

    global _local_ips, _local_ips_refreshed_at

    now = time.time()

    if now - _local_ips_refreshed_at < LOCAL_IP_REFRESH_SECONDS:
        return _local_ips

    addresses = {"127.0.0.1", "::1"}

    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetIPAddress | "
                "Select-Object -ExpandProperty IPAddress"
            ],
            capture_output=True,
            text=True,
            check=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
        )

        for line in result.stdout.splitlines():
            # Strip IPv6 zone index, e.g. fe80::1%12
            address = line.strip().split("%")[0]

            if address:
                addresses.add(address)

    except Exception as e:
        print(f"[CORRELATION] Failed to read local IP addresses: {e}")

        # Keep the previous list rather than dropping to
        # loopback only.
        addresses |= _local_ips

    _local_ips = addresses
    _local_ips_refreshed_at = now

    return _local_ips


# ============================================================
# EVENT FINGERPRINT
# ============================================================

def event_fingerprint(event):
    """
    Stable ID for one normalized alert.

    The same alert is written once per category and per
    correlation IP; this ID lets IPS recognize it as the
    same event.
    """

    data = json.dumps(
        event.to_dict(),
        sort_keys=True,
        default=str
    )

    return hashlib.sha1(
        data.encode("utf-8")
    ).hexdigest()


# ============================================================
# CORRELATION ENGINE
# ============================================================

class CorrelationEngine:

    def __init__(self, state_file=None):

        # ----------------------------------------------------
        # EXISTING CORRELATION STRUCTURE
        #
        # category -> IP -> list of events
        #
        # DO NOT CHANGE THIS.
        # ----------------------------------------------------

        self.buckets = defaultdict(
            lambda: defaultdict(list)
        )

        # ----------------------------------------------------
        # Correlation output file
        # ----------------------------------------------------

        self.correlation_file = CORRELATION_FILE

        # ----------------------------------------------------
        # Bucket state file (survives worker restarts).
        # None disables persistence.
        # ----------------------------------------------------

        self.state_file = (
            Path(state_file) if state_file else None
        )

        # True when buckets changed since the last save
        self._dirty = False

    # ========================================================
    # BUCKET STATE PERSISTENCE
    # ========================================================

    def load_state(self):
        """
        Restore buckets saved by a previous run, so event
        counts continue across restarts. Expired events are
        dropped immediately.
        """

        if not self.state_file or not self.state_file.exists():
            return

        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            skipped = 0

            for category, ips in data.get("buckets", {}).items():
                for ip, events in ips.items():
                    for event in events:
                        try:
                            self.buckets[category][ip].append(
                                AlertSchema(**{
                                    key: value
                                    for key, value in event.items()
                                    if key in STATE_EVENT_FIELDS
                                })
                            )
                        except Exception:
                            skipped += 1

            if skipped:
                print(
                    f"[CORRELATION] Skipped {skipped} invalid events "
                    f"in {self.state_file}"
                )

        except Exception as e:
            print(
                f"[CORRELATION] Ignoring unreadable state file "
                f"{self.state_file}: {e}"
            )
            self.buckets.clear()
            return

        self.cleanup()

        restored = sum(
            len(bucket)
            for ips in self.buckets.values()
            for bucket in ips.values()
        )

        print(
            f"[CORRELATION] Restored {restored} unexpired bucket events "
            f"from {self.state_file}"
        )

    def save_state(self):
        """Save buckets atomically if they changed."""

        if not self.state_file or not self._dirty:
            return

        data = {
            "buckets": {
                category: {
                    ip: [
                        event.to_dict()
                        for event in bucket
                    ]
                    for ip, bucket in ips.items()
                }
                for category, ips in self.buckets.items()
            }
        }

        self.state_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        temp_path = self.state_file.with_suffix(".tmp")

        try:
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, default=str)

            temp_path.replace(self.state_file)

        except OSError as e:
            # Keep _dirty set so the next loop retries
            print(f"[CORRELATION] Failed to save state: {e}")
            return

        self._dirty = False

    # ========================================================
    # TIMESTAMP
    # ========================================================

    def _parse_timestamp(self, timestamp):
        """
        Convert AlertSchema timestamp into datetime.
        """

        if not timestamp:
            return datetime.now(timezone.utc)

        try:
            return datetime.fromisoformat(
                timestamp.replace("Z", "+00:00")
            )

        except (ValueError, TypeError):
            return datetime.now(timezone.utc)

    # ========================================================
    # GET IPs
    # ========================================================

    def _get_ips(self, event):
        """
        Get IP addresses that can be used
        as correlation keys.

        Events are correlated by the REMOTE side only.
        The client's own addresses appear in almost every
        event, so keying on them would merge activity from
        unrelated remote IPs into one bucket.

        If an event has no remote IP (for example a local
        HIDS event), it is correlated by the host IP.
        """

        local_ips = get_local_ips()

        candidates = {
            ip
            for ip in (event.source_ip, event.destination_ip)
            if ip
        }

        remote_ips = {
            ip
            for ip in candidates
            if ip not in local_ips
        }

        if remote_ips:
            return remote_ips

        if event.host_ip:
            return {event.host_ip}

        return candidates

    # ========================================================
    # CALCULATE CORRELATION SEVERITY
    # ========================================================

    def _calculate_severity(self, category, event_count):
        """
        Calculate correlation severity based on
        category and number of events in the bucket.

        EXISTING LOGIC — UNCHANGED.
        """

        severity_levels = CORRELATION_SEVERITY.get(category)

        if not severity_levels:
            return "LOW"

        for severity, (minimum, maximum) in severity_levels.items():

            if minimum <= event_count <= maximum:
                return severity

        return "LOW"

    # ========================================================
    # WRITE CORRELATION
    # ========================================================

    def _write_correlation(
        self,
        category,
        ip,
        bucket,
        window,
        final=True
    ):
        """
        Write the current real-time correlation result.

        IMPORTANT:
        The correlation algorithm is NOT changed here.

        We only enrich the output so that correlation carries
        the complete NIDS/HIDS source event information.

        The IPS engine can therefore consume correlation.json
        without separately reading alerts.json or event.json.
        """

        if not bucket:
            return

        # ----------------------------------------------------
        # Latest event
        # ----------------------------------------------------

        latest_event = bucket[-1]

        # ----------------------------------------------------
        # Existing correlation calculations
        # ----------------------------------------------------

        event_count = len(bucket)

        severity = self._calculate_severity(
            category,
            event_count
        )

        # ====================================================
        # COMPLETE SOURCE EVENTS
        # ====================================================
        #
        # Every event currently inside this correlation bucket
        # is preserved.
        #
        # event.to_dict() already contains:
        #
        # sensor
        # timestamp
        # event_type
        # detection_id
        # severity
        # category_type
        # attack_type
        # mitre_attack
        # source_ip
        # destination_ip
        # source_port
        # destination_port
        # host_ip
        # message
        # details
        # raw
        #
        # The "raw" field contains the original NIDS/HIDS
        # alert data (including the payload).
        #
        # Therefore no source fields are lost.
        # ====================================================

        source_events = [
            event.to_dict()
            for event in bucket
        ]

        # ====================================================
        # CORRELATION OUTPUT
        # ====================================================

        correlation = {
            # ------------------------------------------------
            # Event type
            # ------------------------------------------------

            "event_type": "correlation",

            # ------------------------------------------------
            # Latest event timestamp
            # ------------------------------------------------

            "timestamp": latest_event.timestamp,

            # ------------------------------------------------
            # Existing correlation information
            #
            # These fields retain the same meaning and values
            # as before.
            # ------------------------------------------------

            "category": category,

            "ip": ip,

            "event_count": event_count,

            "window": window,

            "severity": severity,

            "detection_ids": [
                event.detection_id
                for event in bucket
                if event.detection_id is not None
            ],

            "sensors": list({
                event.sensor
                for event in bucket
                if event.sensor
            }),

            # ------------------------------------------------
            # COMPLETE SOURCE EVENTS
            #
            # IPS can inspect everything that came from
            # NIDS/HIDS (all fields, including the payload)
            # without reading another log.
            # ------------------------------------------------

            "source_events": source_events,

            # ------------------------------------------------
            # NEW EVENT THAT PRODUCED THIS CORRELATION
            #
            # The last entry of source_events (complete, with
            # "raw"). IPS decides on this event; the earlier
            # source events were decided when they arrived,
            # so they are not decided again.
            # ------------------------------------------------

            "trigger_event": latest_event.to_dict(),

            "trigger_event_id": event_fingerprint(
                latest_event
            ),

            # Last correlation written for this event
            "trigger_final": final,
        }

        # ====================================================
        # CREATE OUTPUT DIRECTORY
        # ====================================================

        self.correlation_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        # ====================================================
        # APPEND REAL-TIME CORRELATION RESULT
        # ====================================================

        # Size-based rotation; the IPS worker follows the
        # rotated file (rotation.JsonlTail).
        rotate_if_needed(self.correlation_file)

        with open(
            self.correlation_file,
            "a",
            encoding="utf-8"
        ) as f:

            json.dump(
                correlation,
                f,
                ensure_ascii=False
            )

            f.write("\n")

    # ========================================================
    # PROCESS EVENT
    # ========================================================

    def process_event(self, event):
        """
        Process one normalized AlertSchema event.

        EXISTING CORRELATION LOGIC — UNCHANGED.
        """

        if event.event_type != "alert":
            return

        categories = event.category_type

        if not categories:
            return

        event_time = self._parse_timestamp(
            event.timestamp
        )

        ips = self._get_ips(event)

        if not ips:
            return

        # The last correlation written for this event is marked
        # "trigger_final", so IPS can record a single PASS for
        # the event instead of one per category/IP.
        remaining = len(ips) * sum(
            1 for category in categories
            if category in CORRELATION_WINDOWS
        )

        # ----------------------------------------------------
        # Process every category
        # ----------------------------------------------------

        for category in categories:

            if category not in CORRELATION_WINDOWS:
                continue

            window = CORRELATION_WINDOWS[category]

            # ------------------------------------------------
            # Existing IP-based correlation
            # ------------------------------------------------

            for ip in ips:

                bucket = self.buckets[category][ip]

                # --------------------------------------------
                # Remove expired events
                #
                # EXISTING LOGIC — UNCHANGED
                # --------------------------------------------

                bucket[:] = [
                    existing_event
                    for existing_event in bucket
                    if (
                        event_time
                        - self._parse_timestamp(
                            existing_event.timestamp
                        )
                    ).total_seconds() <= window
                ]

                # --------------------------------------------
                # Add current event
                #
                # EXISTING LOGIC — UNCHANGED
                # --------------------------------------------

                bucket.append(event)

                # Keep only the newest events
                if len(bucket) > MAX_BUCKET_EVENTS:
                    del bucket[:-MAX_BUCKET_EVENTS]

                self._dirty = True

                # --------------------------------------------
                # Display correlation
                # --------------------------------------------

                print(
                    f"[CORRELATION] "
                    f"Category={category} "
                    f"IP={ip} "
                    f"Events={len(bucket)} "
                    f"Window={window}s"
                )

                # --------------------------------------------
                # Write enriched correlation result
                # --------------------------------------------

                remaining -= 1

                self._write_correlation(
                    category,
                    ip,
                    bucket,
                    window,
                    final=(remaining == 0)
                )

    # ========================================================
    # CLEANUP
    # ========================================================

    def cleanup(self):
        """
        Remove expired buckets.

        EXISTING LOGIC — UNCHANGED.
        """

        now = datetime.now(timezone.utc)

        for category in list(self.buckets):

            window = CORRELATION_WINDOWS.get(
                category
            )

            if window is None:
                continue

            for ip in list(
                self.buckets[category]
            ):

                bucket = self.buckets[category][ip]

                before = len(bucket)

                bucket[:] = [
                    event
                    for event in bucket
                    if (
                        now
                        - self._parse_timestamp(
                            event.timestamp
                        )
                    ).total_seconds() <= window
                ]

                if len(bucket) != before:
                    self._dirty = True

                if not bucket:
                    del self.buckets[category][ip]

            if not self.buckets[category]:
                del self.buckets[category]

    # ========================================================
    # RUN
    # ========================================================

    def run(self, hids_adapter, nids_adapter):
        """
        Continuously consume new normalized
        HIDS and NIDS events.

        EXISTING LOGIC — UNCHANGED.
        """

        print("[*] Correlation Engine started.")

        while True:

            # ------------------------------------------------
            # HIDS
            # ------------------------------------------------

            hids_events = (
                hids_adapter.read_new_alerts()
            )

            for event in hids_events:

                self.process_event(event)

            # ------------------------------------------------
            # NIDS
            # ------------------------------------------------

            nids_events = (
                nids_adapter.read_new_alerts()
            )

            for event in nids_events:

                self.process_event(event)

            # ------------------------------------------------
            # Cleanup
            # ------------------------------------------------

            self.cleanup()

            self.save_state()

            # ------------------------------------------------
            # Poll interval
            # ------------------------------------------------

            time.sleep(1)