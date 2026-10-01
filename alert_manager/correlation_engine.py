import time
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timezone

from alert_manager.adapters.hids_adapter import HIDSAdapter
from alert_manager.adapters.nids_adapter import NIDSAdapter


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
# CORRELATION ENGINE
# ============================================================

class CorrelationEngine:

    def __init__(self):

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

        self.correlation_file = (
            Path(__file__).resolve().parent
            / "correlation.json"
        )

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

        EXISTING LOGIC — UNCHANGED.
        """

        ips = set()

        if event.source_ip:
            ips.add(event.source_ip)

        if event.destination_ip:
            ips.add(event.destination_ip)

        if event.host_ip:
            ips.add(event.host_ip)

        return ips

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
        window
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
        # alert data.
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
            # This is the new part.
            #
            # IPS can now inspect everything that came from
            # NIDS/HIDS without reading another log.
            # ------------------------------------------------

            "source_events": source_events,
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

                self._write_correlation(
                    category,
                    ip,
                    bucket,
                    window
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

            # ------------------------------------------------
            # Poll interval
            # ------------------------------------------------

            time.sleep(1)