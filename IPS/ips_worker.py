"""
IPS Worker

Reads correlation events from:

    alert_manager/correlation.json

and sends them to:

    IPS Engine

IPS decisions are stored in:

    logs/ips_alerts.json

The IPS worker does NOT capture packets.
It consumes correlation events only.
"""

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from .ips_engine import IPSEngine


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CORRELATION_FILE = (
    PROJECT_ROOT
    / "alert_manager"
    / "correlation.json"
)

IPS_PASS_FILE = (
    PROJECT_ROOT
    / "logs"
    / "ips_pass.json"
)

IPS_ALERTS_FILE = PROJECT_ROOT / "logs" / "ips_alerts.json"

# ============================================================
# IPS WORKER
# ============================================================

class IPSWorker:

    def __init__(self):

        # ----------------------------------------------------
        # Correlation file consumed by IPS
        # ----------------------------------------------------

        self.correlation_file = CORRELATION_FILE

        # ----------------------------------------------------
        # IPS decision output file
        # ----------------------------------------------------

        self.ips_alerts_file = IPS_ALERTS_FILE
        self.ips_pass_file = IPS_PASS_FILE

        # ----------------------------------------------------
        # Make sure logs directory exists
        # ----------------------------------------------------

        self.ips_alerts_file.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        # ----------------------------------------------------
        # IPS rule engine
        # ----------------------------------------------------

        self.engine = IPSEngine()

        # ----------------------------------------------------
        # Current position in correlation.json
        # ----------------------------------------------------

        self.file_position = 0

    # ========================================================
    # WRITE IPS DECISION
    # ========================================================

    def write_decision(
        self,
        decision,
        correlation_event
    ):
        """
        Store one IPS decision in logs/ips_alerts.json.
        """

        # ----------------------------------------------------
        # Extract source event information
        # ----------------------------------------------------

        source_ip = correlation_event.get("ip")

        category = correlation_event.get(
            "category"
        )

        correlation_timestamp = (
            correlation_event.get("timestamp")
        )

        # ----------------------------------------------------
        # Build IPS output
        # ----------------------------------------------------

        entry = {
            "timestamp": datetime.now(
                timezone.utc
            ).astimezone().isoformat(),

            "event_type": "ips_decision",

            "action": decision.action,

            "sid": decision.sid,

            "category": decision.category,

            "priority": decision.priority,

            "severity": decision.severity,

            "message": decision.message,

            "conditions_matched": (
                decision.metadata.get(
                    "conditions_matched",
                    []
                )
            ),

            "indicator_list": (
                decision.indicator_list
            ),

            "matched_indicator": (
                decision.matched_indicator
            ),

            "source_ip": source_ip,

            "correlation_timestamp": (
                correlation_timestamp
            ),

            "correlation_category": category,

            "correlation_event": (
                correlation_event
            )
        }

        # ----------------------------------------------------
        # Append one JSON object per line
        # ----------------------------------------------------

        try:

            with open(
                self.ips_alerts_file,
                "a",
                encoding="utf-8"
            ) as f:

                json.dump(
                    entry,
                    f,
                    ensure_ascii=False
                )

                f.write("\n")

                f.flush()

        except Exception as e:

            print(
                f"[IPS] Failed to write "
                f"IPS decision: {e}"
            )

    # ========================================================
    # READ NEW CORRELATION EVENTS
    # ========================================================

    def read_new_events(self):

        events = []

        # ----------------------------------------------------
        # correlation.json does not exist
        # ----------------------------------------------------

        if not self.correlation_file.exists():

            self.file_position = 0

            return []

        try:

            # ------------------------------------------------
            # Current file size
            # ------------------------------------------------

            current_size = (
                self.correlation_file.stat().st_size
            )

            # ------------------------------------------------
            # File was truncated/recreated
            # ------------------------------------------------

            if current_size < self.file_position:

                print(
                    "[IPS] Correlation file was "
                    "reset/recreated. "
                    "Starting from beginning."
                )

                self.file_position = 0

            # ------------------------------------------------
            # Read correlation file
            # ------------------------------------------------

            with open(
                self.correlation_file,
                "r",
                encoding="utf-8"
            ) as f:

                f.seek(
                    self.file_position
                )

                while True:

                    line = f.readline()

                    if not line:
                        break

                    line = line.strip()

                    if not line:
                        continue

                    # ----------------------------------------
                    # Parse JSON
                    # ----------------------------------------

                    try:

                        event = json.loads(
                            line
                        )

                    except json.JSONDecodeError:

                        print(
                            "[IPS] Skipping invalid "
                            "correlation JSON line."
                        )

                        continue

                    events.append(
                        event
                    )

                # --------------------------------------------
                # Save current position
                # --------------------------------------------

                self.file_position = f.tell()

        except FileNotFoundError:

            self.file_position = 0

            return []

        except Exception as e:

            print(
                f"[IPS] Error reading "
                f"correlation file: {e}"
            )

            return []

        return events

    # ========================================================
    # PROCESS CORRELATION EVENTS
    # ========================================================

    def process_events(
        self,
        events
    ):

        for event in events:

            # ------------------------------------------------
            # Only process correlation events
            # ------------------------------------------------

            if event.get(
                "event_type"
            ) != "correlation":

                continue

            # ------------------------------------------------
            # Display correlation information
            # ------------------------------------------------

            print(
                f"[IPS] "
                f"Category={event.get('category')} "
                f"IP={event.get('ip')} "
                f"Events={event.get('event_count')} "
                f"Severity={event.get('severity')}"
            )

            # ------------------------------------------------
            # Send correlation event to IPS engine
            # ------------------------------------------------

            decisions = (
                self.engine.process_correlation(
                    event
                )
            )

            # ------------------------------------------------
            # No IPS rule matched
            # ------------------------------------------------

            if not decisions:

                print(
                    "[IPS] Decision=PASS "
                    "(No IPS rule matched)"
                )

                # --------------------------------------------
                # Store PASS decision as well
                # --------------------------------------------

                self.write_pass(
                    event
                )

                continue

            # ------------------------------------------------
            # Process matched IPS decisions
            # ------------------------------------------------

            for decision in decisions:

                print(
                    f"[IPS] "
                    f"Action={decision.action} "
                    f"SID={decision.sid} "
                    f"Category={decision.category} "
                    f"Message={decision.message}"
                )

                # --------------------------------------------
                # Display matched indicator
                # --------------------------------------------

                if decision.matched_indicator:

                    print(
                        f"[IPS] "
                        f"Matched Indicator="
                        f"{decision.matched_indicator}"
                    )

                # --------------------------------------------
                # Store decision
                # --------------------------------------------

                self.write_decision(
                    decision,
                    event
                )

    # ========================================================
    # WRITE PASS DECISION
    # ========================================================

    def write_pass(
        self,
        correlation_event
    ):
        """
        Store PASS decisions separately in logs/ips_pass.json.
        """

        entry = {
            "timestamp": datetime.now(
                timezone.utc
            ).astimezone().isoformat(),

            "event_type": "ips_decision",

            "action": "PASS",

            "sid": None,

            "category": correlation_event.get(
                "category"
            ),

            "priority": None,

            "severity": None,

            "message": "No IPS rule matched",

            "indicator_list": None,

            "matched_indicator": None,

            "source_ip": correlation_event.get(
                "ip"
            ),

            "correlation_timestamp": (
                correlation_event.get(
                    "timestamp"
                )
            ),

            "correlation_category": (
                correlation_event.get(
                    "category"
                )
            ),

            "correlation_event": (
                correlation_event
            )
        }

        try:

            with open(
                self.ips_pass_file,
                "a",
                encoding="utf-8"
            ) as f:

                json.dump(
                    entry,
                    f,
                    ensure_ascii=False
                )

                f.write("\n")

                f.flush()

        except Exception as e:

            print(
                f"[IPS] Failed to write "
                f"PASS decision: {e}"
            )

    # ========================================================
    # RUN IPS WORKER
    # ========================================================

    def run(self):

        print(
            "[*] IPS Worker started."
        )

        print(
            f"[*] Watching: "
            f"{self.correlation_file}"
        )

        print(
            f"[*] IPS decisions: "
            f"{self.ips_alerts_file}"
        )

        # ----------------------------------------------------
        # Continuous monitoring
        # ----------------------------------------------------

        while True:

            try:

                # --------------------------------------------
                # Read new correlation events
                # --------------------------------------------

                events = (
                    self.read_new_events()
                )

                # --------------------------------------------
                # Process events
                # --------------------------------------------

                if events:

                    self.process_events(
                        events
                    )

                # --------------------------------------------
                # Avoid busy looping
                # --------------------------------------------

                time.sleep(1)

            except KeyboardInterrupt:

                print(
                    "\n[*] IPS Worker stopped."
                )

                break

            except Exception as e:

                print(
                    f"[IPS WORKER ERROR] {e}"
                )

                time.sleep(1)


# ============================================================
# MAIN
# ============================================================

def main():

    worker = IPSWorker()

    worker.run()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()