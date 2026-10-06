"""
IPS Worker

Reads correlation events from:

    <data>/logs/correlation.json

and sends them to:

    IPS Engine

IPS decisions are stored in:

    <data>/logs/ips_alerts.json

The IPS worker does NOT capture packets.
It consumes correlation events only.
"""

import json
import re
from datetime import datetime, timedelta, timezone

from .ips_engine import IPSEngine
from paths import (
    CORRELATION_FILE,
    IPS_ALERTS_FILE,
    IPS_PASS_FILE,
    IPS_WORKER_CHECKPOINT_FILE,
)
from rotation import JsonlTail, rotate_if_needed
from stop_signal import wait_for_stop


# Read position in correlation.json, so a restart does not
# process (and log) old correlations again.
IPS_CHECKPOINT_FILE = IPS_WORKER_CHECKPOINT_FILE

# ips_pass.json is rotated every day at this local hour.
# Records from before that time move to ips_pass_DD-MM.json
# (DD-MM = rotation date); newer records stay in ips_pass.json.
PASS_ROTATION_HOUR = 10

# "timestamp" is the first field of every PASS record
_TIMESTAMP_RE = re.compile(rb'"timestamp":\s*"([^"]+)"')

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
        # Position in correlation.json (restored from the
        # checkpoint file; follows rotations)
        # ----------------------------------------------------

        self.checkpoint_file = IPS_CHECKPOINT_FILE

        self.tail = JsonlTail(
            self.correlation_file,
            self.checkpoint_file
        )

        # ----------------------------------------------------
        # Time of the oldest record in ips_pass.json
        # (None when the file is empty / missing)
        # ----------------------------------------------------

        self._pass_period_start = self._first_pass_timestamp()

    # ========================================================
    # DAILY ROTATION OF ips_pass.json
    # ========================================================

    @staticmethod
    def _local_now():
        return datetime.now().astimezone()

    @staticmethod
    def _last_rotation_boundary(now):
        """Most recent PASS_ROTATION_HOUR:00 that is <= now."""

        boundary = now.replace(
            hour=PASS_ROTATION_HOUR,
            minute=0,
            second=0,
            microsecond=0
        )

        if now < boundary:
            boundary -= timedelta(days=1)

        return boundary

    def _first_pass_timestamp(self):
        """
        Timestamp of the first record in ips_pass.json, so a
        rotation missed while the worker was stopped is done
        on the next start. Falls back to the file's creation
        time if the first record cannot be parsed.
        """

        try:

            if (
                not self.ips_pass_file.exists()
                or self.ips_pass_file.stat().st_size == 0
            ):
                return None

            with open(
                self.ips_pass_file,
                "r",
                encoding="utf-8",
                errors="ignore"
            ) as f:

                for line in f:

                    line = line.strip()

                    if not line:
                        continue

                    timestamp = json.loads(line).get("timestamp")

                    return datetime.fromisoformat(
                        timestamp
                    ).astimezone()

        except Exception:
            pass

        try:

            return datetime.fromtimestamp(
                self.ips_pass_file.stat().st_ctime
            ).astimezone()

        except OSError:

            return None

    def _rotated_pass_path(self, boundary):
        """ips_pass_DD-MM.json, with _2, _3 ... if it exists."""

        base = f"{self.ips_pass_file.stem}_{boundary:%d-%m}"

        candidate = self.ips_pass_file.with_name(
            f"{base}.json"
        )

        number = 2

        while candidate.exists():

            candidate = self.ips_pass_file.with_name(
                f"{base}_{number}.json"
            )

            number += 1

        return candidate

    @staticmethod
    def _record_time(raw_line):
        """Timestamp of one raw PASS record, or None."""

        match = _TIMESTAMP_RE.search(raw_line[:300])

        if not match:
            return None

        try:
            return datetime.fromisoformat(
                match.group(1).decode()
            ).astimezone()
        except ValueError:
            return None

    def _rotate_pass_if_due(self):
        """
        Once ips_pass.json holds records from before the last
        10:00 boundary:

          - records before 10:00 are moved to ips_pass_DD-MM.json
          - records from 10:00 on stay in ips_pass.json

        Records are copied unchanged. Never raises: on failure
        (e.g. the file is open in an editor) nothing is changed
        and it is retried on the next loop.
        """

        if self._pass_period_start is None:
            return

        temp_old = temp_new = None

        try:

            boundary = self._last_rotation_boundary(
                self._local_now()
            )

            if self._pass_period_start >= boundary:
                return

            if not self.ips_pass_file.exists():
                self._pass_period_start = None
                return

            target = self._rotated_pass_path(boundary)

            temp_old = target.with_suffix(".rotating")
            temp_new = self.ips_pass_file.with_suffix(".remaining")

            moved = kept = 0
            first_kept = None

            # ------------------------------------------------
            # Split by record timestamp
            # ------------------------------------------------

            with open(self.ips_pass_file, "rb") as source, \
                    open(temp_old, "wb") as old, \
                    open(temp_new, "wb") as new:

                for raw in source:

                    if not raw.strip():
                        continue

                    if not raw.endswith(b"\n"):
                        raw += b"\n"

                    record_time = self._record_time(raw)

                    if record_time is not None and record_time >= boundary:
                        new.write(raw)
                        kept += 1
                        first_kept = first_kept or record_time
                    else:
                        old.write(raw)
                        moved += 1

            # ------------------------------------------------
            # 1. Replace ips_pass.json with the remaining
            #    records. Fails (nothing changed) if the file
            #    is open in another program.
            # 2. Publish the dated file.
            # ------------------------------------------------

            if moved == 0:
                # Nothing older than 10:00 (stale start time)
                temp_old.unlink()
                temp_new.unlink()
                temp_old = temp_new = None
                self._pass_period_start = first_kept
                return

            temp_new.replace(self.ips_pass_file)
            temp_new = None

            # ips_pass.json now starts at the boundary; do not
            # rotate again even if the next rename fails
            self._pass_period_start = first_kept

            temp_old.replace(target)
            temp_old = None

            print(
                f"[IPS] Rotated ips_pass.json: {moved} records -> "
                f"{target.name}, {kept} newer records kept"
            )

        except Exception as e:

            print(
                f"[IPS] ips_pass.json rotation failed, "
                f"will retry: {e}"
            )

        finally:

            # Clean up after a failure. If only the second
            # rename failed, keep the moved records in
            # temp_old and say where they are.
            if temp_new is not None:
                try:
                    temp_new.unlink(missing_ok=True)
                    if temp_old is not None:
                        temp_old.unlink(missing_ok=True)
                except OSError:
                    pass
            elif temp_old is not None and temp_old.exists():
                print(f"[IPS] Rotated PASS records kept in {temp_old}")

    # ========================================================
    # CHECKPOINT
    # ========================================================

    def _save_checkpoint(self):
        """Save the correlation.json read position."""

        self.tail.commit()

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
        # Append one JSON object per line (size-rotated)
        # ----------------------------------------------------

        rotate_if_needed(self.ips_alerts_file)

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
        """
        Complete new correlation lines since the checkpoint.
        Follows correlation.json across rotations; a line still
        being written is read next time. The position is saved
        by _save_checkpoint() after the batch is processed.
        """

        # correlation_file may be changed after construction
        if self.tail.path != self.correlation_file:
            self.tail = JsonlTail(
                self.correlation_file,
                self.checkpoint_file
            )

        events = []

        for line in self.tail.read_lines():

            try:

                events.append(
                    json.loads(line)
                )

            except json.JSONDecodeError:

                print(
                    "[IPS] Skipping invalid "
                    "correlation JSON line."
                )

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

                # --------------------------------------------
                # The same event already got a decision from
                # another correlation (another category or
                # IP), so it is not a PASS.
                # --------------------------------------------

                if self.engine.event_has_decision(
                    event.get("trigger_event_id")
                ):
                    continue

                # --------------------------------------------
                # More correlations for this event follow;
                # record PASS only once, on the last one.
                # --------------------------------------------

                if not event.get("trigger_final", True):
                    continue

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

        # Start a new daily file first if 10:00 has passed
        self._rotate_pass_if_due()

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

            if self._pass_period_start is None:
                self._pass_period_start = self._local_now()

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
        # Continuous monitoring until the service stops
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
                # Remember how far correlation.json has been
                # processed (saved after processing, so a
                # crash re-reads the batch instead of losing
                # it)
                # --------------------------------------------

                self._save_checkpoint()

                # --------------------------------------------
                # Daily ips_pass.json rotation at 10:00, also
                # when no PASS records are being written
                # --------------------------------------------

                self._rotate_pass_if_due()

            except KeyboardInterrupt:

                break

            except Exception as e:

                print(
                    f"[IPS WORKER ERROR] {e}"
                )

            # ------------------------------------------------
            # Sleep 1 s, or exit as soon as the service stops
            # ------------------------------------------------

            if wait_for_stop(1):
                break

        self._save_checkpoint()

        print(
            "[*] IPS Worker stopped."
        )


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