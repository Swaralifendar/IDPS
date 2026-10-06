import json
from pathlib import Path
from typing import Optional

from alert_manager.schema.alert_schema import AlertSchema
from rotation import JsonlTail


class NIDSAdapter:
    """
    Adapter for converting NIDS alerts.json entries
    into the common AlertSchema.
    """

    def __init__(
        self,
        alerts_path: str | Path,
        checkpoint_path: str | Path | None = None,
    ):
        self.alerts_path = Path(alerts_path)

        if checkpoint_path is None:
            checkpoint_path = (
                self.alerts_path.parent
                / "alert_manager_nids_checkpoint.json"
            )

        self.checkpoint_path = Path(checkpoint_path)

        # Byte-offset reader that follows alerts.json across
        # rotations (see rotation.py).
        self.tail = JsonlTail(
            self.alerts_path,
            self.checkpoint_path,
            legacy_offset_loader=self._line_number_to_offset,
        )

    def _line_number_to_offset(self, data: dict) -> int:
        """
        Convert the older {"line_number": N} checkpoint to the
        byte offset after line N, so alerts are not re-read.
        """

        line_number = int(data.get("line_number", 0))
        offset = 0

        if line_number <= 0 or not self.alerts_path.exists():
            return 0

        with open(self.alerts_path, "rb") as f:
            for _ in range(line_number):
                raw = f.readline()

                if not raw:
                    break

                offset += len(raw)

        return offset

    @staticmethod
    def _normalize_severity(severity) -> str:
        """
        Convert NIDS numeric severity to the common
        HIGH / MEDIUM / LOW representation.

        NIDS:
            1 = HIGH
            2 = MEDIUM
            3 = LOW
        """

        mapping = {
            1: "HIGH",
            2: "MEDIUM",
            3: "LOW",
        }

        try:
            severity = int(severity)
        except (TypeError, ValueError):
            return "MEDIUM"

        return mapping.get(severity, "MEDIUM")

    @staticmethod
    def _get_attack_type(
        category_type
    ) -> Optional[str]:
        """Convert category_type into a readable attack type."""

        if isinstance(
            category_type,
            list
        ) and category_type:

            return (
                category_type[0]
                .replace("_", " ")
                .title()
            )

        if isinstance(
            category_type,
            str
        ):

            return (
                category_type
                .replace("_", " ")
                .title()
            )

        return None

    def normalize_alert(
        self,
        alert_data: dict
    ) -> AlertSchema:
        """
        Convert one NIDS alert into the common AlertSchema.
        """

        alert = alert_data.get(
            "alert",
            {}
        )

        category_type = alert.get(
            "category_type",
            []
        )

        return AlertSchema(
            sensor="NIDS",

            timestamp=alert_data.get(
                "timestamp"
            ),

            event_type=alert_data.get(
                "event_type",
                "alert",
            ),

            detection_id=str(
                alert.get(
                    "signature_id",
                    alert.get(
                        "sid",
                        "UNKNOWN",
                    ),
                )
            ),

            severity=self._normalize_severity(
                alert.get("severity")
            ),

            category_type=category_type,

            attack_type=self._get_attack_type(
                category_type
            ),

            # NIDS alert data currently does not contain
            # explicit MITRE ATT&CK IDs.
            mitre_attack=[],

            source_ip=alert_data.get(
                "src_ip"
            ),

            destination_ip=alert_data.get(
                "dest_ip"
            ),

            source_port=alert_data.get(
                "src_port"
            ),

            destination_port=alert_data.get(
                "dest_port"
            ),

            host_ip=None,

            message=alert.get(
                "signature",
                alert.get(
                    "msg",
                    "",
                ),
            ),

            details=(
                f"Protocol: "
                f"{alert_data.get('proto')}; "

                f"Direction: "
                f"{alert_data.get('direction')}; "

                f"Category: "
                f"{alert.get('category')}"
            ),

            raw=alert_data,
        )

    def read_new_alerts(
        self
    ) -> list[AlertSchema]:
        """
        Read only newly appended alerts
        from alerts.json.
        """

        normalized_alerts = []

        # Complete new lines only; handles rotation and a
        # line that is still being written.
        for line in self.tail.read_lines():

            try:
                alert_data = json.loads(line)

            except json.JSONDecodeError:
                # Ignore corrupted lines.
                continue

            # Only process actual NIDS alerts.
            if alert_data.get(
                "event_type"
            ) != "alert":
                continue

            try:
                normalized_alerts.append(
                    self.normalize_alert(alert_data)
                )
            except Exception as e:
                print(f"[NIDS ADAPTER] Skipping malformed alert: {e}")

        self.tail.commit()

        return normalized_alerts