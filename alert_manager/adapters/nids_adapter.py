import json
from pathlib import Path
from typing import Optional

from alert_manager.schema.alert_schema import AlertSchema


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

    def _load_checkpoint(self) -> int:
        """Return the number of already processed lines."""

        if not self.checkpoint_path.exists():
            return 0

        try:
            with open(
                self.checkpoint_path,
                "r",
                encoding="utf-8",
            ) as f:
                data = json.load(f)

            return int(data.get("line_number", 0))

        except (
            json.JSONDecodeError,
            ValueError,
            TypeError,
        ):
            return 0

    def _save_checkpoint(self, line_number: int) -> None:
        """Save the number of processed lines."""

        self.checkpoint_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with open(
            self.checkpoint_path,
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                {"line_number": line_number},
                f,
                indent=2,
            )

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

        if not self.alerts_path.exists():
            return []

        checkpoint = self._load_checkpoint()

        normalized_alerts = []

        # Important:
        # If alerts.json is empty, the loop below
        # will not execute. Therefore we initialize
        # this before the loop.
        last_line_number = checkpoint

        with open(
            self.alerts_path,
            "r",
            encoding="utf-8",
        ) as f:

            for line_number, line in enumerate(
                f,
                start=1,
            ):

                # Keep track of the latest line
                # that exists in the file.
                last_line_number = line_number

                # Skip lines that were already processed.
                if line_number <= checkpoint:
                    continue

                line = line.strip()

                # Ignore empty lines.
                if not line:
                    continue

                try:
                    alert_data = json.loads(line)

                except json.JSONDecodeError:
                    # Ignore incomplete/corrupted lines.
                    continue

                # Only process actual NIDS alerts.
                if alert_data.get(
                    "event_type"
                ) != "alert":
                    continue

                normalized = self.normalize_alert(
                    alert_data
                )

                normalized_alerts.append(
                    normalized
                )

        # Save the last processed line.
        #
        # IMPORTANT:
        # Use last_line_number, NOT line_number.
        # This works even when alerts.json is empty.
        self._save_checkpoint(
            last_line_number
        )

        return normalized_alerts