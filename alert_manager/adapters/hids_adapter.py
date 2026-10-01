import json
from pathlib import Path

from alert_manager.schema.alert_schema import AlertSchema

class HIDSAdapter:
    """
    Streams HIDS alerts from event.json.

    Responsibilities:
    - Read only newly appended data.
    - Ignore non-alert HIDS events.
    - Convert HIDS alert records into Alert Manager input.
    - Maintain a checkpoint so old alerts are not processed again.
    """

    def __init__(self, log_path, checkpoint_path):
        self.log_path = Path(log_path)
        self.checkpoint_path = Path(checkpoint_path)

    def _load_checkpoint(self):
        if not self.checkpoint_path.exists():
            return 0

        try:
            with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            return int(data.get("offset", 0))

        except (json.JSONDecodeError, ValueError, TypeError):
            return 0

    def _save_checkpoint(self, offset):
        self.checkpoint_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        temp_path = self.checkpoint_path.with_suffix(".tmp")

        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump({"offset": offset}, f)

        temp_path.replace(self.checkpoint_path)

    def read_new_alerts(self):
        """
        Read only data appended since the previous checkpoint.
        """

        if not self.log_path.exists():
            return []

        offset = self._load_checkpoint()
        alerts = []

        with open(
            self.log_path,
            "r",
            encoding="utf-8"
        ) as f:

            f.seek(offset)

            while True:
                line = f.readline()

                if not line:
                    break

                current_offset = f.tell()

                line = line.strip()

                if not line:
                    self._save_checkpoint(current_offset)
                    continue

                try:
                    event = json.loads(line)

                except json.JSONDecodeError:
                    # Do not advance past an incomplete JSON line.
                    break

                # HIDS adapter processes ONLY alerts.
                if event.get("type") != "alert":
                    self._save_checkpoint(current_offset)
                    continue

                alerts.append(self.normalize_alert(event))

                self._save_checkpoint(current_offset)

        return alerts

    def normalize_alert(self, event):
        """
        Convert a HIDS alert into the common Alert Schema.
        """

        return AlertSchema(
            sensor="HIDS",
            timestamp=event.get("timestamp"),
            event_type="alert",
            detection_id=event.get("rule_id"),

            severity=event.get("severity"),
            category_type=event.get(
                "category_type",
                []
            ),
            attack_type=event.get("attack_type"),
            mitre_attack=event.get(
                "mitre_attack",
                []
            ),
            
            source_ip=event.get("source_ip") or (event.get("event_data", {}).get("IpAddress") if event.get("event_data", {}).get("IpAddress") not in ("-", "", None) else None),
            destination_ip=event.get("destination_ip"),
            source_port=event.get("source_port"),
            destination_port=event.get("destination_port"),
            
            host_ip=event.get("system_ip"),
            
            message=event.get("rule_name"),
            details=event.get("details"),
            
            raw=event,
        )