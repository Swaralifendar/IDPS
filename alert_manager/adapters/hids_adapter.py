import json
from pathlib import Path

from alert_manager.schema.alert_schema import AlertSchema
from rotation import JsonlTail

class HIDSAdapter:
    """
    Streams HIDS alerts from event.json.

    Responsibilities:
    - Read only newly appended data.
    - Ignore non-alert HIDS events.
    - Convert HIDS alert records into Alert Manager input.
    - Maintain a checkpoint so old alerts are not processed again.
    - Follow event.json across rotations (see rotation.py).
    """

    def __init__(self, log_path, checkpoint_path):
        self.log_path = Path(log_path)
        self.checkpoint_path = Path(checkpoint_path)

        # Existing {"offset": N} checkpoints stay valid.
        self.tail = JsonlTail(self.log_path, self.checkpoint_path)

    def read_new_alerts(self):
        """
        Read only data appended since the previous checkpoint.
        """

        alerts = []

        # Complete lines only: a line still being written is left
        # for the next call, so a corrupt line can be skipped
        # instead of stopping the reader.
        for line in self.tail.read_lines():

            try:
                event = json.loads(line)

            except json.JSONDecodeError:
                print("[HIDS ADAPTER] Skipping corrupted line in event.json")
                continue

            # HIDS adapter processes ONLY alerts.
            if event.get("type") != "alert":
                continue

            try:
                alerts.append(self.normalize_alert(event))
            except Exception as e:
                print(f"[HIDS ADAPTER] Skipping malformed alert: {e}")

        self.tail.commit()

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