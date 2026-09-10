from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class AlertSchema:
    """
    Common normalized alert structure used by Alert Manager.

    Both HIDS and NIDS adapters will convert their native
    alert formats into this structure.
    """

    # ---------------------------------------------------------
    # Identification
    # ---------------------------------------------------------

    sensor: str
    timestamp: Optional[str]
    event_type: str
    detection_id: Optional[str]

    # ---------------------------------------------------------
    # Classification
    # ---------------------------------------------------------

    severity: Optional[str]
    category_type: List[str] = field(default_factory=list)
    attack_type: Optional[str] = None
    mitre_attack: List[str] = field(default_factory=list)

    # ---------------------------------------------------------
    # Network information
    # ---------------------------------------------------------

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None

    # ---------------------------------------------------------
    # Host information
    # ---------------------------------------------------------

    host_ip: Optional[str] = None

    # ---------------------------------------------------------
    # Description
    # ---------------------------------------------------------

    message: Optional[str] = None
    details: Optional[str] = None

    # ---------------------------------------------------------
    # Original event
    # ---------------------------------------------------------

    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the normalized alert into a dictionary.
        """

        return {
            "sensor": self.sensor,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "detection_id": self.detection_id,

            "severity": self.severity,
            "category_type": self.category_type,
            "attack_type": self.attack_type,
            "mitre_attack": self.mitre_attack,

            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,

            "host_ip": self.host_ip,

            "message": self.message,
            "details": self.details,

            "raw": self.raw,
        }