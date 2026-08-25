from pathlib import Path
import json
import pydivert

from trafficevent import packet_to_event
from rules_engine import RulesEngine


# Paths
nids_dir = Path(__file__).resolve().parent
rules_path = nids_dir / "rules" / "nids.rules"
eve_path = nids_dir / "EVE.json"

# Create EVE.json if it does not exist
eve_path.touch(exist_ok=True)

# Initialize detection engine
engine = RulesEngine(rules_path, debug=False)

print("=" * 80)
print(f"[*] RulesEngine: Loaded {len(engine.rules)} detection rules from '{rules_path.name}'")
print("[+] NIDS live traffic capture started with PyDivert/WinDivert")
print(f"[*] All captured traffic is logged to '{eve_path.name}'")
print("[*] Matching traffic will contain an 'alert' field")
print("=" * 80 + "\n")


def traffic_event_to_eve(event, alerts):
    """
    Convert a TrafficEvent into an EVE-style JSON object.
    All captured traffic is stored.
    If one or more rules match, the matching alerts are included.
    """

    entry = {
        "timestamp": event.timestamp,
        "event_type": "traffic",
        "direction": event.direction,
        "src_ip": event.source_ip,
        "src_port": event.source_port,
        "dest_ip": event.destination_ip,
        "dest_port": event.destination_port,
        "proto": event.protocol,
        "packet_size": event.packet_size,
        "payload_size": event.payload_size,
    }

    # Store TCP flags when available
    if event.tcp_flags is not None:
        entry["tcp_flags"] = event.tcp_flags

    # Store payload as a readable representation
    if event.payload:
        entry["payload"] = event.payload.hex()
    else:
        entry["payload"] = ""

    # Add alerts only when rules actually matched
    if alerts:
        entry["event_type"] = "alert"

        entry["alerts"] = [
            alert.to_eve_dict()
            for alert in alerts
        ]

    return entry


with pydivert.WinDivert("true") as w:

    for packet in w:

        # Packet -> TrafficEvent
        event = packet_to_event(packet)

        # TrafficEvent -> RulesEngine -> Alerts
        alerts = engine.match(event)

        # TrafficEvent -> EVE JSON
        eve_entry = traffic_event_to_eve(event, alerts)

        # Write EVERY packet/event to EVE.json
        with open(eve_path, "a", encoding="utf-8") as f:
            json.dump(eve_entry, f, separators=(",", ":"))
            f.write("\n")

        # Print ONLY actual alerts in PowerShell
        for alert in alerts:
            print(alert)

        # Reinject packet normally
        w.send(packet)