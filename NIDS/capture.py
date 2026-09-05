from pathlib import Path
import json
import pydivert
import yaml
import ipaddress
import subprocess

from trafficevent import packet_to_event
from rules_engine import RulesEngine


# Paths
nids_dir = Path(__file__).resolve().parent
rules_path = nids_dir / "rules" / "nids.rules"
eve_path = nids_dir / "EVE.json"
config_path = nids_dir / "config.yml"


# Load network configuration
with open(config_path, "r", encoding="utf-8") as f:
    config = yaml.safe_load(f)

home_nets = [
    ipaddress.ip_network(net)
    for net in config["network"]["HOME_NET"]
]


# Load configured network interfaces
interfaces = config["network"].get("INTERFACES", [])

if not interfaces:
    raise RuntimeError("No network interfaces are configured.")


# Get currently connected interfaces from Windows
result = subprocess.run(
    [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-NetAdapter | "
        "Where-Object {$_.Status -eq 'Up'} | "
        "Select-Object -ExpandProperty ifIndex"
    ],
    capture_output=True,
    text=True,
    check=True
)

active_interface_indexes = {
    int(line.strip())
    for line in result.stdout.splitlines()
    if line.strip().isdigit()
}


# Keep only configured interfaces that are currently connected
active_interfaces = [
    interface
    for interface in interfaces
    if interface["index"] in active_interface_indexes
]

if not active_interfaces:
    raise RuntimeError("No configured network interfaces are currently connected.")


# Build WinDivert interface filter
interface_filters = [
    f"ifIdx == {interface['index']}"
    for interface in active_interfaces
]

interface_filter = " or ".join(
    f"({item})" for item in interface_filters
)

print("[*] Active capture interfaces:")

for interface in active_interfaces:
    print(
        f"    - {interface['name']} "
        f"(Index: {interface['index']})"
    )


# Build HOME_NET filter
home_net_filters = []

for network in home_nets:
    first_ip = network.network_address
    last_ip = network.broadcast_address

    home_net_filters.append(
        f"(ip.SrcAddr >= {first_ip} and ip.SrcAddr <= {last_ip})"
    )

    home_net_filters.append(
        f"(ip.DstAddr >= {first_ip} and ip.DstAddr <= {last_ip})"
    )

home_net_filter = " or ".join(home_net_filters)


# Final WinDivert filter
windivert_filter = (
    f"({interface_filter}) and "
    f"({home_net_filter})"
)

def is_home_net(ip):
    address = ipaddress.ip_address(ip)
    return any(address in network for network in home_nets)


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

    # Check whether source and destination belong to HOME_NET
    src_home = is_home_net(event.source_ip)
    dst_home = is_home_net(event.destination_ip)

    entry = {
        "timestamp": event.timestamp,
        "event_type": "traffic",
         "sensor_type": "NIDS",
        "direction": event.direction,
        "src_ip": event.source_ip,
        "src_port": event.source_port,
        "dest_ip": event.destination_ip,
        "dest_port": event.destination_port,
        "proto": event.protocol,
        "packet_size": event.packet_size,
        "payload_size": event.payload_size,
        "src_home_net": src_home,
        "dest_home_net": dst_home,
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


with pydivert.WinDivert(windivert_filter) as w:

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