from pathlib import Path
import json
import pydivert
import yaml
import ipaddress
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from trafficevent import packet_to_event
from rules_engine import RulesEngine


# Paths
nids_dir = Path(__file__).resolve().parent
project_root = nids_dir.parent

if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from IPS.ips_engine import IPSEngine
from paths import (
    IPS_INLINE_BLOCKS_FILE,
    NIDS_ALERTS_FILE,
    NIDS_CONFIG_FILE,
    NIDS_RULES_FILE,
)
from rotation import rotate_if_needed
from stop_signal import get_stop_event, wait_for_stop

rules_path = NIDS_RULES_FILE
alerts_path = NIDS_ALERTS_FILE
config_path = NIDS_CONFIG_FILE


# ---------------------------------------------------------
# Network configuration
#
# HOME_NET and INTERFACES may be explicit lists, or "auto":
#   INTERFACES: auto -> every network adapter that is up
#   HOME_NET:   auto -> the IPv4 subnets of those adapters
# ---------------------------------------------------------

try:
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}
except FileNotFoundError:
    print(f"[!] {config_path} not found; using automatic network detection")
    config = {}

network_config = config.get("network") or {}


def is_auto(value):
    return (
        value is None
        or value == []
        or (isinstance(value, str) and value.strip().lower() == "auto")
    )


home_net_setting = network_config.get("HOME_NET", "auto")
interfaces_setting = network_config.get("INTERFACES", "auto")

AUTO_HOME_NET = is_auto(home_net_setting)
AUTO_INTERFACES = is_auto(interfaces_setting)

# Subnets that are never treated as the home network
EXCLUDED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def run_powershell_json(command):
    """Run a PowerShell command and return its JSON output as a list."""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        check=True
    )

    output = result.stdout.strip()

    if not output:
        return []

    data = json.loads(output)

    # If only one item is returned, PowerShell returns an object
    # instead of a list.
    if isinstance(data, dict):
        data = [data]

    return data


def resolve_active_interfaces():
    """
    Resolve the interfaces to capture on, with their current
    Windows indexes. Returns an empty list when none is connected.
    """
    active_adapters = run_powershell_json(
        "Get-NetAdapter | "
        "Where-Object {$_.Status -eq 'Up'} | "
        "Select-Object Name, ifIndex | "
        "ConvertTo-Json -Compress"
    )

    # Map interface name -> current Windows interface index
    adapter_indexes = {
        adapter["Name"]: int(adapter["ifIndex"])
        for adapter in active_adapters
    }

    if AUTO_INTERFACES:
        return [
            {"name": name, "index": index}
            for name, index in adapter_indexes.items()
        ]

    # Match configured interface names with currently active adapters
    configured_names = [
        interface["name"] if isinstance(interface, dict) else str(interface)
        for interface in interfaces_setting
    ]

    return [
        {"name": name, "index": adapter_indexes[name]}
        for name in configured_names
        if name in adapter_indexes
    ]


def detect_home_nets(interface_indexes):
    """IPv4 subnets assigned to the given interfaces."""
    addresses = run_powershell_json(
        "Get-NetIPAddress -AddressFamily IPv4 | "
        "Select-Object IPAddress, PrefixLength, InterfaceIndex | "
        "ConvertTo-Json -Compress"
    )

    networks = []

    for item in addresses:
        if int(item.get("InterfaceIndex", -1)) not in interface_indexes:
            continue

        network = ipaddress.ip_network(
            f"{item['IPAddress']}/{item['PrefixLength']}",
            strict=False
        )

        if any(network.subnet_of(excluded) for excluded in EXCLUDED_NETWORKS):
            continue

        if network not in networks:
            networks.append(network)

    return networks


def configured_home_nets():
    return [
        ipaddress.ip_network(str(net).strip(), strict=False)
        for net in home_net_setting
    ]


# At boot the network may not be up yet (e.g. Wi-Fi still connecting).
# Wait for a usable interface (and subnet) instead of exiting.
INTERFACE_RETRY_SECONDS = 10

while True:
    try:
        active_interfaces = resolve_active_interfaces()

        if AUTO_HOME_NET:
            home_nets = detect_home_nets(
                {interface["index"] for interface in active_interfaces}
            )
        else:
            home_nets = configured_home_nets()

    except Exception as e:
        print(f"[!] Failed to query network adapters: {e}")
        active_interfaces = []
        home_nets = []

    if active_interfaces and home_nets:
        break

    print(
        "[!] No connected network interface with an IPv4 network yet. "
        f"Retrying in {INTERFACE_RETRY_SECONDS} seconds..."
    )

    if wait_for_stop(INTERFACE_RETRY_SECONDS):
        print("[*] NIDS stopped before capture started.")
        sys.exit(0)


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

print(
    "[*] HOME_NET"
    f"{' (auto)' if AUTO_HOME_NET else ''}: "
    f"{', '.join(str(net) for net in home_nets)}"
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


# Create alerts.json if it does not exist
alerts_path.parent.mkdir(parents=True, exist_ok=True)
alerts_path.touch(exist_ok=True)

# Inline IPS block decisions (separate from the IPS worker's
# ips_alerts.json so two processes never append to one file)
inline_ips_path = IPS_INLINE_BLOCKS_FILE


# ---------------------------------------------------------
# Local host addresses (must never be blocked)
# ---------------------------------------------------------
LOCAL_IP_REFRESH_SECONDS = 60

local_ips = set()
local_ips_refreshed_at = 0.0


def refresh_local_ips(force=False):
    """Reload this machine's IP addresses (they can change via DHCP)."""
    global local_ips, local_ips_refreshed_at

    now = time.time()

    if not force and now - local_ips_refreshed_at < LOCAL_IP_REFRESH_SECONDS:
        return

    try:
        addresses = run_powershell_json(
            "Get-NetIPAddress | "
            "Select-Object IPAddress | "
            "ConvertTo-Json -Compress"
        )
        local_ips = {
            # Strip IPv6 zone index, e.g. fe80::1%12
            item["IPAddress"].split("%")[0]
            for item in addresses
            if item.get("IPAddress")
        }
    except Exception as e:
        print(f"[!] Failed to refresh local IP addresses: {e}")

    local_ips_refreshed_at = now


def get_remote_ip(event):
    """
    Return the remote side of a packet, or None if it cannot be
    determined safely. The local machine's address is never returned.
    """
    refresh_local_ips()

    if event.direction == "OUTBOUND":
        candidate = event.destination_ip
    elif event.direction == "INBOUND":
        candidate = event.source_ip
    elif event.source_ip in local_ips:
        candidate = event.destination_ip
    else:
        candidate = event.source_ip

    if not candidate or candidate in local_ips:
        return None

    return candidate


def write_inline_decision(event, decisions, blocked_ip, expiry_time):
    """Append one inline IPS block decision to logs/ips_inline_blocks.json."""
    entry = {
        "timestamp": datetime.now(timezone.utc).astimezone().isoformat(),
        "event_type": "ips_inline_decision",
        "action": "block",
        "blocked_ip": blocked_ip,
        "block_duration_seconds": BLOCK_DURATION if blocked_ip else 0,
        "block_expires": (
            datetime.fromtimestamp(expiry_time, timezone.utc).astimezone().isoformat()
            if blocked_ip
            else None
        ),
        "direction": event.direction,
        "src_ip": event.source_ip,
        "src_port": event.source_port,
        "dest_ip": event.destination_ip,
        "dest_port": event.destination_port,
        "proto": event.protocol,
        "decisions": [
            {
                "sid": decision.sid,
                "category": decision.category,
                "priority": decision.priority,
                "severity": decision.severity,
                "message": decision.message,
                "matched_indicator": decision.matched_indicator,
            }
            for decision in decisions
        ],
    }

    try:
        rotate_if_needed(inline_ips_path)
        with open(inline_ips_path, "a", encoding="utf-8") as f:
            json.dump(entry, f, ensure_ascii=False)
            f.write("\n")
            f.flush()
    except Exception as e:
        print(f"[IPS] Failed to write inline IPS decision: {e}")

 
# Initialize detection engine 
engine = RulesEngine(rules_path, debug=False) 
ips_engine = IPSEngine() 
 
# Temporary inline IPS blocklist 
# IP -> expiry timestamp 
blocked_ips = {} 
 
BLOCK_DURATION = 10 * 60  # 10 minutes

refresh_local_ips(force=True)
print(f"[*] Local addresses excluded from IPS blocking: {', '.join(sorted(local_ips)) or 'none found'}")

print("=" * 80) 
print(f"[*] RulesEngine: Loaded {len(engine.rules)} detection rules from '{rules_path.name}'") 
print("[+] NIDS live traffic capture started with PyDivert/WinDivert") 
print(f"[*] Only matching alerts are logged to '{alerts_path.name}'") 
print("[*] Non-alert traffic is not written to the alert log") 
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
 
 
# ---------------------------------------------------------
# Capture loop
#
# recv() blocks until a packet arrives. When the service asks
# to stop, a helper thread closes the WinDivert handle, which
# ends the loop; traffic then flows normally again.
# ---------------------------------------------------------
w = pydivert.WinDivert(windivert_filter)
w.open()

capture_stopping = threading.Event()


def close_on_service_stop():
    while not wait_for_stop(3600):
        pass

    capture_stopping.set()

    try:
        if w.is_open:
            w.close()
    except Exception:
        pass


if get_stop_event() is not None:
    threading.Thread(target=close_on_service_stop, daemon=True).start()

try:
    for packet in w: 
        event = packet_to_event(packet) 
 
        # --------------------------------------------------------- 
        # Temporary IP blocklist check 
        # --------------------------------------------------------- 
        current_time = time.time() 
 
        # Remove expired IPs 
        expired_ips = [ 
            ip 
            for ip, expiry in blocked_ips.items() 
            if expiry <= current_time 
        ] 
 
        for ip in expired_ips: 
            del blocked_ips[ip] 
 
        # Drop packets involving a temporarily blocked IP 
        if ( 
            event.source_ip in blocked_ips 
            or event.destination_ip in blocked_ips 
        ): 
            print( 
                f"[IPS][DROP] Temporarily blocked IP: " 
                f"{event.source_ip} -> {event.destination_ip}" 
            ) 
            continue 
 
        # --------------------------------------------------------- 
        # NIDS detection 
        # --------------------------------------------------------- 
        alerts = engine.match(event) 
 
        for alert in alerts: 
            alert_entry = alert.to_eve_dict() 
 
            with open(alerts_path, "a", encoding="utf-8") as f: 
                json.dump(alert_entry, f, separators=(",", ":")) 
                f.write("\n") 
                f.flush() 
 
            print(alert) 
 
        # --------------------------------------------------------- 
        # Inline IPS validation 
        # --------------------------------------------------------- 
        ips_decisions = ips_engine.evaluate_inline( 
            event, 
            alerts 
        ) 
 
        block_decisions = [
            decision
            for decision in ips_decisions
            if str(decision.action).lower() == "block"
        ]

        for decision in block_decisions:
            print(
                f"[IPS][BLOCK] "
                f"{decision.message} | "
                f"{event.source_ip} -> {event.destination_ip}"
            )

        # ---------------------------------------------------------
        # Packet forwarding decision
        # ---------------------------------------------------------
        if block_decisions:
            # Block only the remote IP temporarily for 10 minutes.
            # The local machine's own address is never blocked,
            # otherwise the host would lose all network access.
            expiry_time = time.time() + BLOCK_DURATION
            remote_ip = get_remote_ip(event)

            if remote_ip:
                blocked_ips[remote_ip] = expiry_time

                print(
                    f"[IPS][BLOCK] Temporary IP block applied for 10 minutes: "
                    f"{remote_ip}"
                )
            else:
                print(
                    "[IPS][BLOCK] Remote IP could not be determined safely; "
                    "dropping this packet only."
                )

            write_inline_decision(
                event,
                block_decisions,
                remote_ip,
                expiry_time
            )

            # Do NOT reinject the current packet.
            continue
 
        # No IPS block → forward normally. 
        w.send(packet)

except Exception:
    if not capture_stopping.is_set():
        raise

finally:
    try:
        if w.is_open:
            w.close()
    except Exception:
        pass

print("[*] NIDS capture stopped.")
