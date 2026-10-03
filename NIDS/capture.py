from pathlib import Path 
import json 
import pydivert 
import yaml 
import ipaddress 
import subprocess 
import sys 
import time  
from trafficevent import packet_to_event 
from rules_engine import RulesEngine 
 
 
# Paths 
nids_dir = Path(__file__).resolve().parent 
project_root = nids_dir.parent 
 
if str(project_root) not in sys.path: 
    sys.path.insert(0, str(project_root)) 
 
from IPS.ips_engine import IPSEngine 
rules_path = nids_dir / "rules" / "nids.rules" 
alerts_path = nids_dir / "alerts.json" 
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
# Resolve configured interface names to their current Windows indexes 
result = subprocess.run( 
    [ 
        "powershell", 
        "-NoProfile", 
        "-Command", 
        "Get-NetAdapter | " 
        "Where-Object {$_.Status -eq 'Up'} | " 
        "Select-Object Name, ifIndex | " 
        "ConvertTo-Json -Compress" 
    ], 
    capture_output=True, 
    text=True, 
    check=True 
) 
 
output = result.stdout.strip() 
 
if not output: 
    raise RuntimeError("No active network interfaces found.") 
 
active_adapters = json.loads(output) 
 
# If only one adapter is returned, PowerShell returns an object 
# instead of a list. 
if isinstance(active_adapters, dict): 
    active_adapters = [active_adapters] 
 
# Map interface name -> current Windows interface index 
adapter_indexes = { 
    adapter["Name"]: int(adapter["ifIndex"]) 
    for adapter in active_adapters 
} 
 
# Match configured interface names with currently active adapters 
active_interfaces = [] 
 
for interface in interfaces: 
    name = interface["name"] 
 
    if name in adapter_indexes: 
        active_interfaces.append({ 
            "name": name, 
            "index": adapter_indexes[name] 
        }) 
 
if not active_interfaces: 
    raise RuntimeError( 
        "None of the configured network interfaces are currently connected." 
    ) 
 
 
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
 
 
# Create alerts.json if it does not exist 
alerts_path.touch(exist_ok=True) 
 
 
# Initialize detection engine 
engine = RulesEngine(rules_path, debug=False) 
ips_engine = IPSEngine() 
 
# Temporary inline IPS blocklist 
# IP -> expiry timestamp 
blocked_ips = {} 
 
BLOCK_DURATION = 10 * 60  # 10 minutes 
 
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
 
 
with pydivert.WinDivert(windivert_filter) as w: 
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
 
        blocked = False 
 
        for decision in ips_decisions: 
            if decision.action == "block": 
                blocked = True 
 
                print( 
                    f"[IPS][BLOCK] " 
                    f"{decision.message} | " 
                    f"{event.source_ip} -> {event.destination_ip}" 
                ) 
 
        # --------------------------------------------------------- 
        # Packet forwarding decision 
        # --------------------------------------------------------- 
        if blocked: 
            # Block both IPs temporarily for 10 minutes. 
            expiry_time = time.time() + BLOCK_DURATION 
 
            blocked_ips[event.source_ip] = expiry_time 
            blocked_ips[event.destination_ip] = expiry_time 
 
            print( 
                f"[IPS][BLOCK] Temporary IP block applied for 10 minutes: " 
                f"{event.source_ip}, {event.destination_ip}" 
            ) 
 
            # Do NOT reinject the current packet. 
            continue 
 
        # No IPS block → forward normally. 
        w.send(packet)