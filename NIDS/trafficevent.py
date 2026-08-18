class TrafficEvent:
    def __init__(
        self,
        timestamp,
        direction,
        source_ip,
        destination_ip,
        protocol,
        source_port=None,
        destination_port=None,
        packet_size=None,
        payload_size=None,
        tcp_flags=None,
        payload=None
    ):
        self.timestamp = timestamp
        self.direction = direction
        self.source_ip = source_ip
        self.destination_ip = destination_ip
        self.protocol = protocol
        self.source_port = source_port
        self.destination_port = destination_port
        self.packet_size = packet_size
        self.payload_size = payload_size
        self.tcp_flags = tcp_flags
        self.payload = payload

    def __repr__(self):
        return (
            f"TrafficEvent("
            f"{self.direction} | "
            f"{self.source_ip}:{self.source_port} -> "
            f"{self.destination_ip}:{self.destination_port} | "
            f"{self.protocol} | "
            f"size={self.packet_size} | "
            f"payload={self.payload_size} bytes)"
        )


def packet_to_event(packet):

    # Direction
    if packet.is_inbound:
        direction = "INBOUND"
    elif packet.is_outbound:
        direction = "OUTBOUND"
    else:
        direction = "UNKNOWN"

    # Protocol and ports
    source_port = None
    destination_port = None
    tcp_flags = None

    if packet.tcp:
        protocol = "TCP"
        source_port = packet.tcp.src_port
        destination_port = packet.tcp.dst_port

        tcp_flags = {
            "SYN": packet.tcp.syn,
            "ACK": packet.tcp.ack,
            "FIN": packet.tcp.fin,
            "RST": packet.tcp.rst,
            "PSH": packet.tcp.psh
        }

    elif packet.udp:
        protocol = "UDP"
        source_port = packet.udp.src_port
        destination_port = packet.udp.dst_port

    elif packet.icmpv4:
        protocol = "ICMPv4"

    elif packet.icmpv6:
        protocol = "ICMPv6"

    elif packet.ipv4:
        protocol = "IPv4"

    elif packet.ipv6:
        protocol = "IPv6"

    else:
        protocol = "OTHER"

    # Packet size
    if packet.ipv4:
        packet_size = packet.ipv4.packet_len
    elif packet.ipv6:
        packet_size = packet.ipv6.packet_len
    else:
        packet_size = None

    # Create our TrafficEvent
    return TrafficEvent(
        timestamp=packet.timestamp,
        direction=direction,
        source_ip=packet.src_addr,
        destination_ip=packet.dst_addr,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
        packet_size=packet_size,
        payload_size=len(packet.payload),
        tcp_flags=tcp_flags,
        payload=packet.payload
    )