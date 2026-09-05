import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Union, Any

from trafficevent import TrafficEvent
from rules_parser import Rule, ContentCondition, load_rules_from_file


class Alert:
    """Represents an intrusion detection alert generated when a TrafficEvent matches an IDS rule."""

    def __init__(self, rule: Rule, event: TrafficEvent):
        self.timestamp = event.timestamp
        self.sid = rule.sid
        self.rev = rule.rev
        self.msg = rule.msg
        self.action = rule.action
        self.classtype = rule.classtype
        self.attack_type = rule.attack_type
        self.priority = rule.priority
        self.protocol = event.protocol
        self.source_ip = event.source_ip
        self.source_port = event.source_port
        self.destination_ip = event.destination_ip
        self.destination_port = event.destination_port
        self.direction = event.direction
        self.icmp_type = getattr(event, "icmp_type", None)
        self.rule = rule
        self.event = event
        
    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "sid": self.sid,
            "rev": self.rev,
            "msg": self.msg,
            "action": self.action,
            "classtype": self.classtype,
            "priority": self.priority,
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "direction": self.direction,
            "icmp_type": self.icmp_type,
        }

    def to_eve_dict(self) -> dict:
        """Returns the alert formatted as a Suricata-style EVE JSON dictionary."""
        if isinstance(self.timestamp, (int, float)):
            try:
                ts_str = datetime.fromtimestamp(
                    self.timestamp,
                    tz=timezone.utc
                ).isoformat()
            except Exception:
                ts_str = str(self.timestamp)
        else:
            ts_str = str(self.timestamp)

        return {
            "timestamp": ts_str,
            "event_type": "alert",
            "src_ip": self.source_ip,
            "src_port": self.source_port,
            "dest_ip": self.destination_ip,
            "dest_port": self.destination_port,
            "proto": self.protocol,
            "icmp_type": self.icmp_type,
            "alert": {
                "action": self.action,
                "gid": 1,
                "signature_id": self.sid,
                "rev": self.rev,
                "signature": self.msg,
                "category": self.classtype,
                "severity": self.priority,
                "attack_type": self.attack_type,
                "sid": self.sid,
                "msg": self.msg
            },
            "direction": self.direction,
            "packet_size": getattr(self.event, "packet_size", None),
            "payload_size": getattr(self.event, "payload_size", None),
        }

    def to_eve_json(self) -> str:
        """Returns the alert as a single-line JSON string formatted for EVE.json."""
        return json.dumps(self.to_eve_dict())

    def __repr__(self) -> str:
        src = (
            f"{self.source_ip}:{self.source_port}"
            if self.source_port is not None
            else str(self.source_ip)
        )
        dst = (
            f"{self.destination_ip}:{self.destination_port}"
            if self.destination_port is not None
            else str(self.destination_ip)
        )
        return f"[ALERT] SID:{self.sid} | {self.msg} | {self.protocol} {src} -> {dst}"

    def __str__(self) -> str:
        return self.__repr__()


def match_protocol(rule_proto: str, event_proto: Optional[str]) -> bool:
    """Matches rule protocol specification against TrafficEvent protocol."""
    if not event_proto:
        return False

    r_proto = rule_proto.lower()
    e_proto = event_proto.lower()

    if r_proto in ("any", "ip"):
        return True

    if r_proto == "icmp":
        return e_proto in ("icmpv4", "icmpv6", "icmp")

    return r_proto == e_proto


def match_ip(rule_ip_pattern: str, event_ip: Optional[str]) -> bool:
    """Matches rule IP pattern (any, exact IP, CIDR subnet, IP list, negation) against event IP."""
    pattern = rule_ip_pattern.strip()

    if pattern == "any":
        return True

    if not event_ip:
        return False

    if pattern.startswith("!"):
        return not match_ip(pattern[1:].strip(), event_ip)

    if pattern.startswith("[") and pattern.endswith("]"):
        items = [
            x.strip()
            for x in pattern[1:-1].split(",")
            if x.strip()
        ]
        return any(match_ip(item, event_ip) for item in items)

    try:
        ev_addr = ipaddress.ip_address(event_ip)
        net = ipaddress.ip_network(pattern, strict=False)
        return ev_addr in net
    except ValueError:
        return pattern.lower() == event_ip.lower()


def match_port(rule_port_pattern: str, event_port: Optional[int]) -> bool:
    """Matches rule port pattern (any, single port, range, list, negation) against event port."""
    pattern = rule_port_pattern.strip()

    if pattern == "any":
        return True

    if event_port is None:
        return False

    if pattern.startswith("!"):
        return not match_port(pattern[1:].strip(), event_port)

    if pattern.startswith("[") and pattern.endswith("]"):
        items = [
            x.strip()
            for x in pattern[1:-1].split(",")
            if x.strip()
        ]
        return any(match_port(item, event_port) for item in items)

    if ":" in pattern:
        parts = pattern.split(":", 1)
        start_str, end_str = parts[0].strip(), parts[1].strip()
        start = int(start_str) if start_str else 0
        end = int(end_str) if end_str else 65535
        return start <= event_port <= end

    try:
        return int(pattern) == event_port
    except ValueError:
        return False


def match_tcp_flags(rule_flags: str, tcp_flags: Optional[dict]) -> bool:
    """
    Matches rule TCP flag specification against TrafficEvent tcp_flags dictionary.
    Supports Null scan (flags:0), individual flags (S, A, F, R, P),
    combinations (SF, SR, FP),
    and negation modifiers (!A, !S, !F, !R, !P,
    e.g. 'F,!A' or 'F!A').
    """
    if tcp_flags is None:
        return False

    rf = rule_flags.strip().upper()

    # Null scan: flags:0
    if rf == "0":
        return not any(tcp_flags.values())

    flag_map = {
        "S": "SYN",
        "A": "ACK",
        "F": "FIN",
        "R": "RST",
        "P": "PSH"
    }

    # Tokenize flags into list of (flag_name, is_negated)
    tokens = []

    if "," in rf:
        raw_tokens = [
            t.strip()
            for t in rf.split(",")
            if t.strip()
        ]

        for rt in raw_tokens:
            neg = rt.startswith("!")
            char = rt[1:] if neg else rt

            if char in flag_map:
                tokens.append((flag_map[char], neg))
    else:
        i = 0

        while i < len(rf):
            if rf[i] == "!":
                if i + 1 < len(rf) and rf[i + 1] in flag_map:
                    tokens.append(
                        (flag_map[rf[i + 1]], True)
                    )
                    i += 2
                else:
                    i += 1
            else:
                if rf[i] in flag_map:
                    tokens.append(
                        (flag_map[rf[i]], False)
                    )
                i += 1

    if not tokens:
        return True

    for flag_name, is_negated in tokens:
        val = tcp_flags.get(flag_name, False)

        if is_negated and val:
            return False

        if not is_negated and not val:
            return False

    return True


def match_size(rule_size_expr: str, actual_size: Optional[int]) -> bool:
    """Evaluates size expressions such as '>1000', '<10', '>=100', '<=100', '100<>500', or '=0'."""
    if actual_size is None:
        return False

    expr = rule_size_expr.strip()

    if "<>" in expr:
        parts = expr.split("<>", 1)
        low = int(parts[0].strip())
        high = int(parts[1].strip())
        return low <= actual_size <= high

    if expr.startswith(">="):
        return actual_size >= int(expr[2:].strip())

    if expr.startswith("<="):
        return actual_size <= int(expr[2:].strip())

    if expr.startswith(">"):
        return actual_size > int(expr[1:].strip())

    if expr.startswith("<"):
        return actual_size < int(expr[1:].strip())

    if expr.startswith("="):
        return actual_size == int(expr[1:].strip())

    try:
        return actual_size == int(expr)
    except ValueError:
        return False


def match_contents(
    contents: List[ContentCondition],
    payload: Optional[bytes]
) -> bool:
    """Evaluates one or more payload content conditions (including nocase and negation)."""
    if not contents:
        return True

    if payload is None:
        payload = b""

    payload_lower = None

    for cond in contents:
        target_payload = payload
        pattern = cond.pattern

        if cond.nocase:
            if payload_lower is None:
                payload_lower = payload.lower()

            target_payload = payload_lower
            pattern = pattern.lower()

        found = pattern in target_payload

        if cond.negated:
            if found:
                return False
        else:
            if not found:
                return False

    return True


def evaluate_rule_with_reason(
    rule: Rule,
    event: TrafficEvent
) -> tuple[bool, str]:
    """
    Evaluates whether a single TrafficEvent matches all conditions of a Rule,
    returning a tuple of (matched: bool, reason: str).
    """

    # 1. Protocol check
    if not match_protocol(rule.protocol, event.protocol):
        return False, (
            f"Protocol mismatch "
            f"(rule requires {rule.protocol.upper()}, "
            f"event is {event.protocol})"
        )

    # 2. IP & Port check with direction
    src_ip_match = match_ip(
        rule.source_ip,
        event.source_ip
    )
    src_port_match = match_port(
        rule.source_port,
        event.source_port
    )
    dst_ip_match = match_ip(
        rule.destination_ip,
        event.destination_ip
    )
    dst_port_match = match_port(
        rule.destination_port,
        event.destination_port
    )

    forward_match = (
        src_ip_match
        and src_port_match
        and dst_ip_match
        and dst_port_match
    )

    if rule.direction == "<>":
        rev_src_ip_match = match_ip(
            rule.source_ip,
            event.destination_ip
        )
        rev_src_port_match = match_port(
            rule.source_port,
            event.destination_port
        )
        rev_dst_ip_match = match_ip(
            rule.destination_ip,
            event.source_ip
        )
        rev_dst_port_match = match_port(
            rule.destination_port,
            event.source_port
        )

        reverse_match = (
            rev_src_ip_match
            and rev_src_port_match
            and rev_dst_ip_match
            and rev_dst_port_match
        )

        if not (forward_match or reverse_match):
            return False, (
                f"Bidirectional IP/port mismatch "
                f"(event {event.source_ip}:{event.source_port} "
                f"<-> {event.destination_ip}:{event.destination_port})"
            )

    else:
        if not forward_match:
            if not dst_port_match:
                return False, (
                    f"Destination port mismatch "
                    f"(rule requires {rule.destination_port}, "
                    f"event is {event.destination_port})"
                )

            if not src_port_match:
                return False, (
                    f"Source port mismatch "
                    f"(rule requires {rule.source_port}, "
                    f"event is {event.source_port})"
                )

            if not dst_ip_match:
                return False, (
                    f"Destination IP mismatch "
                    f"(rule requires {rule.destination_ip}, "
                    f"event is {event.destination_ip})"
                )

            if not src_ip_match:
                return False, (
                    f"Source IP mismatch "
                    f"(rule requires {rule.source_ip}, "
                    f"event is {event.source_ip})"
                )

            return False, "IP/Port header mismatch"

    # 3. TCP flags check
    if rule.flags is not None:
        if not match_tcp_flags(
            rule.flags,
            event.tcp_flags
        ):
            return False, (
                f"TCP flags mismatch "
                f"(rule requires flags:{rule.flags}, "
                f"event has {event.tcp_flags})"
            )

    # 4. Payload size (dsize) check
    if rule.dsize is not None:
        size = (
            event.payload_size
            if event.payload_size is not None
            else len(event.payload or b"")
        )

        if not match_size(rule.dsize, size):
            return False, (
                f"Payload size (dsize) mismatch "
                f"(rule requires {rule.dsize}, "
                f"actual size is {size})"
            )

    # 5. Packet size check
    if rule.packet_size is not None:
        if not match_size(
            rule.packet_size,
            event.packet_size
        ):
            return False, (
                f"Packet size mismatch "
                f"(rule requires {rule.packet_size}, "
                f"actual size is {event.packet_size})"
            )

    # 6. ICMP type check
    if rule.icmp_type is not None:
        event_icmp_type = getattr(
            event,
            "icmp_type",
            None
        )

        if event_icmp_type is None:
            return False, (
                f"ICMP type mismatch "
                f"(rule requires type {rule.icmp_type}, "
                f"event has no ICMP type)"
            )

        if event_icmp_type != rule.icmp_type:
            return False, (
                f"ICMP type mismatch "
                f"(rule requires type {rule.icmp_type}, "
                f"event is type {event_icmp_type})"
            )

    # 7. Payload content check
    if rule.contents:
        if not match_contents(
            rule.contents,
            event.payload
        ):
            patterns = [
                c.pattern
                for c in rule.contents
            ]

            return False, (
                "Payload content mismatch "
                f"(missing required content pattern(s): {patterns})"
            )

    # 8. Same IP / LAND attack check
    if rule.sameip:
        if not (
            event.source_ip
            and event.destination_ip
            and event.source_ip == event.destination_ip
        ):
            return False, (
                f"LAND attack mismatch "
                f"(source IP {event.source_ip} "
                f"!= dest IP {event.destination_ip})"
            )

        if (
            event.source_port is not None
            and event.destination_port is not None
        ):
            if event.source_port != event.destination_port:
                return False, (
                    f"LAND attack mismatch "
                    f"(source port {event.source_port} "
                    f"!= dest port {event.destination_port})"
                )

    return True, "All rule conditions matched"


def evaluate_rule(
    rule: Rule,
    event: TrafficEvent
) -> bool:
    """Evaluates whether a single TrafficEvent matches all conditions of a Rule."""
    matched, _ = evaluate_rule_with_reason(
        rule,
        event
    )
    return matched


class RulesEngine:
    """Custom NIDS detection engine evaluating TrafficEvents against parsed rules."""

    def __init__(
        self,
        rules: Optional[Union[str, Path, List[Rule]]] = None,
        debug: bool = False
    ):
        self.rules: List[Rule] = []
        self.debug: bool = debug

        if rules:
            if isinstance(rules, (str, Path)):
                self.load_rules_from_file(rules)
            elif isinstance(rules, list):
                self.rules = list(rules)

    def load_rules_from_file(
        self,
        filepath: Union[str, Path]
    ):
        """Loads rules from a given rules file."""
        self.rules = load_rules_from_file(filepath)

    def add_rule(self, rule: Rule):
        """Adds a single Rule object to the engine."""
        self.rules.append(rule)

    def add_rules(self, rules: List[Rule]):
        """Adds a list of Rule objects to the engine."""
        self.rules.extend(rules)

    def match(
        self,
        event: TrafficEvent,
        verbose: Optional[bool] = None
    ) -> List[Alert]:
        """
        Evaluates a single TrafficEvent against all configured rules and returns generated alerts.
        When debug is enabled (either engine-wide or via verbose=True), outputs explicit evaluation
        steps for visibility into rule matching.
        """

        show_debug = (
            self.debug
            if verbose is None
            else verbose
        )

        alerts: List[Alert] = []

        if show_debug:
            src = (
                f"{event.source_ip}:{event.source_port}"
                if event.source_port is not None
                else str(event.source_ip)
            )

            dst = (
                f"{event.destination_ip}:{event.destination_port}"
                if event.destination_port is not None
                else str(event.destination_ip)
            )

            print(
                f"[RulesEngine] Evaluating TrafficEvent: "
                f"{event.protocol} {src} -> {dst} "
                f"(size={event.packet_size}, "
                f"payload={event.payload_size}B)"
            )

        evaluated_debug_count = 0

        for rule in self.rules:
            matched, reason = evaluate_rule_with_reason(
                rule,
                event
            )

            if matched:
                alert = Alert(
                    rule,
                    event
                )

                alerts.append(alert)

                if show_debug:
                    print(
                        f"[RulesEngine] Checking "
                        f"SID:{rule.sid} "
                        f"(\"{rule.msg}\") -> MATCH"
                    )

                    print(
                        f"  --> {alert}"
                    )

            else:
                if show_debug:
                    # Provide informative debug tracing for relevant rules:
                    # 1. Baseline test rule SID:100001
                    # 2. Rules that match the event's protocol and destination/source port
                    is_baseline = (
                        rule.sid == 100001
                        and event.protocol in ("TCP", "OTHER")
                    )

                    is_port_candidate = (
                        match_protocol(
                            rule.protocol,
                            event.protocol
                        )
                        and event.destination_port is not None
                        and match_port(
                            rule.destination_port,
                            event.destination_port
                        )
                    )

                    # ICMP candidate rules are also shown during debug.
                    is_icmp_candidate = (
                        rule.icmp_type is not None
                        and match_protocol(
                            rule.protocol,
                            event.protocol
                        )
                    )

                    if (
                        is_baseline
                        or is_port_candidate
                        or is_icmp_candidate
                    ):
                        if evaluated_debug_count < 5:
                            print(
                                f"[RulesEngine] Checking "
                                f"SID:{rule.sid} "
                                f"(\"{rule.msg}\") -> "
                                f"NO MATCH ({reason})"
                            )

                            evaluated_debug_count += 1

        if show_debug:
            if alerts:
                print(
                    f"[RulesEngine] Result: MATCH "
                    f"({len(alerts)} alert(s) generated)"
                )
            else:
                print(
                    "[RulesEngine] Result: NO MATCH "
                    "(0 alerts generated)"
                )

        return alerts

    def evaluate(
        self,
        event: TrafficEvent,
        verbose: Optional[bool] = None
    ) -> List[Alert]:
        """Alias for match()."""
        return self.match(
            event,
            verbose=verbose
        )