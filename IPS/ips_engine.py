"""
IPS Engine

The IPS engine consumes correlation events produced by the
Correlation Engine.

It does NOT inspect packets or TrafficEvent objects directly.

Flow:

    correlation.json
          ↓
      IPS Engine
          ↓
       IPS Rules
          ↓
    PASS / ALERT / RECOMMEND / BLOCK

IMPORTANT:

IPS is a second-stage verifier.

An IDS detection is treated as evidence, not automatic proof.

For an IPS rule to match, ALL explicitly configured conditions
must match:

    sensor
    detection_id
    category
    protocol
    IP
    ports
    TCP flags
    payload conditions
    event count
    severity

BLOCK has one additional requirement:

    high-confidence indicator list MUST match

Therefore:

    IDS detection
        AND
    IPS validation
        AND
    indicator list
        ↓
      BLOCK
"""

from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import json
import re


# ============================================================
# PATHS
# ============================================================

IPS_DIR = Path(__file__).resolve().parent

# Editable copy in the data folder (seeded from IPS/ips.rules)
from paths import IPS_RULES_FILE as RULES_FILE  # noqa: E402

# How many (event, rule) decisions to remember so the same
# alert is not decided twice when it appears in several
# correlations (one per category and per IP).
DECISION_CACHE_SIZE = 10000


try:
    from indicators import get_indicator_list
except ImportError:
    from IPS.indicators import get_indicator_list


# ============================================================
# DECISION
# ============================================================

@dataclass
class IPSDecision:

    action: str
    message: str

    sid: Optional[str] = None
    category: Optional[str] = None
    priority: Optional[int] = None
    severity: Optional[str] = None

    indicator_list: Optional[str] = None
    matched_indicator: Optional[str] = None

    event: Dict[str, Any] = field(
        default_factory=dict
    )

    source: str = "CORRELATION"

    metadata: Dict[str, Any] = field(
        default_factory=dict
    )

    def to_dict(self) -> Dict[str, Any]:

        return {
            "event_type": "ips_decision",

            "action": self.action,

            "message": self.message,

            "sid": self.sid,

            "category": self.category,

            "priority": self.priority,

            "severity": self.severity,

            "indicator_list": self.indicator_list,

            "matched_indicator": self.matched_indicator,

            "source": self.source,

            "event": self.event,

            "metadata": self.metadata,
        }

    def __str__(self):

        return (
            f"[IPS] "
            f"Action={self.action} "
            f"SID={self.sid} "
            f"Category={self.category} "
            f"Message={self.message}"
        )


# ============================================================
# RULE
# ============================================================

@dataclass
class IPSRule:

    action: str

    protocol: str

    src_ip: str

    src_port: str

    direction: str

    dst_ip: str

    dst_port: str

    options: Dict[str, Any] = field(
        default_factory=dict
    )


# ============================================================
# IPS ENGINE
# ============================================================

class IPSEngine:

    def __init__(
        self,
        rules_path: Optional[str] = None,
    ):

        self.rules_path = Path(
            rules_path
            if rules_path
            else RULES_FILE
        )

        self.rules: List[IPSRule] = []

        # (trigger_event_id, rule sid) -> None, oldest first
        self._decided: "OrderedDict[tuple, None]" = OrderedDict()

        # trigger_event_id of events that got any decision
        self._decided_events: "OrderedDict[str, None]" = OrderedDict()

        self.load_rules()


    # ========================================================
    # LOAD RULES
    # ========================================================

    def load_rules(self):

        if not self.rules_path.exists():

            raise FileNotFoundError(
                f"IPS rules file not found: "
                f"{self.rules_path}"
            )

        self.rules = []

        with open(
            self.rules_path,
            "r",
            encoding="utf-8"
        ) as f:

            content = f.read()


        # ----------------------------------------------------
        # Remove full-line comments
        # ----------------------------------------------------

        lines = []

        for line in content.splitlines():

            stripped = line.strip()

            if not stripped:
                continue

            if stripped.startswith("#"):
                continue

            lines.append(line)

        content = "\n".join(lines)


        # ----------------------------------------------------
        # Rule format
        #
        # detect tcp any any -> $HOME_NET 80 (
        #     ...
        # )
        #
        # block ip any any -> any any (
        #     ...
        # )
        # ----------------------------------------------------

        rule_pattern = re.compile(
            r"""
            (?P<action>
                pass|
                detect|
                recommend|
                block
            )
            \s+

            (?P<protocol>\S+)
            \s+

            (?P<src_ip>\S+)
            \s+

            (?P<src_port>\S+)
            \s+

            ->
            \s+

            (?P<dst_ip>\S+)
            \s+

            (?P<dst_port>\S+)
            \s*

            \(
                (?P<options>.*?)
            \)

            """,
            re.IGNORECASE
            | re.DOTALL
            | re.VERBOSE
        )


        matches = rule_pattern.finditer(
            content
        )


        for match in matches:

            options = self._parse_options(
                match.group("options")
            )


            rule = IPSRule(

                action=match.group(
                    "action"
                ).lower(),

                protocol=match.group(
                    "protocol"
                ).lower(),

                src_ip=match.group(
                    "src_ip"
                ),

                src_port=match.group(
                    "src_port"
                ),

                direction="->",

                dst_ip=match.group(
                    "dst_ip"
                ),

                dst_port=match.group(
                    "dst_port"
                ),

                options=options,
            )


            self.rules.append(
                rule
            )


        print(
            f"[IPS] Loaded "
            f"{len(self.rules)} rules "
            f"from {self.rules_path}"
        )


    # ========================================================
    # OPTION PARSER
    # ========================================================

    def _parse_options(
        self,
        option_text: str
    ) -> Dict[str, Any]:

        options: Dict[str, Any] = {}


        # ----------------------------------------------------
        # content
        # ----------------------------------------------------

        content_match = re.search(
            r'content\s*:\s*"([^"]*)"',
            option_text,
            re.IGNORECASE
        )

        if content_match:

            options["content"] = (
                content_match.group(1)
            )


        # ----------------------------------------------------
        # content_all
        #
        # content_all:"UNION","SELECT";
        # ----------------------------------------------------

        content_all_match = re.search(
            r"""
            content_all
            \s*:\s*
            (
                (?:"[^"]*"\s*,?\s*)+
            )
            """,
            option_text,
            re.IGNORECASE
            | re.VERBOSE
        )

        if content_all_match:

            options["content_all"] = re.findall(
                r'"([^"]*)"',
                content_all_match.group(1)
            )


        # ----------------------------------------------------
        # content_any
        #
        # content_any:"foo","bar";
        # ----------------------------------------------------

        content_any_match = re.search(
            r"""
            content_any
            \s*:\s*
            (
                (?:"[^"]*"\s*,?\s*)+
            )
            """,
            option_text,
            re.IGNORECASE
            | re.VERBOSE
        )

        if content_any_match:

            options["content_any"] = re.findall(
                r'"([^"]*)"',
                content_any_match.group(1)
            )


        # ----------------------------------------------------
        # content_not
        #
        # content_not:"safe","allowed";
        # ----------------------------------------------------

        content_not_match = re.search(
            r"""
            content_not
            \s*:\s*
            (
                (?:"[^"]*"\s*,?\s*)+
            )
            """,
            option_text,
            re.IGNORECASE
            | re.VERBOSE
        )

        if content_not_match:

            options["content_not"] = re.findall(
                r'"([^"]*)"',
                content_not_match.group(1)
            )


        # ----------------------------------------------------
        # msg
        # ----------------------------------------------------

        msg_match = re.search(
            r'msg\s*:\s*"([^"]*)"',
            option_text,
            re.IGNORECASE
        )

        if msg_match:

            options["msg"] = (
                msg_match.group(1)
            )


        # ----------------------------------------------------
        # sid
        # ----------------------------------------------------

        sid_match = re.search(
            r'\bsid\s*:\s*([0-9]+)',
            option_text,
            re.IGNORECASE
        )

        if sid_match:

            options["sid"] = (
                sid_match.group(1)
            )


        # ----------------------------------------------------
        # rev
        # ----------------------------------------------------

        rev_match = re.search(
            r'\brev\s*:\s*([0-9]+)',
            option_text,
            re.IGNORECASE
        )

        if rev_match:

            options["rev"] = int(
                rev_match.group(1)
            )


        # ----------------------------------------------------
        # category_type
        # ----------------------------------------------------

        category_match = re.search(
            r'\bcategory_type\s*:\s*'
            r'([A-Za-z0-9_-]+)',
            option_text,
            re.IGNORECASE
        )

        if category_match:

            options["category_type"] = (
                category_match.group(1).upper()
            )


        # ----------------------------------------------------
        # priority
        # ----------------------------------------------------

        priority_match = re.search(
            r'\bpriority\s*:\s*([0-9]+)',
            option_text,
            re.IGNORECASE
        )

        if priority_match:

            options["priority"] = int(
                priority_match.group(1)
            )


        # ----------------------------------------------------
        # sensor
        #
        # sensor:NIDS;
        # sensor:HIDS;
        # ----------------------------------------------------

        sensor_match = re.search(
            r'\bsensor\s*:\s*'
            r'([A-Za-z0-9_-]+)',
            option_text,
            re.IGNORECASE
        )

        if sensor_match:

            options["sensor"] = (
                sensor_match.group(1).upper()
            )


        # ----------------------------------------------------
        # detection_id
        #
        # detection_id:100002;
        # ----------------------------------------------------

        detection_match = re.search(
            r'\bdetection_id\s*:\s*'
            r'([A-Za-z0-9_.-]+)',
            option_text,
            re.IGNORECASE
        )

        if detection_match:

            options["detection_id"] = (
                detection_match.group(1)
            )


        # ----------------------------------------------------
        # indicator
        #
        # indicator:src_ip;
        # indicator:payload;
        # ----------------------------------------------------

        indicator_match = re.search(
            r'\bindicator\s*:\s*'
            r'([A-Za-z0-9_-]+)',
            option_text,
            re.IGNORECASE
        )

        if indicator_match:

            options["indicator"] = (
                indicator_match.group(1)
            )


        # ----------------------------------------------------
        # list
        #
        # list:malicious_ips;
        # ----------------------------------------------------

        list_match = re.search(
            r'\blist\s*:\s*'
            r'([A-Za-z0-9_-]+)',
            option_text,
            re.IGNORECASE
        )

        if list_match:

            options["list"] = (
                list_match.group(1)
            )


        # ----------------------------------------------------
        # tcp_flags
        #
        # tcp_flags:SYN-FIN;
        # tcp_flags:NULL;
        # tcp_flags:XMAS;
        # ----------------------------------------------------

        flags_match = re.search(
            r'\btcp_flags\s*:\s*'
            r'([A-Za-z0-9_-]+)',
            option_text,
            re.IGNORECASE
        )

        if flags_match:

            options["tcp_flags"] = (
                flags_match.group(1).upper()
            )


        # ----------------------------------------------------
        # min_events
        # ----------------------------------------------------

        min_events_match = re.search(
            r'\bmin_events\s*:\s*([0-9]+)',
            option_text,
            re.IGNORECASE
        )

        if min_events_match:

            options["min_events"] = int(
                min_events_match.group(1)
            )


        # ----------------------------------------------------
        # severity_at_least
        # ----------------------------------------------------

        severity_match = re.search(
            r'\bseverity_at_least\s*:\s*'
            r'([A-Za-z0-9_-]+)',
            option_text,
            re.IGNORECASE
        )

        if severity_match:

            options["severity_at_least"] = (
                severity_match.group(1).upper()
            )


        # ----------------------------------------------------
        # nocase
        # ----------------------------------------------------

        options["nocase"] = bool(
            re.search(
                r'\bnocase\b',
                option_text,
                re.IGNORECASE
            )
        )


        return options


    # ========================================================
    # CATEGORY MATCH
    # ========================================================

    def _category_matches(
        self,
        rule: IPSRule,
        event: Dict[str, Any]
    ) -> bool:

        rule_category = rule.options.get(
            "category_type"
        )

        # Rule has no category requirement
        if not rule_category:
            return True


        # ----------------------------------------------------
        # Normalized source event
        #
        # category_type may be:
        #
        # ["EXPLOIT"]
        # ["EXPLOIT", "C2"]
        # ----------------------------------------------------

        event_categories = event.get(
            "category_type"
        )


        if event_categories:

            if isinstance(
                event_categories,
                str
            ):

                event_categories = [
                    event_categories
                ]


            normalized_categories = {
                str(category).upper()
                for category
                in event_categories
            }


            return (
                str(rule_category).upper()
                in normalized_categories
            )


        # ----------------------------------------------------
        # Fallback to correlation category
        # ----------------------------------------------------

        event_category = event.get(
            "category"
        )


        if event_category:

            return (
                str(event_category).upper()
                ==
                str(rule_category).upper()
            )


        # ----------------------------------------------------
        # FAIL CLOSED
        #
        # If rule explicitly requires a category
        # and event doesn't contain it,
        # don't match.
        # ----------------------------------------------------

        return False


    # ========================================================
    # SENSOR MATCH
    # ========================================================

    def _sensor_matches(
        self,
        rule: IPSRule,
        event: Dict[str, Any]
    ) -> bool:

        required_sensor = rule.options.get(
            "sensor"
        )

        if not required_sensor:
            return True


        event_sensor = event.get(
            "sensor"
        )

        if not event_sensor:
            return False


        return (
            str(event_sensor).upper()
            ==
            str(required_sensor).upper()
        )


    # ========================================================
    # DETECTION ID MATCH
    # ========================================================

    def _detection_id_matches(
        self,
        rule: IPSRule,
        event: Dict[str, Any]
    ) -> bool:

        required_id = rule.options.get(
            "detection_id"
        )

        if not required_id:
            return True


        # ----------------------------------------------------
        # Direct source event detection ID
        # ----------------------------------------------------

        event_id = event.get(
            "detection_id"
        )


        if event_id is not None:

            return (
                str(event_id)
                ==
                str(required_id)
            )


        # ----------------------------------------------------
        # Fallback to correlation detection_ids
        # ----------------------------------------------------

        detection_ids = event.get(
            "detection_ids",
            []
        )


        if isinstance(
            detection_ids,
            str
        ):

            detection_ids = [
                detection_ids
            ]


        return (
            str(required_id)
            in {
                str(value)
                for value in detection_ids
            }
        )


    # ========================================================
    # PROTOCOL MATCH
    # ========================================================

    def _protocol_matches(
        self,
        rule: IPSRule,
        event: Dict[str, Any]
    ) -> bool:

        rule_protocol = (
            rule.protocol.lower()
        )


        # Generic IP rule
        if rule_protocol == "ip":
            return True


        protocol = self._get_protocol(
            event
        )


        if not protocol:
            return False


        return (
            protocol.lower()
            ==
            rule_protocol
        )


    # ========================================================
    # GET PROTOCOL
    # ========================================================

    def _get_protocol(
        self,
        event: Dict[str, Any]
    ) -> Optional[str]:

        raw = event.get(
            "raw",
            {}
        )


        if not isinstance(
            raw,
            dict
        ):

            raw = {}


        protocol = (

            raw.get("proto")

            or raw.get("protocol")

            or event.get("protocol")
        )


        if not protocol:
            return None


        protocol = str(
            protocol
        ).lower()


        if protocol in {
            "tcp",
            "tcpv4",
            "tcpv6"
        }:

            return "tcp"


        if protocol in {
            "udp",
            "udpv4",
            "udpv6"
        }:

            return "udp"


        if protocol.startswith(
            "icmp"
        ):

            return "icmp"


        if protocol == "ip":
            return "ip"


        return protocol


    # ========================================================
    # PORT MATCH
    # ========================================================

    def _port_matches(
        self,
        rule_port: str,
        event_port: Any
    ) -> bool:

        rule_port = str(
            rule_port
        ).strip()


        # ----------------------------------------------------
        # ANY
        # ----------------------------------------------------

        if rule_port.lower() == "any":
            return True


        if event_port is None:
            return False


        try:

            event_port = int(
                event_port
            )

        except (
            ValueError,
            TypeError
        ):

            return False


        # ----------------------------------------------------
        # List
        #
        # [80,443,8080]
        # ----------------------------------------------------

        if (
            rule_port.startswith("[")
            and
            rule_port.endswith("]")
        ):

            values = rule_port[
                1:-1
            ].split(",")


            for value in values:

                value = value.strip()


                if not value:
                    continue


                if value.isdigit():

                    if (
                        event_port
                        ==
                        int(value)
                    ):

                        return True


            return False


        # ----------------------------------------------------
        # Comma-separated
        #
        # 80,443,8080
        # ----------------------------------------------------

        if "," in rule_port:

            values = (
                rule_port.split(",")
            )


            for value in values:

                value = value.strip()


                if value.isdigit():

                    if (
                        event_port
                        ==
                        int(value)
                    ):

                        return True


            return False


        # ----------------------------------------------------
        # Single port
        # ----------------------------------------------------

        if rule_port.isdigit():

            return (
                event_port
                ==
                int(rule_port)
            )


        # ----------------------------------------------------
        # Port range
        #
        # 1000:2000
        # ----------------------------------------------------

        if ":" in rule_port:

            start, end = (
                rule_port.split(
                    ":",
                    1
                )
            )


            try:

                start = (
                    int(start)
                    if start
                    else 0
                )

                end = (
                    int(end)
                    if end
                    else 65535
                )

            except ValueError:

                return False


            return (
                start
                <=
                event_port
                <=
                end
            )


        return False


    # ========================================================
    # IP MATCH
    # ========================================================

    def _ip_matches(
        self,
        rule_ip: str,
        event_ip: Optional[str]
    ) -> bool:

        rule_ip = str(
            rule_ip
        ).strip()


        # ANY
        if rule_ip.lower() == "any":
            return True


        # ----------------------------------------------------
        # HOME_NET
        #
        # The correlation layer already gives us
        # the relevant source/destination context.
        # ----------------------------------------------------

        if rule_ip.upper() == "$HOME_NET":

            return True


        if not event_ip:
            return False


        return (
            str(rule_ip).lower()
            ==
            str(event_ip).lower()
        )


    # ========================================================
    # GET PAYLOAD
    # ========================================================

    def _get_payload(
        self,
        event: Dict[str, Any]
    ) -> Optional[str]:

        raw = event.get(
            "raw",
            {}
        )

        if not isinstance(
            raw,
            dict
        ):
            raw = {}

        payload = (
            raw.get("payload")
            or event.get("payload")
            or event.get("details")
            or raw.get("details")
            or event.get("message")
            or raw.get("message")
        )

        if payload is None:
            return None

        if isinstance(
            payload,
            bytes
        ):
            return payload.decode(
                "utf-8",
                errors="ignore"
            )

        # NIDS stores payload as HEX in JSON.
        if isinstance(
            payload,
            str
        ):

            try:
                decoded = bytes.fromhex(
                    payload
                )

                return decoded.decode(
                    "utf-8",
                    errors="ignore"
                )

            except ValueError:
                # Payload is already plain text.
                return payload

        return str(
            payload
        )

    # ========================================================
    # BASIC CONTENT MATCH
    # ========================================================

    def _content_matches(
        self,
        rule: IPSRule,
        event: Dict[str, Any]
    ) -> bool:

        content = rule.options.get(
            "content"
        )

        # Rule has no basic content condition
        if not content:
            return True

        payload = self._get_payload(
            event
        )

        # Content is required, but payload is unavailable
        if payload is None:
            return False

        if rule.options.get(
            "nocase"
        ):
            return (
                content.lower()
                in payload.lower()
            )

        return (
            content
            in payload
        )


    # ========================================================
    # MULTI CONTENT MATCH
    # ========================================================

    def _multi_content_matches(
        self,
        rule: IPSRule,
        event: Dict[str, Any]
    ) -> bool:

        content_all = rule.options.get(
            "content_all",
            []
        )

        content_any = rule.options.get(
            "content_any",
            []
        )

        content_not = rule.options.get(
            "content_not",
            []
        )


        # No multi-content conditions
        if not (
            content_all
            or content_any
            or content_not
        ):

            return True


        payload = self._get_payload(
            event
        )


        if payload is None:
            return False


        if rule.options.get(
            "nocase"
        ):

            payload_compare = (
                payload.lower()
            )

        else:

            payload_compare = payload


        # ----------------------------------------------------
        # ALL
        #
        # Every string MUST exist.
        # ----------------------------------------------------

        for content in content_all:

            check = (
                content.lower()
                if rule.options.get("nocase")
                else content
            )


            if check not in payload_compare:

                return False


        # ----------------------------------------------------
        # ANY
        #
        # At least one MUST exist.
        # ----------------------------------------------------

        if content_any:

            found = False


            for content in content_any:

                check = (
                    content.lower()
                    if rule.options.get(
                        "nocase"
                    )
                    else content
                )


                if (
                    check
                    in
                    payload_compare
                ):

                    found = True

                    break


            if not found:
                return False


        # ----------------------------------------------------
        # NOT
        #
        # None of these may exist.
        # ----------------------------------------------------

        for content in content_not:

            check = (
                content.lower()
                if rule.options.get("nocase")
                else content
            )


            if check in payload_compare:

                return False


        return True


    # ========================================================
    # TCP FLAGS MATCH
    # ========================================================

    def _tcp_flags_matches(
        self,
        rule: IPSRule,
        event: Dict[str, Any]
    ) -> bool:

        required_flags = rule.options.get(
            "tcp_flags"
        )


        # Rule doesn't require flags
        if not required_flags:
            return True


        actual_flags = event.get(
            "tcp_flags"
        )


        # Try raw event
        if actual_flags is None:

            raw = event.get(
                "raw",
                {}
            )


            if isinstance(
                raw,
                dict
            ):

                actual_flags = raw.get(
                    "tcp_flags"
                )


        if actual_flags is None:
            return False


        actual = str(
            actual_flags
        ).upper().strip()


        required = str(
            required_flags
        ).upper().strip()


        # ----------------------------------------------------
        # Exact match
        # ----------------------------------------------------

        if actual == required:
            return True


        # ----------------------------------------------------
        # Normalize:
        #
        # SYN-FIN
        # SYN,FIN
        # SYN FIN
        # ----------------------------------------------------

        actual_set = {
            value.strip()
            for value
            in re.split(
                r"[-+,|\s]+",
                actual
            )
            if value.strip()
        }


        required_set = {
            value.strip()
            for value
            in re.split(
                r"[-+,|\s]+",
                required
            )
            if value.strip()
        }


        return (
            actual_set
            ==
            required_set
        )


    # ========================================================
    # MIN EVENTS MATCH
    # ========================================================

    def _min_events_matches(
        self,
        rule: IPSRule,
        event: Dict[str, Any]
    ) -> bool:

        required = rule.options.get(
            "min_events"
        )


        if required is None:
            return True


        event_count = event.get(
            "correlation_event_count"
        )


        if event_count is None:

            event_count = event.get(
                "event_count"
            )


        if event_count is None:
            return False


        try:

            return (
                int(event_count)
                >=
                int(required)
            )

        except (
            ValueError,
            TypeError
        ):

            return False


    # ========================================================
    # SEVERITY MATCH
    # ========================================================

    def _severity_matches(
        self,
        rule: IPSRule,
        event: Dict[str, Any]
    ) -> bool:

        required = rule.options.get(
            "severity_at_least"
        )


        if not required:
            return True


        actual = (

            event.get("severity")

            or
            event.get(
                "correlation_severity"
            )
        )


        if not actual:
            return False


        levels = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }


        actual_level = levels.get(
            str(actual).upper()
        )


        required_level = levels.get(
            str(required).upper()
        )


        if actual_level is None:
            return False


        if required_level is None:
            return False


        return (
            actual_level
            >=
            required_level
        )


    # ========================================================
    # INDICATOR VALUE
    # ========================================================

    def _get_indicator_value(
        self,
        indicator: str,
        event: Dict[str, Any]
    ) -> Optional[str]:

        indicator = str(
            indicator
        ).lower()


        if indicator == "src_ip":

            return event.get(
                "source_ip"
            )


        if indicator == "dst_ip":

            return event.get(
                "destination_ip"
            )


        if indicator == "payload":

            return self._get_payload(
                event
            )


        return None


    # ========================================================
    # INDICATOR MATCH
    # ========================================================

    def _indicator_matches(
        self,
        rule: IPSRule,
        event: Dict[str, Any]
    ):

        indicator = rule.options.get(
            "indicator"
        )


        list_name = rule.options.get(
            "list"
        )


        # BLOCK without an indicator
        # is never allowed.
        if not indicator or not list_name:

            return False, None


        indicator_value = (
            self._get_indicator_value(
                indicator,
                event
            )
        )


        if indicator_value is None:

            return False, None


        indicator_list = (
            get_indicator_list(
                list_name
            )
        )


        if not indicator_list:

            return False, None


        # ----------------------------------------------------
        # IP indicators
        # ----------------------------------------------------

        if indicator in {
            "src_ip",
            "dst_ip"
        }:

            normalized_value = (
                str(indicator_value)
                .strip()
                .lower()
            )


            for item in indicator_list:

                if (
                    normalized_value
                    ==
                    str(item)
                    .strip()
                    .lower()
                ):

                    return (
                        True,
                        str(item)
                    )


            return False, None


        # ----------------------------------------------------
        # Payload indicators
        # ----------------------------------------------------

        value = str(
            indicator_value
        ).lower()


        for item in indicator_list:

            item = str(
                item
            )


            if (
                item.lower()
                in value
            ):

                return (
                    True,
                    item
                )


        return False, None


    # ========================================================
    # RULE MATCH
    # ========================================================

    def _rule_matches(
        self,
        rule: IPSRule,
        event: Dict[str, Any]
    ):
        """
        ALL configured conditions use AND semantics.

        If any required condition fails,
        the IPS rule does not match.

        BLOCK additionally requires a configured
        indicator-list match.
        """

        # ----------------------------------------------------
        # 1. CATEGORY
        # ----------------------------------------------------

        if not self._category_matches(
            rule,
            event
        ):

            return False, None


        # ----------------------------------------------------
        # 2. SENSOR
        # ----------------------------------------------------

        if not self._sensor_matches(
            rule,
            event
        ):

            return False, None


        # ----------------------------------------------------
        # 3. EXACT IDS DETECTION
        # ----------------------------------------------------

        if not self._detection_id_matches(
            rule,
            event
        ):

            return False, None


        # ----------------------------------------------------
        # 4. PROTOCOL
        # ----------------------------------------------------

        if not self._protocol_matches(
            rule,
            event
        ):

            return False, None


        # ----------------------------------------------------
        # 5. SOURCE IP
        # ----------------------------------------------------

        if not self._ip_matches(
            rule.src_ip,
            event.get(
                "source_ip"
            )
        ):

            return False, None


        # ----------------------------------------------------
        # 6. DESTINATION IP
        # ----------------------------------------------------

        if not self._ip_matches(
            rule.dst_ip,
            event.get(
                "destination_ip"
            )
        ):

            return False, None


        # ----------------------------------------------------
        # 7. SOURCE PORT
        # ----------------------------------------------------

        if not self._port_matches(
            rule.src_port,
            event.get(
                "source_port"
            )
        ):

            return False, None


        # ----------------------------------------------------
        # 8. DESTINATION PORT
        # ----------------------------------------------------

        if not self._port_matches(
            rule.dst_port,
            event.get(
                "destination_port"
            )
        ):

            return False, None


        # ----------------------------------------------------
        # 9. TCP FLAGS
        # ----------------------------------------------------

        if not self._tcp_flags_matches(
            rule,
            event
        ):

            return False, None


        # ----------------------------------------------------
        # 10. BASIC CONTENT
        # ----------------------------------------------------

        if not self._content_matches(
            rule,
            event
        ):

            return False, None


        # ----------------------------------------------------
        # 11. MULTI CONTENT
        # ----------------------------------------------------

        if not self._multi_content_matches(
            rule,
            event
        ):

            return False, None


        # ----------------------------------------------------
        # 12. MINIMUM EVENT COUNT
        # ----------------------------------------------------

        if not self._min_events_matches(
            rule,
            event
        ):

            return False, None


        # ----------------------------------------------------
        # 13. SEVERITY
        # ----------------------------------------------------

        if not self._severity_matches(
            rule,
            event
        ):

            return False, None


        # ----------------------------------------------------
        # 14. INDICATOR VALIDATION
        #
        # If an IPS rule explicitly defines an indicator and
        # indicator list, the indicator becomes an additional
        # validation condition for all action types.
        #
        # BLOCK rules MUST have an indicator/list and the
        # indicator must match before the block is allowed.
        # ----------------------------------------------------

        has_indicator = bool(
            rule.options.get("indicator")
            and rule.options.get("list")
        )

        matched_indicator = None

        if has_indicator:

            indicator_matched, matched_indicator = (
                self._indicator_matches(
                    rule,
                    event
                )
            )

            if not indicator_matched:
                return False, None


        # ----------------------------------------------------
        # 15. BLOCK
        #
        # BLOCK rules MUST have an indicator/list.
        # This prevents generic detections from directly
        # causing a block.
        # ----------------------------------------------------

        if rule.action == "block":

            if not has_indicator:
                return False, None

            return True, matched_indicator


        # ----------------------------------------------------
        # 16. NON-BLOCK RULE
        # ----------------------------------------------------

        return True, matched_indicator


    # ========================================================
    # BUILD DECISION MESSAGE
    # ========================================================

    def _build_decision_message(
        self,
        rule: IPSRule,
        event: Dict[str, Any],
        matched_indicator: Optional[str] = None
    ) -> str:
        """
        Build a concise explanation of why a non-PASS IPS
        decision was generated. The message is based only on
        conditions that the IPS rule actually validated.
        """

        options = rule.options

        detection_id = str(
            options.get(
                "detection_id",
                event.get("detection_id", "")
            )
        )

        category = (
            options.get("category_type")
            or event.get("category")
            or event.get("correlation_category")
            or "UNKNOWN"
        )

        protocol = (
            options.get("protocol")
            or self._get_protocol(event)
            or rule.protocol
        )

        destination_port = (
            event.get("destination_port")
            or event.get("raw", {}).get("dst_port")
            or rule.dst_port
        )

        # SQL UNION SELECT
        if detection_id == "100002":
            message = (
                "SQL injection detected and validated by IPS: "
                "NIDS detection 100002 matched a "
                f"{str(protocol).upper()} request to port "
                f"{destination_port} containing both 'UNION' and "
                "'SELECT'. "
                f"The event is categorized as {category}."
            )

            if rule.action == "block" and matched_indicator:
                message += (
                    f" The payload also matched the configured "
                    f"high-confidence SQL injection indicator '{matched_indicator}'."
                )

            return message

        # SQL OR bypass
        if detection_id == "100003":
            return (
                "SQL injection authentication-bypass activity detected "
                "and validated by IPS: NIDS detection 100003 matched "
                "the configured SQL bypass pattern in the request. "
                f"The event is categorized as {category}."
            )

        # SQL SLEEP
        if detection_id == "100004":
            return (
                "Time-based SQL injection activity detected and validated "
                "by IPS: NIDS detection 100004 matched the SQL SLEEP() "
                "pattern in the request. "
                f"The event is categorized as {category}."
            )

        # XSS
        xss_messages = {
            "100005": "the '<script' pattern",
            "100006": "the 'javascript:' URI pattern",
            "100007": "the HTML onerror event-handler pattern",
        }

        if detection_id in xss_messages:
            return (
                "Cross-site scripting activity detected and validated "
                f"by IPS: NIDS detection {detection_id} matched "
                f"{xss_messages[detection_id]} in the request. "
                f"The event is categorized as {category}."
            )

        # PowerShell / command execution
        if detection_id == "100025":
            return (
                "Encoded PowerShell activity detected and validated by "
                "IPS: NIDS detection 100025 matched traffic containing "
                "both 'powershell' and '-enc'. "
                f"The event is categorized as {category}."
            )

        if detection_id == "100026":
            return (
                "Command execution activity detected and validated by "
                "IPS: NIDS detection 100026 matched traffic containing "
                "the 'cmd.exe /c' execution pattern. "
                f"The event is categorized as {category}."
            )

        # Meterpreter / Cobalt Strike
        if detection_id == "100028":
            return (
                "Meterpreter-related payload activity detected and "
                "validated by IPS: NIDS detection 100028 matched the "
                "configured executable payload signature. "
                f"The event is categorized as {category}."
            )

        if detection_id == "100029":
            return (
                "Cobalt Strike-related activity detected and validated "
                "by IPS: NIDS detection 100029 matched the configured "
                "Cobalt Strike URI pattern. "
                f"The event is categorized as {category}."
            )

        # TCP flag anomalies
        flag_messages = {
            "100031": "TCP NULL scan",
            "100032": "TCP XMAS scan",
            "100033": "TCP SYN-FIN scan",
            "100034": "TCP FIN without ACK activity",
            "100045": "TCP SYN-RST anomaly",
            "100046": "TCP FIN-RST anomaly",
            "100047": "TCP SYN-PSH anomaly",
            "100048": "TCP RST packet containing payload",
        }

        if detection_id in flag_messages:
            return (
                f"{flag_messages[detection_id]} detected and validated "
                f"by IPS: NIDS detection {detection_id} matched the "
                "configured TCP flag/anomaly conditions. "
                f"The event is categorized as {category}."
            )

        # LAND
        if detection_id in {"100065", "100096"}:
            return (
                "LAND attack pattern detected and validated by IPS: "
                f"NIDS detection {detection_id} matched the configured "
                "source and destination addressing conditions. "
                f"The event is categorized as {category}."
            )

        # ICMP reconnaissance
        if detection_id == "100066":
            return (
                "ICMP reconnaissance activity detected and validated by "
                "IPS: NIDS detection 100066 matched an ICMP Echo Request "
                "consistent with the configured reconnaissance rule. "
                f"The event is categorized as {category}."
            )

        # HIDS
        if str(options.get("sensor", event.get("sensor", ""))).upper() == "HIDS":
            return (
                "Host-based security activity detected and validated by "
                f"IPS: HIDS detection {detection_id} matched the configured "
                "host security validation conditions. "
                f"The event is categorized as {category}."
            )

        # Generic block message
        if rule.action == "block":
            if matched_indicator:
                return (
                    f"Traffic blocked after IPS validation: detection "
                    f"{detection_id} matched all configured validation "
                    f"conditions and the indicator '{matched_indicator}' "
                    "matched the configured blocking list. "
                    f"The event is categorized as {category}."
                )

            return (
                f"Traffic matched the configured IPS blocking conditions "
                f"for detection {detection_id}. "
                f"The event is categorized as {category}."
            )

        # Generic non-PASS message
        return (
            f"IPS validation succeeded: detection {detection_id} "
            "matched all configured IPS validation conditions. "
            f"The event is categorized as {category}."
        )


    # ========================================================
    # GET MATCHED CONDITIONS
    # ========================================================

    def _get_matched_conditions(
        self,
        rule: IPSRule,
        event: Dict[str, Any],
        matched_indicator: Optional[str] = None
    ) -> List[str]:
        """Return a readable list of the conditions required by the matched rule."""

        options = rule.options
        conditions = []

        if options.get("sensor"):
            conditions.append(
                f"Sensor matched: {options['sensor']}"
            )

        if options.get("detection_id"):
            conditions.append(
                f"Detection ID matched: {options['detection_id']}"
            )

        if options.get("category_type"):
            conditions.append(
                f"Category matched: {options['category_type']}"
            )

        if options.get("protocol"):
            conditions.append(
                f"Protocol matched: {str(options['protocol']).upper()}"
            )

        if str(rule.dst_port).lower() != "any":
            conditions.append(
                f"Destination port matched: {rule.dst_port}"
            )

        if str(rule.src_port).lower() != "any":
            conditions.append(
                f"Source port matched: {rule.src_port}"
            )

        if options.get("tcp_flags"):
            conditions.append(
                f"TCP flags matched: {options['tcp_flags']}"
            )

        if options.get("content"):
            conditions.append(
                f"Payload contains: {options['content']}"
            )

        for value in options.get("content_all", []):
            conditions.append(
                f"Payload contains: {value}"
            )

        if options.get("content_any"):
            conditions.append(
                "At least one configured payload pattern matched: "
                + ", ".join(options["content_any"])
            )

        for value in options.get("content_not", []):
            conditions.append(
                f"Payload does not contain: {value}"
            )

        if options.get("min_events") is not None:
            conditions.append(
                f"Minimum event count satisfied: {options['min_events']}"
            )

        if options.get("severity_at_least"):
            conditions.append(
                f"Severity requirement satisfied: {options['severity_at_least']}"
            )

        if matched_indicator:
            conditions.append(
                f"Indicator matched: {matched_indicator}"
            )

        return conditions


    # ========================================================
    # CREATE DECISION
    # ========================================================

    def _create_decision(
        self,
        rule: IPSRule,
        event: Dict[str, Any],
        matched_indicator: Optional[str] = None
    ) -> IPSDecision:

        options = rule.options


        action = rule.action.upper()


        # Existing behavior:
        # detect -> ALERT
        if action == "DETECT":

            action = "ALERT"


        return IPSDecision(

            action=action,

            message=self._build_decision_message(
                rule,
                event,
                matched_indicator
            ),

            sid=options.get(
                "sid"
            ),

            category=options.get(
                "category_type"
            ),

            priority=options.get(
                "priority"
            ),

            severity=(
                event.get("severity")
                or
                event.get(
                    "correlation_severity"
                )
            ),

            indicator_list=options.get(
                "list"
            ),

            matched_indicator=(
                matched_indicator
            ),

            event=event,

            source="CORRELATION",

            metadata={

                "window": (
                    event.get(
                        "correlation_window"
                    )
                    or
                    event.get(
                        "window"
                    )
                ),

                "event_count": (
                    event.get(
                        "correlation_event_count"
                    )
                    or
                    event.get(
                        "event_count"
                    )
                ),

                "detection_ids": event.get(
                    "detection_ids",
                    []
                ),

                "validated_sensor": (
                    event.get(
                        "sensor"
                    )
                ),

                "validated_detection_id": (
                    event.get(
                        "detection_id"
                    )
                ),

                "validated_protocol": (
                    self._get_protocol(
                        event
                    )
                ),

                "validated_source_ip": (
                    event.get(
                        "source_ip"
                    )
                ),

                "validated_destination_ip": (
                    event.get(
                        "destination_ip"
                    )
                ),

                "validated_source_port": (
                    event.get(
                        "source_port"
                    )
                ),

                "validated_destination_port": (
                    event.get(
                        "destination_port"
                    )
                ),

                "validated_tcp_flags": (
                    event.get(
                        "tcp_flags"
                    )
                ),

                "conditions_matched": self._get_matched_conditions(
                    rule,
                    event,
                    matched_indicator
                ),

                "validation": (
                    "ALL_REQUIRED_CONDITIONS_MATCHED"
                ),
            },
        )


    # ========================================================
    # PROCESS ONE CORRELATION EVENT
    # ========================================================

        # ========================================================
    # INLINE PACKET EVALUATION
    # ========================================================

    def evaluate_inline(
        self,
        traffic_event,
        nids_alerts
    ) -> List[IPSDecision]:
        """
        Evaluate the current packet against existing IPS BLOCK rules.

        This method is used by the inline NIDS path.

        It does NOT replace process_correlation().
        It only evaluates BLOCK rules synchronously for
        the current packet before it is reinjected.

        BLOCK still requires:
            IDS detection
            AND
            IPS rule conditions
            AND
            configured indicator-list match
        """

        decisions: List[IPSDecision] = []

        # ----------------------------------------------------
        # No NIDS alert means there is no IDS detection
        # for an IPS BLOCK rule to validate.
        # ----------------------------------------------------

        if not nids_alerts:
            return decisions

        # ----------------------------------------------------
        # Evaluate every NIDS alert independently.
        # ----------------------------------------------------

        for alert in nids_alerts:

            # ------------------------------------------------
            # Build the normalized event expected by the
            # existing IPS rule-matching functions.
            # ------------------------------------------------

            event = {
                "event_type": "alert",
                "sensor": "NIDS",

                # NIDS rule SID becomes the detection ID.
                "detection_id": str(
                    getattr(
                        alert,
                        "sid",
                        ""
                    )
                ),

                "timestamp": getattr(
                    alert,
                    "timestamp",
                    None
                ),

                "source_ip": traffic_event.source_ip,
                "destination_ip": traffic_event.destination_ip,

                "source_port": traffic_event.source_port,
                "destination_port": traffic_event.destination_port,

                "protocol": traffic_event.protocol,

                "tcp_flags": traffic_event.tcp_flags,

                "payload": traffic_event.payload,

                "category_type": (
                    getattr(
                        alert,
                        "category_type",
                        []
                    )
                ),

                "severity": getattr(
                    alert,
                    "severity",
                    None
                ),

                "message": getattr(
                    alert,
                    "msg",
                    None
                ),

                "raw": {
                    "proto": traffic_event.protocol,
                    "src_ip": traffic_event.source_ip,
                    "dst_ip": traffic_event.destination_ip,
                    "src_port": traffic_event.source_port,
                    "dst_port": traffic_event.destination_port,
                    "tcp_flags": traffic_event.tcp_flags,
                    "payload": traffic_event.payload,
                },
            }

            # ------------------------------------------------
            # Try ONLY BLOCK rules.
            #
            # DETECT / PASS / RECOMMEND rules continue to
            # operate through the existing correlation path.
            # ------------------------------------------------

            for rule in self.rules:

                if rule.action != "block":
                    continue

                # ------------------------------------------------
                # Correlation-only conditions cannot be evaluated
                # from one packet.
                #
                # Therefore fail closed if a BLOCK rule requires
                # correlation event count or correlation severity.
                # ------------------------------------------------

                if (
                    "min_events"
                    in rule.options
                ):
                    continue

                if (
                    "severity_at_least"
                    in rule.options
                ):
                    continue

                # ------------------------------------------------
                # Reuse the EXISTING IPS rule validation.
                #
                # This preserves:
                #   - sensor validation
                #   - detection ID validation
                #   - protocol validation
                #   - IP validation
                #   - port validation
                #   - TCP flag validation
                #   - payload validation
                #   - indicator-list validation
                # ------------------------------------------------

                matched, matched_indicator = (
                    self._rule_matches(
                        rule,
                        event
                    )
                )

                if not matched:
                    continue

                # ------------------------------------------------
                # Create the normal IPS decision object.
                # ------------------------------------------------

                decision = self._create_decision(
                    rule,
                    event,
                    matched_indicator
                )

                # Mark this decision as coming from the
                # inline packet path.
                decision.source = "INLINE"

                decision.metadata[
                    "inline"
                ] = True

                decision.metadata[
                    "validation"
                ] = "ALL_REQUIRED_CONDITIONS_MATCHED"

                decisions.append(
                    decision
                )

        return decisions

    def process_correlation(
        self,
        correlation_event: Dict[str, Any]
    ) -> List[IPSDecision]:

        if not correlation_event:

            return []


        if correlation_event.get(
            "event_type"
        ) != "correlation":

            return []


        decisions: List[
            IPSDecision
        ] = []


        # ----------------------------------------------------
        # Evaluate only the NEW event that produced this
        # correlation. Earlier events in source_events were
        # already evaluated when they arrived; evaluating
        # them again would repeat the same decisions.
        # ----------------------------------------------------

        trigger_event = correlation_event.get(
            "trigger_event"
        )

        trigger_event_id = correlation_event.get(
            "trigger_event_id"
        )

        if trigger_event:

            source_events = [
                trigger_event
            ]

        else:

            # Older correlation lines without trigger_event
            source_events = (
                correlation_event.get(
                    "source_events",
                    []
                )
                or [correlation_event]
            )

        correlation_category = str(
            correlation_event.get("category") or ""
        ).upper()


        # ====================================================
        # PROCESS EACH SOURCE EVENT
        # ====================================================

        for source_event in source_events:

            event = dict(
                source_event
            )


            # ------------------------------------------------
            # Add correlation-level context.
            #
            # Existing correlation logic is NOT changed.
            # ------------------------------------------------

            event[
                "correlation_category"
            ] = (
                correlation_event.get(
                    "category"
                )
            )


            event[
                "correlation_ip"
            ] = (
                correlation_event.get(
                    "ip"
                )
            )


            event[
                "correlation_event_count"
            ] = (
                correlation_event.get(
                    "event_count"
                )
            )


            event[
                "correlation_window"
            ] = (
                correlation_event.get(
                    "window"
                )
            )


            event[
                "correlation_severity"
            ] = (
                correlation_event.get(
                    "severity"
                )
            )


            # ------------------------------------------------
            # Try every IPS rule.
            # ------------------------------------------------

            for rule in self.rules:

                # --------------------------------------------
                # A categorized rule is evaluated only on the
                # correlation of its own category, so that
                # min_events counts the right bucket.
                # --------------------------------------------

                rule_category = str(
                    rule.options.get("category_type") or ""
                ).upper()

                if (
                    rule_category
                    and correlation_category
                    and rule_category != correlation_category
                ):
                    continue

                # --------------------------------------------
                # Same event already decided by this rule
                # (it appears once per category and per IP).
                # --------------------------------------------

                decision_key = (
                    trigger_event_id,
                    rule.options.get("sid")
                )

                if (
                    trigger_event_id
                    and decision_key in self._decided
                ):
                    continue

                matched, indicator = (
                    self._rule_matches(
                        rule,
                        event
                    )
                )


                if not matched:

                    continue


                decision = (
                    self._create_decision(
                        rule,
                        event,
                        indicator
                    )
                )


                decisions.append(
                    decision
                )

                if trigger_event_id:
                    self._remember_decision(decision_key)


        return decisions


    def _remember_decision(
        self,
        decision_key: tuple
    ):
        """Remember a decision, dropping the oldest when full."""

        self._decided[decision_key] = None

        if len(self._decided) > DECISION_CACHE_SIZE:
            self._decided.popitem(last=False)

        self._decided_events[decision_key[0]] = None

        if len(self._decided_events) > DECISION_CACHE_SIZE:
            self._decided_events.popitem(last=False)


    def event_has_decision(
        self,
        trigger_event_id: Optional[str]
    ) -> bool:
        """True if this event already produced an IPS decision."""

        return bool(
            trigger_event_id
            and trigger_event_id in self._decided_events
        )


    # ========================================================
    # PROCESS JSON LINE
    # ========================================================

    def process_json_line(
        self,
        line: str
    ) -> List[IPSDecision]:

        line = line.strip()


        if not line:

            return []


        try:

            event = json.loads(
                line
            )

        except json.JSONDecodeError:

            return []


        return self.process_correlation(
            event
        )


# ============================================================
# SIMPLE TEST
# ============================================================

if __name__ == "__main__":

    engine = IPSEngine()


    print(
        f"[IPS] Engine ready. "
        f"Rules loaded: "
        f"{len(engine.rules)}"
    )