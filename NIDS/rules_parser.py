from pathlib import Path
from typing import List, Optional, Union, Any


class ContentCondition:
    """Represents a payload content search condition."""

    def __init__(self, pattern: bytes, nocase: bool = False, negated: bool = False, raw: str = ""):
        self.pattern = pattern
        self.nocase = nocase
        self.negated = negated
        self.raw = raw

    def __repr__(self) -> str:
        neg = "!" if self.negated else ""
        nc = " (nocase)" if self.nocase else ""
        return f"ContentCondition({neg}{self.pattern!r}{nc})"


def parse_content_bytes(content_str: str) -> bytes:
    """
    Parses a content string into raw bytes.
    Supports pipe-enclosed hexadecimal byte sequences like |4d 5a 90 00| or mixed text |ff|SMB.
    """
    if "|" not in content_str:
        return content_str.encode("latin-1", errors="ignore")

    result = bytearray()
    parts = content_str.split("|")
    for i, part in enumerate(parts):
        if i % 2 == 0:
            # Text chunk outside pipes
            if part:
                result.extend(part.encode("latin-1", errors="ignore"))
        else:
            # Hex chunk inside pipes
            hex_clean = "".join(part.split())
            if hex_clean:
                try:
                    result.extend(bytes.fromhex(hex_clean))
                except ValueError:
                    result.extend(part.encode("latin-1", errors="ignore"))
    return bytes(result)


class Rule:
    """Represents a parsed NIDS rule."""

    def __init__(
        self,
        action: str,
        protocol: str,
        source_ip: str,
        source_port: str,
        destination_ip: str,
        destination_port: str,
        msg: Optional[str] = None,
        content: Optional[str] = None,
        sid: Optional[Union[int, str]] = None,
        rev: Optional[Union[int, str]] = None,
        direction: str = "->",
        contents: Optional[List[ContentCondition]] = None,
        flags: Optional[str] = None,
        dsize: Optional[str] = None,
        packet_size: Optional[str] = None,
        icmp_type: Optional[Union[int, str]] = None,
        classtype: str = "misc-activity",
        category_type: Optional[List[str]] = None,
        priority: Union[int, str] = 3,
        sameip: bool = False,
        raw_rule: str = ""
    ):
        self.action = str(action).lower()
        self.protocol = str(protocol).lower()
        self.source_ip = str(source_ip)
        self.source_port = str(source_port)
        self.direction = str(direction)
        self.destination_ip = str(destination_ip)
        self.destination_port = str(destination_port)
        self.msg = msg
        self.sid = int(sid) if sid is not None else None
        self.rev = int(rev) if rev is not None else None
        self.flags = flags
        self.dsize = dsize
        self.packet_size = packet_size
        self.icmp_type = int(icmp_type) if icmp_type is not None else None
        self.classtype = classtype or "misc-activity"
        self.category_type = category_type or []
        self.priority = int(priority) if priority is not None else 3
        self.sameip = bool(sameip)
        self.raw_rule = raw_rule
        # Configure contents list
        if contents is not None:
            self.contents = contents
        elif content is not None:
            parsed = parse_content_bytes(content)
            self.contents = [ContentCondition(pattern=parsed, raw=content)]
        else:
            self.contents = []

    @property
    def content(self) -> Optional[str]:
        """Provides backwards compatibility for code reading rule.content."""
        if self.contents:
            return self.contents[0].raw
        return None

    @content.setter
    def content(self, value: Optional[str]):
        if value is not None:
            parsed = parse_content_bytes(value)
            self.contents = [ContentCondition(pattern=parsed, raw=value)]
        else:
            self.contents = []

    def __repr__(self) -> str:
        contents_repr = ", ".join(repr(c) for c in self.contents)
        return (
            f"Rule("
            f"sid={self.sid}, "
            f"action={self.action}, "
            f"protocol={self.protocol}, "
            f"src={self.source_ip}:{self.source_port}, "
            f"dir={self.direction}, "
            f"dst={self.destination_ip}:{self.destination_port}, "
            f"msg={self.msg!r}, "
            f"icmp_type={self.icmp_type}, "
            f"contents=[{contents_repr}]"
            f")"
        )


def _split_options(options_str: str) -> List[str]:
    """Splits options by semicolon, preserving semicolons and special characters inside quotes."""
    options = []
    current = []
    in_quotes = False
    escape = False

    for char in options_str:
        if char == '\\' and not escape:
            escape = True
            current.append(char)
            continue
        if char == '"' and not escape:
            in_quotes = not in_quotes
        elif char == ';' and not in_quotes:
            item = "".join(current).strip()
            if item:
                options.append(item)
            current = []
            escape = False
            continue
        current.append(char)
        escape = False

    item = "".join(current).strip()
    if item:
        options.append(item)

    return options


def parse_rule(line: str) -> Optional[Rule]:
    """
    Parses a single rule string into a structured Rule object.
    Returns None if the line is empty, a comment, or malformed.
    """
    line = line.strip()

    # Ignore comments and empty lines
    if not line or line.startswith("#"):
        return None

    # Must contain options enclosed in parentheses
    if "(" not in line or not line.endswith(")"):
        return None

    header_part, options_part = line.split("(", 1)
    options_part = options_part.rsplit(")", 1)[0].strip()

    header_tokens = header_part.strip().split()
    if len(header_tokens) < 7:
        return None

    action = header_tokens[0].lower()
    protocol = header_tokens[1].lower()
    source_ip = header_tokens[2]
    source_port = header_tokens[3]
    direction = header_tokens[4]
    destination_ip = header_tokens[5]
    destination_port = header_tokens[6]

    msg = None
    sid = None
    rev = None
    flags = None
    dsize = None
    packet_size = None
    icmp_type = None
    classtype = "misc-activity"
    category_type = []
    priority = 3
    sameip = False
    contents: List[ContentCondition] = []

    for option in _split_options(options_part):
        opt = option.strip()
        if not opt:
            continue

        if opt.lower() == "nocase":
            if contents:
                contents[-1].nocase = True
            continue

        if opt.lower() == "sameip":
            sameip = True
            continue

        if ":" not in opt:
            continue

        key, val = opt.split(":", 1)
        key = key.strip().lower()
        val = val.strip()

        if key == "msg":
            msg = val.strip('"')

        elif key == "content":
            negated = False
            if val.startswith("!"):
                negated = True
                val = val[1:].strip()
            pattern_str = val.strip('"')
            pattern_bytes = parse_content_bytes(pattern_str)
            contents.append(
                ContentCondition(
                    pattern=pattern_bytes,
                    nocase=False,
                    negated=negated,
                    raw=pattern_str
                )
            )

        elif key == "!content":
            pattern_str = val.strip('"')
            pattern_bytes = parse_content_bytes(pattern_str)
            contents.append(
                ContentCondition(
                    pattern=pattern_bytes,
                    nocase=False,
                    negated=True,
                    raw=pattern_str
                )
            )

        elif key == "sid":
            try:
                sid = int(val)
            except ValueError:
                pass

        elif key == "rev":
            try:
                rev = int(val)
            except ValueError:
                pass

        elif key in ("classtype", "category"):
            classtype = val.strip('"')

        elif key == "category_type":
            category_type = [
            item.strip()
            for item in val.strip('"').split(",")
            if item.strip()
    ]

        elif key in ("priority", "severity"):
            try:
                priority = int(val)
            except ValueError:
                pass

        elif key == "flags":
            flags = val.strip('"')

        elif key in ("dsize", "payload_size"):
            dsize = val.strip('"')

        elif key == "packet_size":
            packet_size = val.strip('"')

        elif key == "icmp_type":
            try:
                icmp_type = int(val)
            except ValueError:
                pass

        elif key == "sameip":
            sameip = val.lower() in ("true", "1", "yes") if val else True

    return Rule(
        action=action,
        protocol=protocol,
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        msg=msg,
        sid=sid,
        rev=rev,
        direction=direction,
        contents=contents,
        flags=flags,
        dsize=dsize,
        packet_size=packet_size,
        icmp_type=icmp_type,
        classtype=classtype,
        category_type=category_type,
        priority=priority,
        sameip=sameip,
        raw_rule=line
    )


def load_rules_from_file(filepath: Any) -> List[Rule]:
    """Loads and parses all valid rules from a file path."""
    path = Path(filepath)
    if not path.is_absolute() and not path.exists():
        candidate = Path(__file__).resolve().parent / path
        if candidate.exists():
            path = candidate

    rules = []
    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            rule = parse_rule(line)
            if rule:
                rules.append(rule)
    return rules


if __name__ == "__main__":
    rules_path = Path(__file__).resolve().parent / "rules" / "nids.rules"
    rules = load_rules_from_file(rules_path)
    print(f"Loaded {len(rules)} rules from {rules_path}:")
    for r in rules:
        print(r)
