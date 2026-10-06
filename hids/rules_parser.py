"""
HIDS Rule Parser.

Parses human-readable HIDS rule files (e.g. hids.rules) using the syntax:
    alert -> RULE_ID -> CHANNEL -> EVENTID -> CONDITION

Provides line-numbered syntax validation, channel extraction, event ID normalization,
and structured Rule object generation.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set, Union


# Default path to hids.rules in project root
# Editable copy in the data folder (seeded from hids/hids.rules)
from paths import HIDS_RULES_FILE as DEFAULT_RULES_FILE  # noqa: E402

@dataclass
class Rule:
    """
    Represents a parsed HIDS detection rule.
    """
    rule_id: str
    channels: List[str]
    event_ids: Set[int]
    condition: str
    enabled: bool = True
    action: str = "alert"

    @property
    def channels_lower(self) -> Set[str]:
        """Return channels normalized to lowercase for case-insensitive matching."""
        return {c.lower() for c in self.channels}


class RuleParser:
    """
    Parses HIDS detection rules from a file or text content.
    """

    def __init__(
        self,
        rules_file: Optional[Union[str, Path]] = None,
        rules_content: Optional[str] = None,
    ):
        self.rules_file = Path(rules_file) if rules_file else (DEFAULT_RULES_FILE if rules_content is None else None)
        self.rules_content = rules_content

    def parse(self) -> List[Rule]:
        """
        Parse rules from file or content string.
        Returns a list of Rule objects.
        Raises ValueError with line numbers if a malformed rule is detected.
        """
        if self.rules_content is not None:
            lines = self.rules_content.splitlines()
        elif self.rules_file and self.rules_file.exists():
            with open(self.rules_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
        else:
            raise FileNotFoundError(f"HIDS rules file not found: {self.rules_file}")

        rules: List[Rule] = []

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            # Ignore blank lines and comment lines
            if not line or line.startswith("#"):
                continue

            # Strip trailing inline comments if any
            if " #" in line:
                line = line.split(" #", 1)[0].strip()

            if "->" not in line:
                raise ValueError(
                    f"Malformed rule at line {line_no}: missing '->' delimiter in {raw_line.strip()!r}"
                )

            parts = [p.strip() for p in line.split("->")]
            if len(parts) != 5:
                raise ValueError(
                    f"Malformed rule at line {line_no}: expected 5 fields "
                    f"(alert -> RULE_ID -> CHANNEL -> EVENTID -> CONDITION), "
                    f"got {len(parts)} fields in {raw_line.strip()!r}"
                )

            action, rule_id, channels_str, event_ids_str, condition = parts

            if not action or action.lower() != "alert":
                raise ValueError(
                    f"Malformed rule at line {line_no}: invalid rule action '{action}', expected 'alert'"
                )

            if not rule_id:
                raise ValueError(
                    f"Malformed rule at line {line_no}: rule ID cannot be empty"
                )

            # Parse channels
            channels = [c.strip() for c in channels_str.split(",") if c.strip()]
            if not channels:
                raise ValueError(
                    f"Malformed rule at line {line_no}: rule must define at least one channel in '{channels_str}'"
                )

            # Parse event IDs
            event_id_tokens = [e.strip() for e in event_ids_str.split(",") if e.strip()]
            if not event_id_tokens:
                raise ValueError(
                    f"Malformed rule at line {line_no}: rule must define at least one event ID in '{event_ids_str}'"
                )

            event_ids: Set[int] = set()
            for token in event_id_tokens:
                try:
                    event_ids.add(int(token))
                except ValueError:
                    raise ValueError(
                        f"Malformed rule at line {line_no}: invalid integer event ID '{token}' in '{event_ids_str}'"
                    )

            if not condition:
                raise ValueError(
                    f"Malformed rule at line {line_no}: condition cannot be empty"
                )

            rules.append(
                Rule(
                    rule_id=rule_id,
                    channels=channels,
                    event_ids=event_ids,
                    condition=condition,
                    enabled=True,
                    action=action.lower(),
                )
            )

        return rules
