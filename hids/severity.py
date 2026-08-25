"""
HIDS Severity System.

Defines standardized, comparable security severity levels for intrusion detection alerts.
"""

from enum import Enum
from functools import total_ordering
from typing import Any, Union


@total_ordering
class Severity(Enum):
    """
    Standardized security alert severity levels.

    Severities are strictly ordered:
    INFO < LOW < MEDIUM < HIGH < CRITICAL
    """
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Return numerical ranking for comparison."""
        ranks = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5,
        }
        return ranks[self]

    def __lt__(self, other: Any) -> bool:
        if isinstance(other, Severity):
            return self.rank < other.rank
        if isinstance(other, str):
            other_sev = Severity.from_string(other)
            return self.rank < other_sev.rank
        return NotImplemented

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, Severity):
            return self.rank == other.rank
        if isinstance(other, str):
            try:
                other_sev = Severity.from_string(other)
                return self.rank == other_sev.rank
            except ValueError:
                return False
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)

    def __str__(self) -> str:
        return self.value

    @classmethod
    def from_string(cls, value: Union[str, "Severity"], default: "Severity" = None) -> "Severity":
        """
        Parse a string into a Severity enum instance (case-insensitive).
        Returns default if provided and value is invalid.
        """
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            normalized = value.strip().upper()
            for sev in cls:
                if sev.value == normalized:
                    return sev
        if default is not None:
            return default
        raise ValueError(f"Unknown severity level: {value!r}. Valid levels: {[s.value for s in cls]}")
