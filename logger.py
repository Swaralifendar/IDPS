import logging
from pathlib import Path
from typing import Any, Union


# Project root directory
BASE_DIR = Path(__file__).resolve().parent

# Directory where log files will be stored
LOG_DIR = BASE_DIR / "logs"

# Create the logs directory if it doesn't exist
LOG_DIR.mkdir(exist_ok=True)

# Log file
LOG_FILE = LOG_DIR / "idsips.log"


def get_logger():
    logger = logging.getLogger("IDSIPS")

    # Prevent duplicate handlers if get_logger() is called more than once
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    # Write logs to file
    file_handler = logging.FileHandler(
        LOG_FILE,
        encoding="utf-8"
    )

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    file_handler.setFormatter(formatter)

    logger.addHandler(file_handler)

    return logger


def format_security_alert(match: Any) -> str:
    """
    Format a RuleMatch object into a structured security log line.
    """
    event = getattr(match, "event", None)
    user = event.user if event and event.user else "N/A"
    computer = event.computer if event and event.computer else "N/A"
    event_id = event.event_id if event else "N/A"
    channel = event.channel if event else "N/A"

    suppress_str = f" [SUPPRESSED: {match.suppression_reason}]" if getattr(match, "suppressed", False) else ""

    return (
        f"HIDS ALERT | Severity: {match.severity.value} | Rule: {match.rule_id} | "
        f"Name: {match.rule_name} | MITRE: {match.mitre_attack} | "
        f"EventID: {event_id} | Channel: {channel} | User: {user} | Host: {computer} | "
        f"Details: {match.details}{suppress_str}"
    )


def format_correlated_alert(alert: Any) -> str:
    """
    Format a CorrelatedAlert object into a structured security log line.
    """
    return (
        f"HIDS CORRELATION | Severity: {alert.severity.value} | CorrID: {alert.correlation_id} | "
        f"Name: {alert.name} | MITRE: {alert.mitre_attack} | "
        f"Events: {len(alert.events)} | Details: {alert.details}"
    )