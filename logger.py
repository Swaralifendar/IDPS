"""
IDSIPS Logging Module.

Provides consolidated, thread-safe HIDS logging:
1. Structured JSON Lines logging strictly to logs/event.json with accurate IST (+05:30) timestamps.
2. Live PowerShell console output with IST timestamps and color-coded alert severities.
"""

from datetime import datetime, timezone, timedelta
import json
import logging
from pathlib import Path
import socket
import sys
import threading
from typing import Any, Dict, List, Optional, Union

# ============================================================
# Project Paths & Timezone (IST - UTC+05:30)
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)

# Persistent HIDS event logging file
EVENT_JSON_FILE = LOG_DIR / "event.json"
JSON_LOG_FILE = EVENT_JSON_FILE
LOG_FILE = EVENT_JSON_FILE

# Windows service lifecycle log
SERVICE_LOG_FILE = LOG_DIR / "idsips.log"

# Indian Standard Time (IST) timezone
IST = timezone(timedelta(hours=5, minutes=30), name="Asia/Kolkata")

# Thread lock for concurrent file writes to event.json
_LOG_LOCK = threading.Lock()


def get_current_ist() -> datetime:
    """Return current timezone-aware datetime in IST."""
    return datetime.now(IST)

def get_system_ip() -> str:
    """Return the primary IPv4 address of the local system."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

def to_ist_iso(dt_or_str: Any) -> str:
    """
    Convert any datetime or ISO string to an accurate, timezone-aware IST ISO string (+05:30).
    """
    if isinstance(dt_or_str, datetime):
        if dt_or_str.tzinfo is None:
            return dt_or_str.replace(tzinfo=timezone.utc).astimezone(IST).isoformat()
        return dt_or_str.astimezone(IST).isoformat()

    if isinstance(dt_or_str, str) and dt_or_str.strip():
        clean_str = dt_or_str.strip()
        try:
            if clean_str.endswith("Z"):
                clean_str = clean_str[:-1] + "+00:00"
            dt = datetime.fromisoformat(clean_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(IST).isoformat()
        except Exception:
            pass

    return get_current_ist().isoformat()


# ============================================================
# Windows Console ANSI Color Support
# ============================================================

def _init_windows_console():
    """Enable Virtual Terminal Processing on Windows console for ANSI color codes."""
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            h_stdout = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
            mode = ctypes.c_ulong()
            if kernel32.GetConsoleMode(h_stdout, ctypes.byref(mode)):
                kernel32.SetConsoleMode(h_stdout, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        except Exception:
            pass

_init_windows_console()

# ANSI Color Codes
COLOR_RESET = "\033[0m"
COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_BLUE = "\033[94m"
COLOR_MAGENTA = "\033[95m"
COLOR_CYAN = "\033[96m"
COLOR_WHITE = "\033[97m"
COLOR_GRAY = "\033[90m"


# ============================================================
# PowerShell Live Console Output
# ============================================================

def _format_console_time(dt_or_str: Optional[Any] = None) -> str:
    """Format time prefix [HH:MM:SS] in IST."""
    if isinstance(dt_or_str, datetime):
        ist_dt = dt_or_str.astimezone(IST) if dt_or_str.tzinfo else dt_or_str.replace(tzinfo=timezone.utc).astimezone(IST)
    else:
        ist_dt = get_current_ist()
    return ist_dt.strftime("%H:%M:%S")


def console_event(event: Any) -> None:
    """Print live event processing telemetry to console."""
    if not event:
        return
    t_str = _format_console_time(getattr(event, "timestamp_dt", None))
    channel = getattr(event, "channel", "Unknown") or "Unknown"
    event_id = getattr(event, "event_id", "N/A")
    record_id = getattr(event, "record_id", "N/A")
    rec_str = f"RecordID: {record_id}" if record_id is not None else "RecordID: N/A"

    line = f"{COLOR_GRAY}[{t_str}]{COLOR_RESET} HIDS EVENT | {channel} | EventID: {event_id} | {rec_str}"
    print(line, flush=True)


def console_alert(match: Any) -> None:
    """Print live rule match security alert to console with color coding."""
    if not match:
        return
    event = getattr(match, "event", None)
    t_str = _format_console_time(getattr(event, "timestamp_dt", None) if event else None)

    sev_str = match.severity.value if hasattr(match.severity, "value") else str(match.severity)
    sev_upper = sev_str.upper()

    # Determine color
    if sev_upper == "CRITICAL":
        color = COLOR_RED
    elif sev_upper == "HIGH":
        color = COLOR_MAGENTA
    elif sev_upper == "MEDIUM":
        color = COLOR_YELLOW
    elif sev_upper == "LOW":
        color = COLOR_CYAN
    else:
        color = COLOR_WHITE

    rule_id = getattr(match, "rule_id", "N/A")
    rule_name = getattr(match, "rule_name", "N/A")
    suppress_str = f" [SUPPRESSED: {match.suppression_reason}]" if getattr(match, "suppressed", False) else ""

    line = (
        f"{COLOR_GRAY}[{t_str}]{COLOR_RESET} "
        f"{color}HIDS ALERT | {sev_upper} | {rule_id} | {rule_name}{suppress_str}{COLOR_RESET}"
    )
    print(line, flush=True)


def console_correlation(alert: Any) -> None:
    """Print live multi-event correlation alert to console in red."""
    if not alert:
        return
    t_str = _format_console_time()
    sev_str = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
    corr_id = getattr(alert, "correlation_id", "CORR-001")
    name = getattr(alert, "name", "Correlation Alert")
    count = len(getattr(alert, "events", []))

    line = (
        f"{COLOR_GRAY}[{t_str}]{COLOR_RESET} "
        f"{COLOR_RED}HIDS CORRELATION | {sev_str.upper()} | {corr_id} | {name} | Events: {count}{COLOR_RESET}"
    )
    print(line, flush=True)


# ============================================================
# Thread-Safe JSON Lines Logging (event.json)
# ============================================================

def write_json_log(data: Dict[str, Any], json_path: Optional[Union[str, Path]] = None) -> None:
    """
    Append one structured JSON record to event.json (JSON Lines format).
    Thread-safe and fails gracefully without crashing HIDS.
    """
    target_file = Path(json_path) if json_path else EVENT_JSON_FILE
    try:
        target_file.parent.mkdir(parents=True, exist_ok=True)
        # Ensure data values don't contain ANSI escape sequences
        json_line = json.dumps(data, ensure_ascii=False, default=str)
        with _LOG_LOCK:
            with open(target_file, "a", encoding="utf-8") as f:
                f.write(json_line + "\n")
    except Exception as exc:
        print(f"{COLOR_RED}[LOGGER ERROR] Failed writing to {target_file}: {exc}{COLOR_RESET}", file=sys.stderr, flush=True)


def _format_mitre_attack(mitre: Any) -> List[str]:
    """Convert MITRE ATT&CK string or list into a clean list of technique IDs."""
    if isinstance(mitre, list):
        return [str(m).strip() for m in mitre if m]
    if isinstance(mitre, str) and mitre:
        parts = []
        for p in mitre.replace("/", ",").split(","):
            token = p.strip().split(" - ")[0].strip()
            if token and token not in parts:
                parts.append(token)
        return parts
    return []


def log_event_json(event: Any, json_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Write a processed raw/normalized event record (type='event') to event.json.
    """
    ev_dt = getattr(event, "timestamp_dt", None) or getattr(event, "timestamp", None)
    timestamp_ist = to_ist_iso(ev_dt)
    processed_ist = get_current_ist().isoformat()

    record = {
        "timestamp": timestamp_ist,
        "processed_at": processed_ist,
        "type": "event",
        "sensor": "HIDS",
        "system_ip": get_system_ip(),
        "channel": getattr(event, "channel", "Unknown"),
        "event_id": getattr(event, "event_id", 0),
        "record_id": getattr(event, "record_id", None),
        "provider": getattr(event, "provider", ""),
        "user": getattr(event, "user", "N/A") or "N/A",
        "computer": getattr(event, "computer", "N/A") or "N/A",
        "message": getattr(event, "message", ""),
    }

    write_json_log(record, json_path=json_path)
    return record


def log_security_alert_json(match: Any, json_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Write a RuleMatch security alert (type='alert') to event.json.
    """
    event = getattr(match, "event", None)
    ev_dt = getattr(event, "timestamp_dt", None) if event else None
    timestamp_ist = to_ist_iso(ev_dt)
    processed_ist = get_current_ist().isoformat()

    sev_str = match.severity.value if hasattr(match.severity, "value") else str(match.severity)

    record = {
        "timestamp": timestamp_ist,
        "processed_at": processed_ist,
        "type": "alert",
        "sensor": "HIDS",
        "system_ip": get_system_ip(),
        "rule_id": getattr(match, "rule_id", "N/A"),
        "rule_name": getattr(match, "rule_name", "N/A"),
        "severity": sev_str,
        "mitre_attack": _format_mitre_attack(getattr(match, "mitre_attack", "")),
        "category_type": getattr(match, "category_type", []) or ["BENIGN_TEST"],
        "attack_type": getattr(match, "attack_type", "N/A"),
        "channel": getattr(event, "channel", "N/A") if event else "N/A",
        "event_id": getattr(event, "event_id", None) if event else None,
        "record_id": getattr(event, "record_id", None) if event else None,
        "user": getattr(event, "user", "N/A") if event and getattr(event, "user", None) else "N/A",
        "computer": getattr(event, "computer", "N/A") if event and getattr(event, "computer", None) else "N/A",
        "details": getattr(match, "details", ""),
        "message": getattr(match, "rule_name", ""),
        "suppressed": getattr(match, "suppressed", False),
        "suppression_reason": getattr(match, "suppression_reason", ""),
    }

    write_json_log(record, json_path=json_path)
    return record


def log_correlated_alert_json(alert: Any, json_path: Optional[Union[str, Path]] = None) -> Dict[str, Any]:
    """
    Write a CorrelatedAlert (type='correlation') to event.json.
    """
    sev_str = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
    events_count = len(alert.events) if hasattr(alert, "events") and alert.events else 0
    timestamp_ist = get_current_ist().isoformat()

    record = {
        "timestamp": timestamp_ist,
        "processed_at": timestamp_ist,
        "type": "correlation",
        "sensor": "HIDS",
        "system_ip": get_system_ip(),
        "correlation_id": getattr(alert, "correlation_id", "N/A"),
        "name": getattr(alert, "name", "N/A"),
        "severity": sev_str,
        "mitre_attack": _format_mitre_attack(getattr(alert, "mitre_attack", "")),
        "event_count": events_count,
        "details": getattr(alert, "details", ""),
    }

    write_json_log(record, json_path=json_path)
    return record


# ============================================================
# Compatibility Text Formatters & Logger
# ============================================================

def format_security_alert(match: Any) -> str:
    """Format RuleMatch as text line for console display or test assertions."""
    event = getattr(match, "event", None)
    user = event.user if event and event.user else "N/A"
    computer = event.computer if event and event.computer else "N/A"
    event_id = event.event_id if event else "N/A"
    channel = event.channel if event else "N/A"
    suppress_str = f" [SUPPRESSED: {match.suppression_reason}]" if getattr(match, "suppressed", False) else ""
    sev_str = match.severity.value if hasattr(match.severity, "value") else str(match.severity)

    return (
        f"HIDS ALERT | Severity: {sev_str} | Rule: {match.rule_id} | "
        f"Name: {match.rule_name} | MITRE: {match.mitre_attack} | "
        f"EventID: {event_id} | Channel: {channel} | User: {user} | Host: {computer} | "
        f"Details: {match.details}{suppress_str}"
    )


def format_correlated_alert(alert: Any) -> str:
    """Format CorrelatedAlert as text line for console display or test assertions."""
    sev_str = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
    events_count = len(alert.events) if hasattr(alert, "events") and alert.events else 0

    return (
        f"HIDS CORRELATION | Severity: {sev_str} | CorrID: {alert.correlation_id} | "
        f"Name: {alert.name} | MITRE: {alert.mitre_attack} | "
        f"Events: {events_count} | Details: {alert.details}"
    )


def get_logger(
    log_file: Optional[Union[str, Path]] = None
) -> logging.Logger:
    """
    Return the IDSIPS service logger.

    Service lifecycle messages are written to logs/idsips.log
    and also displayed in the console.
    """

    logger = logging.getLogger("IDSIPS")

    # Prevent duplicate handlers
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    # --------------------------------------------------------
    # File handler - logs/idsips.log
    # --------------------------------------------------------
    target_file = Path(log_file) if log_file else SERVICE_LOG_FILE
    target_file.parent.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(
        target_file,
        mode="a",
        encoding="utf-8"
    )

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    # --------------------------------------------------------
    # Console handler
    # --------------------------------------------------------
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    return logger