"""
HIDS Event Normalizer.

Parses raw Windows Event Log data (XML, dictionaries, or JSON) into a unified,
standardized NormalizedEvent schema with UTC datetime normalization, forensic
preservation of raw data, and resilient field extraction.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Dict, Optional, Union
import xml.etree.ElementTree as ET


# Standard Windows Event Log Level mapping
LEVEL_MAP = {
    "0": "Information",
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information",
    "5": "Verbose",
    0: "Information",
    1: "Critical",
    2: "Error",
    3: "Warning",
    4: "Information",
    5: "Verbose",
}


@dataclass
class NormalizedEvent:
    """
    Standardized schema for all normalized Windows events across all log channels.
    """
    event_id: int = 0
    provider: str = ""
    channel: str = ""
    computer: str = ""
    timestamp: str = ""  # ISO 8601 string in UTC
    timestamp_dt: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    level: str = "Information"
    user: str = ""
    process: str = ""
    process_id: Optional[int] = None
    thread_id: Optional[int] = None
    record_id: Optional[int] = None
    message: str = ""
    event_data: Dict[str, Any] = field(default_factory=dict)
    raw_data: Any = ""

    def get(self, key: str, default: Any = None) -> Any:
        """Allow dictionary-style .get() access for backward compatibility."""
        if hasattr(self, key):
            val = getattr(self, key)
            return val if val is not None else default
        if key in self.event_data:
            return self.event_data[key]
        return default

    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-style index access."""
        if hasattr(self, key):
            return getattr(self, key)
        if key in self.event_data:
            return self.event_data[key]
        raise KeyError(key)

    def __contains__(self, key: str) -> bool:
        return hasattr(self, key) or key in self.event_data

    def to_dict(self) -> Dict[str, Any]:
        """Convert normalized event to a serializable dictionary."""
        return {
            "event_id": self.event_id,
            "provider": self.provider,
            "channel": self.channel,
            "computer": self.computer,
            "timestamp": self.timestamp,
            "timestamp_dt": self.timestamp_dt.isoformat(),
            "level": self.level,
            "user": self.user,
            "process": self.process,
            "process_id": self.process_id,
            "thread_id": self.thread_id,
            "record_id": self.record_id,
            "message": self.message,
            "event_data": self.event_data,
            "raw_data": str(self.raw_data) if self.raw_data else "",
        }


def parse_iso_timestamp(ts_str: Any) -> datetime:
    """
    Parse timestamp string or value into a timezone-aware UTC datetime.
    Gracefully handles ISO 8601 strings with 'Z', fractional seconds, or missing timezones.
    """
    if isinstance(ts_str, datetime):
        if ts_str.tzinfo is None:
            return ts_str.replace(tzinfo=timezone.utc)
        return ts_str.astimezone(timezone.utc)

    if not ts_str or not isinstance(ts_str, str):
        return datetime.now(timezone.utc)

    ts_clean = ts_str.strip()

    # Handle .NET / Windows ISO format: 2026-08-25T06:04:44.9371196Z
    try:
        if ts_clean.endswith("Z"):
            ts_clean = ts_clean[:-1] + "+00:00"

        # If fractional seconds exceed 6 digits (microseconds), truncate to 6 digits
        match = re.match(r"^(.*?\.\d{6})\d*([+-]\d{2}:?\d{2}|Z)?$", ts_clean)
        if match:
            ts_clean = match.group(1) + (match.group(2) or "")

        dt = datetime.fromisoformat(ts_clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        pass

    # Common fallback formats
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%m/%d/%Y %I:%M:%S %p",
    ):
        try:
            dt = datetime.strptime(ts_str[:19], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            continue

    return datetime.now(timezone.utc)


def _clean_tag(tag: str) -> str:
    """Remove XML namespace from element tag."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def parse_xml_event(xml_str: str) -> Optional[Dict[str, Any]]:
    """
    Parse a Windows Event XML string into a raw structured dictionary.
    Returns None if XML is malformed or not a valid Windows event.
    """
    if not xml_str or not isinstance(xml_str, str) or not xml_str.strip():
        return None

    try:
        root = ET.fromstring(xml_str)
    except Exception:
        # Malformed XML cannot be parsed as a valid Windows Event
        return None

    # Find System element
    system_elem = None
    if _clean_tag(root.tag) == "Event":
        for child in root:
            if _clean_tag(child.tag) == "System":
                system_elem = child
                break
    elif _clean_tag(root.tag) == "System":
        system_elem = root

    if system_elem is None:
        return None

    result: Dict[str, Any] = {
        "event_id": 0,
        "provider": "",
        "channel": "",
        "computer": "",
        "timestamp": "",
        "level": "Information",
        "record_id": None,
        "process_id": None,
        "thread_id": None,
        "user_id": "",
        "event_data": {},
        "raw_xml": xml_str,
    }

    for elem in system_elem:
        tag = _clean_tag(elem.tag)
        text = (elem.text or "").strip()

        if tag == "EventID":
            try:
                result["event_id"] = int(text)
            except (ValueError, TypeError):
                result["event_id"] = 0
        elif tag == "Provider":
            result["provider"] = elem.attrib.get("Name", "")
        elif tag == "Channel":
            result["channel"] = text
        elif tag == "Computer":
            result["computer"] = text
        elif tag == "TimeCreated":
            result["timestamp"] = elem.attrib.get("SystemTime", "")
        elif tag == "EventRecordID":
            try:
                result["record_id"] = int(text)
            except (ValueError, TypeError):
                pass
        elif tag == "Level":
            result["level"] = LEVEL_MAP.get(text, text or "Information")
        elif tag == "Execution":
            pid_str = elem.attrib.get("ProcessID")
            tid_str = elem.attrib.get("ThreadID")
            if pid_str and pid_str.isdigit():
                result["process_id"] = int(pid_str)
            if tid_str and tid_str.isdigit():
                result["thread_id"] = int(tid_str)
        elif tag == "Security":
            result["user_id"] = elem.attrib.get("UserID", "")

    # Parse EventData or UserData elements
    event_data: Dict[str, Any] = {}
    for child in root:
        tag = _clean_tag(child.tag)
        if tag in ("EventData", "UserData"):
            pos_index = 1
            for sub in child.iter():
                if sub is child:
                    continue
                sub_tag = _clean_tag(sub.tag)
                name = sub.attrib.get("Name") or sub.attrib.get("name")
                val = (sub.text or "").strip()

                if name:
                    event_data[name] = val
                elif sub_tag == "Data" and val:
                    event_data[f"param{pos_index}"] = val
                    pos_index += 1
                elif sub_tag not in ("EventData", "UserData", "EventXML") and val:
                    event_data[sub_tag] = val

    result["event_data"] = event_data
    return result


def extract_user(data: Dict[str, Any], event_data: Dict[str, Any]) -> str:
    """Extract standard user / account name from common event fields."""
    user_candidates = [
        event_data.get("TargetUserName"),
        event_data.get("SubjectUserName"),
        event_data.get("AccountName"),
        event_data.get("UserName"),
        event_data.get("User"),
        event_data.get("TargetUser"),
        event_data.get("MemberName"),
        data.get("user_id"),
        data.get("User"),
        data.get("user"),
    ]

    domain_candidates = [
        event_data.get("TargetDomainName"),
        event_data.get("SubjectDomainName"),
        event_data.get("AccountDomain"),
    ]

    # Find first non-empty valid user name
    for user_val in user_candidates:
        if user_val and isinstance(user_val, str) and user_val.strip() and user_val.strip() != "-":
            user_clean = user_val.strip()
            # If domain is present and not already part of user string, include it
            domain = next((d.strip() for d in domain_candidates if d and isinstance(d, str) and d.strip() and d.strip() not in ("-", ".")), None)
            if domain and "\\" not in user_clean and "@" not in user_clean and not user_clean.startswith("S-1-"):
                return f"{domain}\\{user_clean}"
            return user_clean

    return ""


def extract_process(data: Dict[str, Any], event_data: Dict[str, Any]) -> str:
    """Extract process name, executable path, or command line from event data."""
    process_candidates = [
        event_data.get("CommandLine"),
        event_data.get("ProcessCommandLine"),
        event_data.get("NewProcessName"),
        event_data.get("ImagePath"),
        event_data.get("ProcessName"),
        event_data.get("Path"),
        event_data.get("Application"),
        event_data.get("ServiceName"),
        event_data.get("ParentProcessName"),
        event_data.get("ScriptBlockText"),
        data.get("process"),
    ]

    for proc_val in process_candidates:
        if proc_val and isinstance(proc_val, str) and proc_val.strip() and proc_val.strip() != "-":
            return proc_val.strip()

    return ""


def extract_process_id(data: Dict[str, Any], event_data: Dict[str, Any]) -> Optional[int]:
    """Extract integer process ID."""
    if data.get("process_id") is not None:
        return data["process_id"]

    for key in ("NewProcessId", "ProcessId", "ProcessID"):
        val = event_data.get(key)
        if val is not None:
            if isinstance(val, int):
                return val
            if isinstance(val, str):
                try:
                    if val.startswith("0x") or val.startswith("0X"):
                        return int(val, 16)
                    return int(val)
                except ValueError:
                    pass
    return None


def normalize_event(event: Any) -> Optional[NormalizedEvent]:
    """
    Standardize any raw Windows event (XML string, dictionary, or existing NormalizedEvent)
    into a production-grade NormalizedEvent instance.
    Returns None if the event is null, malformed, or contains no valid event data.
    """
    if event is None:
        return None

    if isinstance(event, NormalizedEvent):
        return event

    raw_data = event
    event_dict: Optional[Dict[str, Any]] = None

    if isinstance(event, str):
        # XML string input
        event_dict = parse_xml_event(event)
        if event_dict is None:
            return None
    elif isinstance(event, dict):
        if not event:
            return None

        if "raw_xml" in event and isinstance(event["raw_xml"], str):
            event_dict = parse_xml_event(event["raw_xml"])
            if event_dict is not None:
                for k, v in event.items():
                    if k != "raw_xml" and v is not None:
                        event_dict[k] = v
            else:
                event_dict = event.copy()
        else:
            # Check if dictionary contains any recognizable event fields
            valid_keys = {
                "event_id", "Id", "EventID", "channel", "Channel", "LogName",
                "ProviderName", "provider", "TimeCreated", "event_data", "message", "Message"
            }
            if not any(k in event for k in valid_keys):
                return None
            event_dict = event.copy()
    else:
        return None

    if not event_dict:
        return None

    # Extract event data dict
    event_data = event_dict.get("event_data")
    if not isinstance(event_data, dict):
        event_data = {}

    # Extract Event ID
    event_id = event_dict.get("event_id") or event_dict.get("Id") or event_dict.get("EventID") or 0
    try:
        event_id = int(event_id)
    except (ValueError, TypeError):
        event_id = 0

    # Extract Provider
    provider = str(event_dict.get("provider") or event_dict.get("ProviderName") or event_dict.get("source") or "").strip()

    # Extract Channel
    channel = str(event_dict.get("channel") or event_dict.get("LogName") or event_dict.get("Channel") or "").strip()

    # Extract Computer
    computer = str(event_dict.get("computer") or event_dict.get("Computer") or event_dict.get("MachineName") or "").strip()

    # Extract Timestamp
    raw_timestamp = (
        event_dict.get("timestamp")
        or event_dict.get("TimeCreated")
        or event_dict.get("TimeGenerated")
        or ""
    )
    timestamp_dt = parse_iso_timestamp(raw_timestamp)
    timestamp_iso = timestamp_dt.isoformat()

    # Extract Level
    level_raw = event_dict.get("level") or event_dict.get("LevelDisplayName") or event_dict.get("Level") or "Information"
    level = LEVEL_MAP.get(str(level_raw).strip(), str(level_raw).strip() or "Information")

    # Extract Record ID
    record_id = event_dict.get("record_id") or event_dict.get("EventRecordID") or event_dict.get("RecordNumber")
    try:
        record_id = int(record_id) if record_id is not None else None
    except (ValueError, TypeError):
        record_id = None

    # Extract Process ID & Thread ID
    process_id = extract_process_id(event_dict, event_data)
    thread_id = event_dict.get("thread_id") or event_dict.get("ThreadID")
    try:
        thread_id = int(thread_id) if thread_id is not None else None
    except (ValueError, TypeError):
        thread_id = None

    # Extract User and Process
    user = extract_user(event_dict, event_data)
    process = extract_process(event_dict, event_data)

    # Extract or synthesize Message
    message = str(event_dict.get("message") or event_dict.get("Message") or "").strip()
    if not message:
        summary_parts = []
        if user:
            summary_parts.append(f"User={user}")
        if process:
            summary_parts.append(f"Process={process}")
        for k, v in list(event_data.items())[:5]:
            if k not in ("TargetUserName", "SubjectUserName", "CommandLine", "NewProcessName", "ImagePath"):
                summary_parts.append(f"{k}={v}")
        message = f"Event {event_id} from {provider or channel}: " + (", ".join(summary_parts) if summary_parts else "No details")

    return NormalizedEvent(
        event_id=event_id,
        provider=provider,
        channel=channel,
        computer=computer,
        timestamp=timestamp_iso,
        timestamp_dt=timestamp_dt,
        level=level,
        user=user,
        process=process,
        process_id=process_id,
        thread_id=thread_id,
        record_id=record_id,
        message=message,
        event_data=event_data,
        raw_data=raw_data,
    )