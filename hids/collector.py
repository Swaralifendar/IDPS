"""
HIDS Windows Event Collector.

Collects real-time Windows Event logs using the native Windows Event Log API (pywin32)
with persistent per-channel EventRecordID checkpointing, atomic state writes,
failure isolation per channel, and graceful permission/error recovery.
"""

import json
import logging
import os
from pathlib import Path
import tempfile
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET

try:
    import win32evtlog
    import win32event
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False


# Default project root paths.
#
# NOTE: "runtime/" is the embedded/portable Python interpreter used by
# setup.ps1 for packaging (see runtime/python*.dll, runtime/Scripts, etc.).
# It is NOT a place for application state. The single authoritative
# checkpoint location for the whole project is logs/checkpoints.json,
# matching config.yaml's `hids.checkpoint.file` default. This constant is
# only used when a caller constructs WindowsEventCollector/
# EventCheckpointManager without an explicit checkpoint_path (e.g. the
# legacy collect_system_events() helper below); HIDSEngine and service.py
# always resolve and pass the config-driven path explicitly.
BASE_DIR = Path(__file__).resolve().parent.parent
from paths import HIDS_COLLECTOR_CHECKPOINT_FILE as DEFAULT_CHECKPOINT_FILE  # noqa: E402

# Standard security channels to monitor
DEFAULT_MONITORED_CHANNELS = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-PowerShell/Operational",
    "Windows PowerShell",
]


class EventCheckpointManager:
    """
    Manages persistent per-channel EventRecordID checkpoints.
    Uses atomic writes to prevent corruption during power failure or service restart.
    """

    def __init__(self, checkpoint_path: Optional[Path] = None):
        self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else DEFAULT_CHECKPOINT_FILE
        self.checkpoints: Dict[str, int] = {}
        self._ensure_dir()
        self.load()

    def _ensure_dir(self):
        """Ensure parent directory exists."""
        try:
            self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def load(self) -> Dict[str, int]:
        """Load checkpoints from disk."""
        if not self.checkpoint_path.exists():
            self.checkpoints = {}
            return self.checkpoints

        try:
            with open(self.checkpoint_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    self.checkpoints = {}
                    return self.checkpoints
                data = json.loads(content)
                if isinstance(data, dict):
                    self.checkpoints = {
                        str(k): int(v) for k, v in data.items() if str(v).isdigit() or isinstance(v, int)
                    }
                else:
                    self.checkpoints = {}
        except Exception as e:
            logging.getLogger("IDSIPS").warning(
                "Failed to load checkpoint file %s: %s. Reinitializing checkpoints.",
                self.checkpoint_path,
                e,
            )
            self.checkpoints = {}
        return self.checkpoints

    def get(self, channel: str) -> Optional[int]:
        """Get the last processed EventRecordID for a channel."""
        return self.checkpoints.get(channel)

    def set(self, channel: str, record_id: int):
        """Update in-memory checkpoint for a channel."""
        if record_id is not None:
            self.checkpoints[channel] = max(self.checkpoints.get(channel, 0), int(record_id))

    def save(self):
        """
        Atomically write current checkpoints to disk.
        """
        self._ensure_dir()
        temp_file = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=str(self.checkpoint_path.parent),
                delete=False,
            ) as f:
                temp_file = Path(f.name)
                json.dump(self.checkpoints, f, indent=2)
                f.flush()
                os.fsync(f.fileno())

            # Atomic replace
            temp_file.replace(self.checkpoint_path)
        except Exception as e:
            logging.getLogger("IDSIPS").error("Failed to atomically save checkpoint file: %s", e)
            if temp_file and temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass


class WindowsEventCollector:
    """
    Production-grade Windows Event Log Collector.
    Queries native Windows Event channels, renders XML, tracks checkpoints,
    and isolates channel-specific failures.
    """

    def __init__(
        self,
        channels: Optional[List[str]] = None,
        checkpoint_path: Optional[Path] = None,
        batch_size: int = 100,
    ):
        self.channels = list(channels) if channels else list(DEFAULT_MONITORED_CHANNELS)
        self.batch_size = batch_size
        self.checkpoint_mgr = EventCheckpointManager(checkpoint_path)
        self.disabled_channels: Set[str] = set()
        self._failed_channel_warned: Set[str] = set()
        self._logger = logging.getLogger("IDSIPS")

        self._logger.info("Collector initialized for channels: %s", self.channels)

        # Log loaded checkpoints
        for ch, rec_id in self.checkpoint_mgr.checkpoints.items():
            self._logger.info("Checkpoint loaded: [%s] -> RecordID %d", ch, rec_id)

        # Initialize baselines for channels without prior checkpoints
        self._initialize_unseen_channels()

    def _initialize_unseen_channels(self):
        """
        For any channel that does not have an existing saved checkpoint,
        query the latest event record ID as the baseline to avoid flooding
        historical alerts on fresh start.
        """
        if not PYWIN32_AVAILABLE:
            return

        for channel in self.channels:
            if self.checkpoint_mgr.get(channel) is not None:
                continue

            query = None
            try:
                query = win32evtlog.EvtQuery(
                    channel,
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                )
            except Exception as e:
                if channel not in self._failed_channel_warned:
                    self._logger.warning(
                        "Channel [%s] baseline initialization skipped: %s (Will retry during collection)",
                        channel,
                        self._describe_channel_error("EvtQuery", e),
                    )
                    self._failed_channel_warned.add(channel)
                continue

            try:
                events = win32evtlog.EvtNext(query, 1)
            except Exception as e:
                if channel not in self._failed_channel_warned:
                    self._logger.warning(
                        "Channel [%s] baseline initialization skipped: %s (Will retry during collection)",
                        channel,
                        self._describe_channel_error("EvtNext", e),
                    )
                    self._failed_channel_warned.add(channel)
                continue

            if not events:
                # Channel exists but is currently empty
                self.checkpoint_mgr.set(channel, 0)
                self._logger.info("Baseline checkpoint initialized for empty channel [%s] at RecordID 0", channel)
                continue

            try:
                xml_str = win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
            except Exception as e:
                if channel not in self._failed_channel_warned:
                    self._logger.warning(
                        "Channel [%s] baseline initialization skipped: %s (Will retry during collection)",
                        channel,
                        self._describe_channel_error("EvtRender", e),
                    )
                    self._failed_channel_warned.add(channel)
                continue

            rec_id = self._extract_record_id_from_xml(xml_str)
            if rec_id is not None:
                self.checkpoint_mgr.set(channel, rec_id)
                self._logger.info(
                    "Baseline checkpoint created for [%s] at RecordID %d",
                    channel,
                    rec_id,
                )
            else:
                if channel not in self._failed_channel_warned:
                    self._logger.warning(
                        "Channel [%s] baseline initialization skipped: EventRecordID could not be "
                        "extracted from the rendered event XML (Will retry during collection)",
                        channel,
                    )
                    self._failed_channel_warned.add(channel)

        self.checkpoint_mgr.save()

    @staticmethod
    def _describe_channel_error(op: str, e: Exception) -> str:
        """
        Produce an actionable diagnostic message for a failed Windows Event Log
        API call, identifying which operation failed and, for the common
        Access Denied case, explaining the real-world cause (the calling
        account lacks read access to the channel) rather than a bare error code.

        pywin32 raises pywintypes.error as a 3-tuple (winerror, funcname, strerror)
        for Win32 API failures, and PermissionError for some wrapped cases.
        Both expose enough information to identify the failing call and cause.
        """
        winerror = None
        funcname = None
        strerror = str(e)

        args = getattr(e, "args", None)
        if args and len(args) >= 3 and isinstance(args[0], int):
            winerror, funcname, strerror = args[0], args[1], args[2]
        elif isinstance(e, PermissionError):
            winerror = getattr(e, "winerror", 5) or 5

        if winerror == 5:  # ERROR_ACCESS_DENIED
            api_call = funcname or op
            return (
                f"{api_call} denied (WinError 5, Access is denied). "
                "The account running this process does not have permission to "
                "read this channel. Reading the Security channel specifically "
                "requires the process to run as LocalSystem/a Windows Service, "
                "as an elevated Administrator, or as a member of the "
                "'Event Log Readers' local group -- a non-elevated interactive "
                "session (even one belonging to an administrator) is denied by "
                "the channel's access control list due to UAC token filtering."
            )

        if funcname:
            return f"{funcname} failed: {strerror}"
        return f"{op} failed: {strerror}"

    @staticmethod
    def _extract_record_id_from_xml(xml_str: str) -> Optional[int]:
        """Extract EventRecordID from rendered XML without full parse."""
        try:
            root = ET.fromstring(xml_str)
            for elem in root.iter():
                tag = elem.tag.split("}", 1)[1] if "}" in elem.tag else elem.tag
                if tag == "EventRecordID" and elem.text and elem.text.strip().isdigit():
                    return int(elem.text.strip())
        except Exception:
            pass
        return None

    def collect_channel_events(
        self, channel: str, max_events: Optional[int] = None
    ) -> Tuple[List[Dict[str, Any]], Optional[int]]:
        """
        Collect new events from a specific Windows Event Log channel.
        Returns a tuple of (events_list, highest_record_id_seen).
        """
        if not PYWIN32_AVAILABLE:
            raise RuntimeError("pywin32 is not installed or available on this system.")

        limit = max_events or self.batch_size
        last_rec_id = self.checkpoint_mgr.get(channel)

        # Build XPath query for only new events if checkpoint exists
        if last_rec_id is not None and last_rec_id > 0:
            query_xpath = f"*[System[(EventRecordID > {last_rec_id})]]"
        else:
            query_xpath = None

        collected_events: List[Dict[str, Any]] = []
        max_record_id = last_rec_id or 0

        try:
            if query_xpath:
                query_handle = win32evtlog.EvtQuery(
                    channel,
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
                    query_xpath,
                )
            else:
                query_handle = win32evtlog.EvtQuery(
                    channel,
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
                )

            handles = win32evtlog.EvtNext(query_handle, limit)
            if not handles:
                return [], max_record_id

            for handle in handles:
                try:
                    xml_str = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
                    rec_id = self._extract_record_id_from_xml(xml_str)
                    if rec_id is not None:
                        max_record_id = max(max_record_id, rec_id)

                    event_entry = {
                        "raw_xml": xml_str,
                        "channel": channel,
                        "record_id": rec_id,
                    }
                    collected_events.append(event_entry)
                except Exception as render_err:
                    self._logger.debug("Failed rendering single event in [%s]: %s", channel, render_err)
                    continue

            # Clear failure warning status on success
            if channel in self._failed_channel_warned:
                self._logger.info("Collector recovered access to channel [%s]", channel)
                self._failed_channel_warned.remove(channel)

        except Exception as e:
            # Channel failure isolation: do not crash HIDS
            if channel not in self._failed_channel_warned:
                self._logger.warning(
                    "Channel access failure on [%s]: %s",
                    channel,
                    self._describe_channel_error("EvtQuery/EvtNext", e),
                )
                self._failed_channel_warned.add(channel)
            return [], last_rec_id

        return collected_events, max_record_id

    def collect_all_events(
        self, max_events_per_channel: Optional[int] = None
    ) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
        """
        Poll all configured channels for new events in chronological order.
        Returns:
            (all_events, pending_checkpoints_dict)
        """
        all_events: List[Dict[str, Any]] = []
        pending_checkpoints: Dict[str, int] = {}

        for channel in self.channels:
            try:
                events, highest_rec_id = self.collect_channel_events(
                    channel, max_events=max_events_per_channel
                )
                if events:
                    all_events.extend(events)
                if highest_rec_id is not None:
                    pending_checkpoints[channel] = highest_rec_id
            except Exception as e:
                self._logger.error("Unexpected error in channel collector loop [%s]: %s", channel, e)
                continue

        return all_events, pending_checkpoints

    def commit_checkpoint(self, channel: str, record_id: int):
        """Commit a single channel checkpoint and persist to disk."""
        self.checkpoint_mgr.set(channel, record_id)
        self.checkpoint_mgr.save()

    def commit_checkpoints(self, checkpoints: Dict[str, int]):
        """Commit multiple channel checkpoints and persist to disk."""
        if not checkpoints:
            return
        for channel, rec_id in checkpoints.items():
            self.checkpoint_mgr.set(channel, rec_id)
        self.checkpoint_mgr.save()


def collect_system_events(max_events: int = 10) -> List[Dict[str, Any]]:
    """
    Backwards-compatible standalone collector function.
    """
    collector = WindowsEventCollector(channels=["System"], batch_size=max_events)
    events, _ = collector.collect_channel_events("System", max_events=max_events)
    return events
















# """
# HIDS Windows Event Collector.

# Collects real-time Windows Event logs using the native Windows Event Log API (pywin32)
# with persistent per-channel EventRecordID checkpointing, atomic state writes,
# failure isolation per channel, and graceful permission/error recovery.
# """

# import json
# import logging
# import os
# from pathlib import Path
# import tempfile
# import time
# from typing import Any, Dict, List, Optional, Set, Tuple
# import xml.etree.ElementTree as ET

# try:
#     import win32evtlog
#     import win32event
#     PYWIN32_AVAILABLE = True
# except ImportError:
#     PYWIN32_AVAILABLE = False


# # Default project root and runtime paths
# BASE_DIR = Path(__file__).resolve().parent.parent
# RUNTIME_DIR = BASE_DIR / "runtime"
# DEFAULT_CHECKPOINT_FILE = RUNTIME_DIR / "checkpoints.json"

# # Standard security channels to monitor
# DEFAULT_MONITORED_CHANNELS = [
#     "Security",
#     "System",
#     "Application",
#     "Microsoft-Windows-Windows Defender/Operational",
#     "Microsoft-Windows-PowerShell/Operational",
#     "Windows PowerShell",
# ]


# class EventCheckpointManager:
#     """
#     Manages persistent per-channel EventRecordID checkpoints.
#     Uses atomic writes to prevent corruption during power failure or service restart.
#     """

#     def __init__(self, checkpoint_path: Optional[Path] = None):
#         self.checkpoint_path = Path(checkpoint_path) if checkpoint_path else DEFAULT_CHECKPOINT_FILE
#         self.checkpoints: Dict[str, int] = {}
#         self._ensure_dir()
#         self.load()

#     def _ensure_dir(self):
#         """Ensure parent directory exists."""
#         try:
#             self.checkpoint_path.parent.mkdir(parents=True, exist_ok=True)
#         except Exception:
#             pass

#     def load(self) -> Dict[str, int]:
#         """Load checkpoints from disk."""
#         if not self.checkpoint_path.exists():
#             self.checkpoints = {}
#             return self.checkpoints

#         try:
#             with open(self.checkpoint_path, "r", encoding="utf-8") as f:
#                 content = f.read().strip()
#                 if not content:
#                     self.checkpoints = {}
#                     return self.checkpoints
#                 data = json.loads(content)
#                 if isinstance(data, dict):
#                     self.checkpoints = {
#                         str(k): int(v) for k, v in data.items() if str(v).isdigit() or isinstance(v, int)
#                     }
#                 else:
#                     self.checkpoints = {}
#         except Exception as e:
#             logging.getLogger("IDSIPS").warning(
#                 "Failed to load checkpoint file %s: %s. Reinitializing checkpoints.",
#                 self.checkpoint_path,
#                 e,
#             )
#             self.checkpoints = {}
#         return self.checkpoints

#     def get(self, channel: str) -> Optional[int]:
#         """Get the last processed EventRecordID for a channel."""
#         return self.checkpoints.get(channel)

#     def set(self, channel: str, record_id: int):
#         """Update in-memory checkpoint for a channel."""
#         if record_id is not None:
#             self.checkpoints[channel] = max(self.checkpoints.get(channel, 0), int(record_id))

#     def save(self):
#         """
#         Atomically write current checkpoints to disk.
#         """
#         self._ensure_dir()
#         temp_file = None
#         try:
#             with tempfile.NamedTemporaryFile(
#                 mode="w",
#                 encoding="utf-8",
#                 dir=str(self.checkpoint_path.parent),
#                 delete=False,
#             ) as f:
#                 temp_file = Path(f.name)
#                 json.dump(self.checkpoints, f, indent=2)
#                 f.flush()
#                 os.fsync(f.fileno())

#             # Atomic replace
#             temp_file.replace(self.checkpoint_path)
#         except Exception as e:
#             logging.getLogger("IDSIPS").error("Failed to atomically save checkpoint file: %s", e)
#             if temp_file and temp_file.exists():
#                 try:
#                     temp_file.unlink()
#                 except Exception:
#                     pass


# class WindowsEventCollector:
#     """
#     Production-grade Windows Event Log Collector.
#     Queries native Windows Event channels, renders XML, tracks checkpoints,
#     and isolates channel-specific failures.
#     """

#     def __init__(
#         self,
#         channels: Optional[List[str]] = None,
#         checkpoint_path: Optional[Path] = None,
#         batch_size: int = 100,
#     ):
#         self.channels = list(channels) if channels else list(DEFAULT_MONITORED_CHANNELS)
#         self.batch_size = batch_size
#         self.checkpoint_mgr = EventCheckpointManager(checkpoint_path)
#         self.disabled_channels: Set[str] = set()
#         self._failed_channel_warned: Set[str] = set()
#         self._logger = logging.getLogger("IDSIPS")

#         self._logger.info("Collector initialized for channels: %s", self.channels)

#         # Log loaded checkpoints
#         for ch, rec_id in self.checkpoint_mgr.checkpoints.items():
#             self._logger.info("Checkpoint loaded: [%s] -> RecordID %d", ch, rec_id)

#         # Initialize baselines for channels without prior checkpoints
#         self._initialize_unseen_channels()

#     def _initialize_unseen_channels(self):
#         """
#         For any channel that does not have an existing saved checkpoint,
#         query the latest event record ID as the baseline to avoid flooding
#         historical alerts on fresh start.
#         """
#         if not PYWIN32_AVAILABLE:
#             return

#         for channel in self.channels:
#             if self.checkpoint_mgr.get(channel) is not None:
#                 continue

#             try:
#                 query = win32evtlog.EvtQuery(
#                     channel,
#                     win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
#                 )
#                 events = win32evtlog.EvtNext(query, 1)
#                 if events:
#                     xml_str = win32evtlog.EvtRender(events[0], win32evtlog.EvtRenderEventXml)
#                     rec_id = self._extract_record_id_from_xml(xml_str)
#                     if rec_id is not None:
#                         self.checkpoint_mgr.set(channel, rec_id)
#                         self._logger.info(
#                             "Baseline checkpoint created for [%s] at RecordID %d",
#                             channel,
#                             rec_id,
#                         )
#                 else:
#                     # Channel exists but is currently empty
#                     self.checkpoint_mgr.set(channel, 0)
#                     self._logger.info("Baseline checkpoint initialized for empty channel [%s] at RecordID 0", channel)
#             except Exception as e:
#                 # If access denied or channel not found during init, record for runtime retry
#                 if channel not in self._failed_channel_warned:
#                     self._logger.warning(
#                         "Channel [%s] baseline initialization skipped: %s (Will retry during collection)",
#                         channel,
#                         e,
#                     )
#                     self._failed_channel_warned.add(channel)

#         self.checkpoint_mgr.save()

#     @staticmethod
#     def _extract_record_id_from_xml(xml_str: str) -> Optional[int]:
#         """Extract EventRecordID from rendered XML without full parse."""
#         try:
#             root = ET.fromstring(xml_str)
#             for elem in root.iter():
#                 tag = elem.tag.split("}", 1)[1] if "}" in elem.tag else elem.tag
#                 if tag == "EventRecordID" and elem.text and elem.text.strip().isdigit():
#                     return int(elem.text.strip())
#         except Exception:
#             pass
#         return None

#     def collect_channel_events(
#         self, channel: str, max_events: Optional[int] = None
#     ) -> Tuple[List[Dict[str, Any]], Optional[int]]:
#         """
#         Collect new events from a specific Windows Event Log channel.
#         Returns a tuple of (events_list, highest_record_id_seen).
#         """
#         if not PYWIN32_AVAILABLE:
#             raise RuntimeError("pywin32 is not installed or available on this system.")

#         limit = max_events or self.batch_size
#         last_rec_id = self.checkpoint_mgr.get(channel)

#         # Build XPath query for only new events if checkpoint exists
#         if last_rec_id is not None and last_rec_id > 0:
#             query_xpath = f"*[System[(EventRecordID > {last_rec_id})]]"
#         else:
#             query_xpath = None

#         collected_events: List[Dict[str, Any]] = []
#         max_record_id = last_rec_id or 0

#         try:
#             if query_xpath:
#                 query_handle = win32evtlog.EvtQuery(
#                     channel,
#                     win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
#                     query_xpath,
#                 )
#             else:
#                 query_handle = win32evtlog.EvtQuery(
#                     channel,
#                     win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryForwardDirection,
#                 )

#             handles = win32evtlog.EvtNext(query_handle, limit)
#             if not handles:
#                 return [], max_record_id

#             for handle in handles:
#                 try:
#                     xml_str = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
#                     rec_id = self._extract_record_id_from_xml(xml_str)
#                     if rec_id is not None:
#                         max_record_id = max(max_record_id, rec_id)

#                     event_entry = {
#                         "raw_xml": xml_str,
#                         "channel": channel,
#                         "record_id": rec_id,
#                     }
#                     collected_events.append(event_entry)
#                 except Exception as render_err:
#                     self._logger.debug("Failed rendering single event in [%s]: %s", channel, render_err)
#                     continue

#             # Clear failure warning status on success
#             if channel in self._failed_channel_warned:
#                 self._logger.info("Collector recovered access to channel [%s]", channel)
#                 self._failed_channel_warned.remove(channel)

#         except Exception as e:
#             # Channel failure isolation: do not crash HIDS
#             if channel not in self._failed_channel_warned:
#                 self._logger.warning("Channel access failure on [%s]: %s", channel, e)
#                 self._failed_channel_warned.add(channel)
#             return [], last_rec_id

#         return collected_events, max_record_id

#     def collect_all_events(
#         self, max_events_per_channel: Optional[int] = None
#     ) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
#         """
#         Poll all configured channels for new events in chronological order.
#         Returns:
#             (all_events, pending_checkpoints_dict)
#         """
#         all_events: List[Dict[str, Any]] = []
#         pending_checkpoints: Dict[str, int] = {}

#         for channel in self.channels:
#             try:
#                 events, highest_rec_id = self.collect_channel_events(
#                     channel, max_events=max_events_per_channel
#                 )
#                 if events:
#                     all_events.extend(events)
#                 if highest_rec_id is not None:
#                     pending_checkpoints[channel] = highest_rec_id
#             except Exception as e:
#                 self._logger.error("Unexpected error in channel collector loop [%s]: %s", channel, e)
#                 continue

#         return all_events, pending_checkpoints

#     def commit_checkpoint(self, channel: str, record_id: int):
#         """Commit a single channel checkpoint and persist to disk."""
#         self.checkpoint_mgr.set(channel, record_id)
#         self.checkpoint_mgr.save()

#     def commit_checkpoints(self, checkpoints: Dict[str, int]):
#         """Commit multiple channel checkpoints and persist to disk."""
#         if not checkpoints:
#             return
#         for channel, rec_id in checkpoints.items():
#             self.checkpoint_mgr.set(channel, rec_id)
#         self.checkpoint_mgr.save()


# def collect_system_events(max_events: int = 10) -> List[Dict[str, Any]]:
#     """
#     Backwards-compatible standalone collector function.
#     """
#     collector = WindowsEventCollector(channels=["System"], batch_size=max_events)
#     events, _ = collector.collect_channel_events("System", max_events=max_events)
#     return events