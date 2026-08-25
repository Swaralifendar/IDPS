import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from hids.collector import (
    EventCheckpointManager,
    WindowsEventCollector,
    DEFAULT_MONITORED_CHANNELS,
)


class TestCollector(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.checkpoint_file = Path(self.temp_dir.name) / "test_checkpoints.json"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_checkpoint_manager_load_save_atomic(self):
        mgr = EventCheckpointManager(self.checkpoint_file)
        self.assertEqual(mgr.checkpoints, {})

        mgr.set("Security", 100)
        mgr.set("System", 250)
        mgr.save()

        self.assertTrue(self.checkpoint_file.exists())

        # Create new manager pointing to same file
        mgr2 = EventCheckpointManager(self.checkpoint_file)
        self.assertEqual(mgr2.get("Security"), 100)
        self.assertEqual(mgr2.get("System"), 250)
        self.assertIsNone(mgr2.get("Application"))

        # Updating with lower number shouldn't regress
        mgr2.set("Security", 50)
        self.assertEqual(mgr2.get("Security"), 100)

        # Updating with higher number works
        mgr2.set("Security", 150)
        self.assertEqual(mgr2.get("Security"), 150)
        mgr2.save()

        mgr3 = EventCheckpointManager(self.checkpoint_file)
        self.assertEqual(mgr3.get("Security"), 150)

    def test_checkpoint_corruption_recovery(self):
        # Write corrupted JSON
        with open(self.checkpoint_file, "w", encoding="utf-8") as f:
            f.write("{ INVALID JSON CONTENT ...")

        mgr = EventCheckpointManager(self.checkpoint_file)
        self.assertEqual(mgr.checkpoints, {})
        mgr.set("System", 500)
        mgr.save()

        mgr2 = EventCheckpointManager(self.checkpoint_file)
        self.assertEqual(mgr2.get("System"), 500)

    def test_extract_record_id(self):
        xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
            <System>
                <EventRecordID>12345</EventRecordID>
            </System>
        </Event>"""
        rec_id = WindowsEventCollector._extract_record_id_from_xml(xml)
        self.assertEqual(rec_id, 12345)

        invalid_xml = "<Event><System><EventRecordID>abc</EventRecordID></System></Event>"
        self.assertIsNone(WindowsEventCollector._extract_record_id_from_xml(invalid_xml))

    @patch("hids.collector.win32evtlog")
    def test_collect_channel_with_checkpoint_xpath(self, mock_evtlog):
        # Mocking win32evtlog
        mock_handle = MagicMock()
        mock_evtlog.EvtQuery.return_value = mock_handle
        mock_evtlog.EvtNext.return_value = ["event_ptr1"]
        mock_evtlog.EvtRender.return_value = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
            <System><EventRecordID>105</EventRecordID><EventID>4625</EventID></System>
        </Event>"""

        mgr = EventCheckpointManager(self.checkpoint_file)
        mgr.set("Security", 100)
        mgr.save()

        collector = WindowsEventCollector(
            channels=["Security"],
            checkpoint_path=self.checkpoint_file
        )

        events, highest_id = collector.collect_channel_events("Security")

        self.assertEqual(len(events), 1)
        self.assertEqual(highest_id, 105)
        # Verify XPath query included record ID > 100
        mock_evtlog.EvtQuery.assert_called_with(
            "Security",
            mock_evtlog.EvtQueryChannelPath | mock_evtlog.EvtQueryForwardDirection,
            "*[System[(EventRecordID > 100)]]"
        )

    def test_channel_error_isolation(self):
        with patch("hids.collector.win32evtlog") as mock_evtlog:
            # First call for Security raises Access Denied, second for System succeeds
            def query_side_effect(channel, flags, *args):
                if channel == "Security":
                    raise PermissionError("Access is denied.")
                return MagicMock()

            mock_evtlog.EvtQuery.side_effect = query_side_effect
            mock_evtlog.EvtNext.return_value = []

            collector = WindowsEventCollector(
                channels=["Security", "System"],
                checkpoint_path=self.checkpoint_file
            )

            # Security fails silently/warns, System succeeds without throwing
            events, checkpoints = collector.collect_all_events()
            self.assertIsInstance(events, list)


if __name__ == "__main__":
    unittest.main()
