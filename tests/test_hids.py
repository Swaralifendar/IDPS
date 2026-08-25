import logging
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from hids.hids import HIDSEngine, AlertDeduplicator, run_hids
from hids.collector import WindowsEventCollector
from hids.normalizer import NormalizedEvent
from hids.severity import Severity


class TestHIDS(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.checkpoint_file = Path(self.temp_dir.name) / "checkpoints.json"
        self.logger = logging.getLogger("TestIDSIPS")
        self.logger.setLevel(logging.DEBUG)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_alert_deduplicator(self):
        dedup = AlertDeduplicator(ttl_seconds=10.0, max_entries=5)
        fp = "SEC-001:Security:4625:1001:user1"

        self.assertFalse(dedup.is_duplicate(fp, now_ts=100.0))
        dedup.record(fp, now_ts=100.0)
        self.assertTrue(dedup.is_duplicate(fp, now_ts=105.0))

        # After TTL
        self.assertFalse(dedup.is_duplicate(fp, now_ts=115.0))

    def test_process_raw_event_pipeline(self):
        engine = HIDSEngine(
            checkpoint_path=self.checkpoint_file,
            logger=self.logger
        )

        sample_event = {
            "Id": 1116,
            "Channel": "Microsoft-Windows-Windows Defender/Operational",
            "ProviderName": "Microsoft-Windows-Windows Defender",
            "event_data": {"Threat Name": "Trojan:Win32/Emotet"},
            "record_id": 5001,
        }

        norm, matches, corrs = engine.process_raw_event(sample_event)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "MAL-001")
        self.assertEqual(matches[0].severity, Severity.CRITICAL)

        # Immediate duplicate should be deduplicated
        _, matches2, _ = engine.process_raw_event(sample_event)
        self.assertEqual(len(matches2), 1)
        # Deduplicator recorded it, so duplicate alert logging was suppressed

    def test_malformed_event_resilience(self):
        engine = HIDSEngine(
            checkpoint_path=self.checkpoint_file,
            logger=self.logger
        )

        # Malformed event should not raise exception
        norm1, matches, corrs = engine.process_raw_event(None)
        self.assertIsNotNone(norm1)
        self.assertEqual(len(matches), 0)

        norm2, matches2, corrs2 = engine.process_raw_event("<<< Not valid XML >>>")
        self.assertIsNotNone(norm2)
        self.assertEqual(len(matches2), 0)

    def test_graceful_shutdown_threading_event(self):
        engine = HIDSEngine(
            checkpoint_path=self.checkpoint_file,
            poll_interval=0.1,
            logger=self.logger
        )

        stop_evt = threading.Event()

        # Start HIDS in background thread
        t = threading.Thread(target=engine.run, args=(stop_evt,))
        t.start()

        time.sleep(0.2)
        self.assertTrue(engine._running)

        # Signal stop
        stop_evt.set()
        t.join(timeout=3.0)

        self.assertFalse(t.is_alive())
        self.assertFalse(engine._running)

    def test_monitor_step_checkpoint_advance(self):
        mock_collector = MagicMock()
        mock_collector.collect_all_events.return_value = (
            [
                {
                    "Id": 4625,
                    "Channel": "Security",
                    "record_id": 999,
                    "event_data": {"TargetUserName": "admin"}
                }
            ],
            {"Security": 999}
        )

        engine = HIDSEngine(
            collector=mock_collector,
            logger=self.logger
        )

        engine.monitor_step()

        mock_collector.commit_checkpoints.assert_called_once_with({"Security": 999})


if __name__ == "__main__":
    unittest.main()
