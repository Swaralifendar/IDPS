import json
import os
from pathlib import Path
import tempfile
import unittest

from hids.hids import HIDSEngine
from hids.severity import Severity
from logger import get_logger, EVENT_JSON_FILE


class TestHIDSIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.checkpoint_file = Path(self.temp_dir.name) / "checkpoints.json"
        self.json_log = Path(self.temp_dir.name) / "test_event.json"
        self.logger = get_logger()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_full_pipeline_raw_xml_to_log_file(self):
        # 1. Prepare raw Windows Security XML for ransomware shadow deletion
        sample_xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
            <System>
                <Provider Name='Microsoft-Windows-Security-Auditing'/>
                <EventID>4688</EventID>
                <Level>0</Level>
                <TimeCreated SystemTime='2026-08-25T10:00:00.000000Z'/>
                <EventRecordID>88888</EventRecordID>
                <Execution ProcessID='4400' ThreadID='1200'/>
                <Channel>Security</Channel>
                <Computer>FINANCE-SRV01</Computer>
            </System>
            <EventData>
                <Data Name='SubjectUserName'>svc_backup</Data>
                <Data Name='NewProcessName'>C:\\Windows\\System32\\vssadmin.exe</Data>
                <Data Name='CommandLine'>vssadmin.exe delete shadows /all /quiet</Data>
            </EventData>
        </Event>"""

        engine = HIDSEngine(
            checkpoint_path=self.checkpoint_file,
            logger=self.logger,
            json_log_path=self.json_log,
        )

        _, matches, corrs = engine.process_raw_event(sample_xml)
        self.assertEqual(len(matches), 1)
        match = matches[0]
        self.assertEqual(match.rule_id, "PROC-001")
        self.assertEqual(match.severity, Severity.HIGH)
        self.assertIn("Ransomware shadow copy deletion", match.details)

        # Verify event.json exists and contains both event and alert objects
        self.assertTrue(self.json_log.exists())
        with open(self.json_log, "r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]

        event_records = [r for r in records if r.get("type") == "event"]
        alert_records = [r for r in records if r.get("type") == "alert"]

        self.assertGreaterEqual(len(event_records), 1)
        self.assertGreaterEqual(len(alert_records), 1)

        alert = alert_records[0]
        self.assertEqual(alert["rule_id"], "PROC-001")
        self.assertEqual(alert["severity"], "HIGH")
        self.assertIn("Ransomware shadow copy deletion", alert["details"])
        self.assertIn("+05:30", alert["timestamp"])

    def test_end_to_end_brute_force_correlation_to_log_file(self):
        engine = HIDSEngine(
            checkpoint_path=self.checkpoint_file,
            logger=self.logger,
            json_log_path=self.json_log,
        )

        # Feed 3 failed logons
        for i in range(3):
            fail_event = {
                "Id": 4625,
                "Channel": "Security",
                "Computer": "FINANCE-SRV01",
                "TimeCreated": f"2026-08-25T11:0{i}:00.000000Z",
                "event_data": {"TargetUserName": "finance_admin", "IpAddress": "192.168.1.150"},
                "record_id": 9000 + i,
            }
            engine.process_raw_event(fail_event)

        # Feed 1 successful logon
        succ_event = {
            "Id": 4624,
            "Channel": "Security",
            "Computer": "FINANCE-SRV01",
            "TimeCreated": "2026-08-25T11:04:00.000000Z",
            "event_data": {"TargetUserName": "finance_admin", "IpAddress": "192.168.1.150"},
            "record_id": 9004,
        }
        _, _, corrs = engine.process_raw_event(succ_event)

        self.assertEqual(len(corrs), 1)
        self.assertEqual(corrs[0].correlation_id, "CORR-001")
        self.assertEqual(corrs[0].severity, Severity.CRITICAL)

        # Verify correlated alert logged to event.json
        with open(self.json_log, "r", encoding="utf-8") as f:
            records = [json.loads(line) for line in f if line.strip()]

        corr_records = [r for r in records if r.get("type") == "correlation"]
        self.assertEqual(len(corr_records), 1)
        self.assertEqual(corr_records[0]["correlation_id"], "CORR-001")
        self.assertEqual(corr_records[0]["severity"], "CRITICAL")
        self.assertIn("+05:30", corr_records[0]["timestamp"])


if __name__ == "__main__":
    unittest.main()
