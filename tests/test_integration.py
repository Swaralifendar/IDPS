import os
from pathlib import Path
import tempfile
import unittest

from hids.hids import HIDSEngine
from hids.severity import Severity
from logger import get_logger, LOG_FILE


class TestHIDSIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.checkpoint_file = Path(self.temp_dir.name) / "checkpoints.json"
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
            logger=self.logger
        )

        _, matches, corrs = engine.process_raw_event(sample_xml)
        self.assertEqual(len(matches), 1)
        match = matches[0]
        self.assertEqual(match.rule_id, "PROC-001")
        self.assertEqual(match.severity, Severity.HIGH)
        self.assertIn("Ransomware shadow copy deletion", match.details)

        # Verify log file exists and contains the alert line
        self.assertTrue(LOG_FILE.exists())
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            log_content = f.read()

        self.assertIn("HIDS ALERT", log_content)
        self.assertIn("PROC-001", log_content)
        self.assertIn("HIGH", log_content)
        self.assertIn("vssadmin.exe delete shadows", log_content)

    def test_end_to_end_brute_force_correlation_to_log_file(self):
        engine = HIDSEngine(
            checkpoint_path=self.checkpoint_file,
            logger=self.logger
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

        # Verify correlated alert logged to idsips.log
        with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
            log_content = f.read()

        self.assertIn("HIDS CORRELATION", log_content)
        self.assertIn("CORR-001", log_content)
        self.assertIn("CRITICAL", log_content)


if __name__ == "__main__":
    unittest.main()
