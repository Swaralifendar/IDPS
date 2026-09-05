import unittest
from datetime import datetime, timezone
from hids.normalizer import normalize_event, parse_iso_timestamp, NormalizedEvent


class TestNormalizer(unittest.TestCase):
    def test_xml_event_normalization(self):
        sample_xml = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
            <System>
                <Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/>
                <EventID>4625</EventID>
                <Version>0</Version>
                <Level>0</Level>
                <Task>12544</Task>
                <Opcode>0</Opcode>
                <Keywords>0x8010000000000000</Keywords>
                <TimeCreated SystemTime='2026-08-25T06:04:44.9371196Z'/>
                <EventRecordID>987654</EventRecordID>
                <Execution ProcessID='712' ThreadID='1024'/>
                <Channel>Security</Channel>
                <Computer>CORP-SERVER01</Computer>
            </System>
            <EventData>
                <Data Name='TargetUserName'>evil_user</Data>
                <Data Name='TargetDomainName'>CORP</Data>
                <Data Name='Status'>0xC000006D</Data>
                <Data Name='SubStatus'>0xC000006A</Data>
                <Data Name='ProcessName'>C:\\Windows\\System32\\svchost.exe</Data>
            </EventData>
        </Event>"""

        norm = normalize_event(sample_xml)
        self.assertIsInstance(norm, NormalizedEvent)
        self.assertEqual(norm.event_id, 4625)
        self.assertEqual(norm.provider, "Microsoft-Windows-Security-Auditing")
        self.assertEqual(norm.channel, "Security")
        self.assertEqual(norm.computer, "CORP-SERVER01")
        self.assertEqual(norm.record_id, 987654)
        self.assertEqual(norm.user, "CORP\\evil_user")
        self.assertEqual(norm.process, "C:\\Windows\\System32\\svchost.exe")
        self.assertEqual(norm.process_id, 712)
        self.assertEqual(norm.thread_id, 1024)
        self.assertIsNotNone(norm.timestamp_dt)
        self.assertEqual(norm.timestamp_dt.tzinfo, timezone.utc)
        self.assertEqual(norm.timestamp_dt.year, 2026)
        self.assertEqual(norm.event_data["Status"], "0xC000006D")
        self.assertEqual(norm.raw_data, sample_xml)

    def test_dict_event_normalization(self):
        prototype_dict = {
            "Id": 7045,
            "ProviderName": "Service Control Manager",
            "LevelDisplayName": "Information",
            "TimeCreated": "2026-08-25T07:15:00.000000Z",
            "Message": "A service was installed in the system.",
            "event_data": {
                "ServiceName": "BackdoorSvc",
                "ImagePath": "C:\\Windows\\Temp\\nc.exe -L -p 4444",
            }
        }

        norm = normalize_event(prototype_dict)
        self.assertEqual(norm.event_id, 7045)
        self.assertEqual(norm.provider, "Service Control Manager")
        self.assertEqual(norm.process, "C:\\Windows\\Temp\\nc.exe -L -p 4444")
        self.assertEqual(norm.message, "A service was installed in the system.")
        self.assertEqual(norm["event_id"], 7045)
        self.assertEqual(norm.get("ServiceName"), "BackdoorSvc")

    def test_timestamp_parsing_variations(self):
        dt1 = parse_iso_timestamp("2026-08-25T06:04:44.9371196Z")
        self.assertEqual(dt1.tzinfo, timezone.utc)
        self.assertEqual(dt1.second, 44)

        dt2 = parse_iso_timestamp("2026-08-25 12:30:00")
        self.assertEqual(dt2.tzinfo, timezone.utc)
        self.assertEqual(dt2.hour, 12)

        dt3 = parse_iso_timestamp(None)
        self.assertEqual(dt3.tzinfo, timezone.utc)

    def test_missing_fields_resilience(self):
        # Case B: Structurally usable events with missing fields return NormalizedEvent with safe defaults
        norm1 = normalize_event({})
        self.assertIsNotNone(norm1)
        self.assertEqual(norm1.event_id, 0)
        self.assertEqual(norm1.user, "")
        self.assertIsNotNone(norm1.timestamp_dt)

        norm2 = normalize_event({"Channel": "System"})
        self.assertIsNotNone(norm2)
        self.assertEqual(norm2.event_id, 0)
        self.assertEqual(norm2.channel, "System")

        # Case A: Completely invalid inputs return None
        self.assertIsNone(normalize_event(None))
        self.assertIsNone(normalize_event("<Invalid XML><<<<"))
        self.assertIsNone(normalize_event(12345))

    def test_to_dict_and_access(self):
        norm = normalize_event({
            "event_id": 1116,
            "provider": "Microsoft-Windows-Windows Defender",
            "channel": "Microsoft-Windows-Windows Defender/Operational",
            "event_data": {"Threat Name": "Trojan:Win32/Mimikatz.A"}
        })
        d = norm.to_dict()
        self.assertEqual(d["event_id"], 1116)
        self.assertEqual(d["event_data"]["Threat Name"], "Trojan:Win32/Mimikatz.A")
        self.assertIn("timestamp_dt", d)


if __name__ == "__main__":
    unittest.main()
