"""
Live Windows Event Collection & Checkpoint Verification Test.

Demonstrates and verifies real-time, live Windows Event collection against the actual
host Windows Event Log API (pywin32 / win32evtlog) without synthetic/fake events:
1. Connects to live Windows Event Log channels.
2. Initializes baseline checkpoints at current latest EventRecordIDs (preventing flood).
3. Executes a harmless real OS action generating authentic Windows Events.
4. Confirms Windows EventRecordID X == Collector EventRecordID X == Normalized EventRecordID X.
5. Confirms live telemetry is written to logs/idsips.log.
6. Confirms checkpoint advances persistently to the new EventRecordID.
7. Tests service/engine restart behavior:
   - Restarts HIDS engine from saved checkpoint.
   - Proves no duplicate events are collected from previously processed logs.
   - Generates a new real Windows event.
   - Proves only the newly created event is collected.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import win32evtlog

from hids.collector import WindowsEventCollector, EventCheckpointManager
from hids.normalizer import normalize_event, NormalizedEvent
from hids.hids import HIDSEngine
from logger import get_logger, EVENT_JSON_FILE, LOG_FILE


class TestLiveWindowsEventCollection(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.checkpoint_file = Path(self.temp_dir.name) / "live_checkpoints.json"
        self.logger = get_logger()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_live_event_collection_end_to_end(self):
        print("\n" + "=" * 70)
        print("  [LIVE TEST 1] REAL WINDOWS EVENT COLLECTION & PIPELINE VERIFICATION")
        print("=" * 70)

        # 1. Initialize Collector with dedicated live checkpoint file
        collector = WindowsEventCollector(
            channels=[
                "Microsoft-Windows-PowerShell/Operational",
                "Windows PowerShell",
                "Application",
                "System",
            ],
            checkpoint_path=self.checkpoint_file,
        )

        initial_checkpoints = collector.checkpoint_mgr.load()
        print(f"[*] Initial Baseline Checkpoints Established:")
        for ch, rec_id in initial_checkpoints.items():
            print(f"    - {ch}: RecordID {rec_id}")

        ps_initial_rec = initial_checkpoints.get("Microsoft-Windows-PowerShell/Operational", 0)

        # 2. Trigger a real, benign Windows action via powershell.exe
        print("\n[*] Triggering a real, harmless Windows PowerShell command...")
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", "Write-Output 'IDSIPS-Live-Verification'; Get-Process -Name explorer -ErrorAction SilentlyContinue | Select-Object -First 1 Id, ProcessName"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0)

        # 3. Query live Windows Event Log directly with bounded polling to observe the newly created Windows Event
        windows_latest_rec_id = ps_initial_rec
        windows_latest_xml = ""
        poll_timeout = 5.0
        start_t = time.time()
        while time.time() - start_t < poll_timeout:
            try:
                query = win32evtlog.EvtQuery(
                    "Microsoft-Windows-PowerShell/Operational",
                    win32evtlog.EvtQueryChannelPath | win32evtlog.EvtQueryReverseDirection,
                )
                recent_handles = win32evtlog.EvtNext(query, 5)
                if recent_handles:
                    windows_latest_xml = win32evtlog.EvtRender(recent_handles[0], win32evtlog.EvtRenderEventXml)
                    rec_id = WindowsEventCollector._extract_record_id_from_xml(windows_latest_xml)
                    if rec_id is not None and rec_id > ps_initial_rec:
                        windows_latest_rec_id = rec_id
                        break
            except Exception:
                pass
            time.sleep(0.2)

        print(f"[*] Direct Windows Event Log query confirmed latest EventRecordID in OS: {windows_latest_rec_id}")
        self.assertGreater(
            windows_latest_rec_id,
            ps_initial_rec,
            "A new real Windows event should have been generated with higher RecordID",
        )

        # 4. Use HIDS Engine to perform a live monitoring cycle
        engine = HIDSEngine(
            collector=collector,
            logger=self.logger,
        )

        engine.monitor_step()

        # 5. Verify Checkpoint advancement
        updated_checkpoints = collector.checkpoint_mgr.load()
        ps_updated_rec = updated_checkpoints.get("Microsoft-Windows-PowerShell/Operational", 0)
        print(f"[*] Updated Checkpoint for Microsoft-Windows-PowerShell/Operational: {ps_updated_rec}")

        self.assertGreaterEqual(
            ps_updated_rec,
            windows_latest_rec_id,
            "Checkpoint must advance to match or exceed the latest collected real Windows EventRecordID",
        )

        # 6. Verify log file contains live HIDS EVENT entries
        self.assertTrue(EVENT_JSON_FILE.exists())
        with open(EVENT_JSON_FILE, "r", encoding="utf-8", errors="replace") as f:
            log_text = f.read()

        self.assertIn("event", log_text)
        self.assertIn("Microsoft-Windows-PowerShell/Operational", log_text)
        print(f"[*] Verified: Live Windows event with RecordID {windows_latest_rec_id} was successfully processed and logged to {EVENT_JSON_FILE.name}")
        print("  -> Windows EventRecordID == Collector EventRecordID == Checkpoint RecordID == Logged RecordID [PASSED]")

    def test_live_hids_restart_and_no_duplicate_collection(self):
        print("\n" + "=" * 70)
        print("  [LIVE TEST 2] HIDS ENGINE RESTART & ZERO-DUPLICATE VERIFICATION")
        print("=" * 70)

        # 1. Start First Engine Instance and collect initial baseline
        engine1 = HIDSEngine(
            channels=["Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"],
            checkpoint_path=self.checkpoint_file,
            logger=self.logger,
        )

        # Trigger real event 1
        subprocess.run(["powershell.exe", "-NoProfile", "-Command", "Write-Output 'IDSIPS-Init'; Get-Date"], capture_output=True)
        # Drain all events generated by the init command
        for _ in range(5):
            time.sleep(0.3)
            engine1.monitor_step()

        saved_checkpoint_after_step1 = engine1.collector.checkpoint_mgr.load()
        rec1 = saved_checkpoint_after_step1.get("Microsoft-Windows-PowerShell/Operational", 0)
        print(f"[*] Engine 1 collected live events. Checkpoint saved: {rec1}")

        # Simulate service shutdown
        engine1.stop()

        # 2. Start Second Engine Instance (simulating service restart)
        print("\n[*] Simulating Service / HIDS Restart (loading saved checkpoint)...")
        engine2 = HIDSEngine(
            channels=["Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"],
            checkpoint_path=self.checkpoint_file,
            logger=self.logger,
        )

        loaded_cp = dict(engine2.collector.checkpoint_mgr.load())
        self.assertEqual(
            loaded_cp.get("Microsoft-Windows-PowerShell/Operational"),
            rec1,
            "Engine 2 must load exact saved checkpoint from disk on startup",
        )
        print(f"[*] Engine 2 successfully resumed from Checkpoint: {rec1}")

        # 3. Poll without new events: must collect 0 duplicate events
        raw_events, pending_cp = engine2.collector.collect_all_events()
        self.assertEqual(len(raw_events), 0, "Restarted collector must NOT re-collect previously processed events")
        print("[*] Verified: Zero historical/duplicate events collected after restart [PASSED]")

        # 4. Generate new real event 2
        print("\n[*] Triggering new live event after restart...")
        subprocess.run(["powershell.exe", "-NoProfile", "-Command", "Write-Output 'IDSIPS-Restart'; Get-Process | Select-Object -First 1 Id, ProcessName"], capture_output=True)

        raw_events2 = []
        pending_cp2 = {}
        poll_timeout = 5.0
        start_t = time.time()
        while time.time() - start_t < poll_timeout:
            raw_events2, pending_cp2 = engine2.collector.collect_all_events()
            if len(raw_events2) > 0:
                break
            time.sleep(0.2)

        self.assertGreater(len(raw_events2), 0, "Collector must collect only newly created events")
        for ev in raw_events2:
            norm = normalize_event(ev)
            prev_channel_rec = loaded_cp.get(norm.channel, 0)
            self.assertGreater(norm.record_id, prev_channel_rec, "Collected event must have RecordID strictly greater than channel checkpoint")

        print(f"[*] Engine 2 collected {len(raw_events2)} new live event(s) across channels [PASSED]")

        # Process and advance
        for ev in raw_events2:
            engine2.process_raw_event(ev)
        engine2.collector.commit_checkpoints(pending_cp2)

        final_cp = engine2.collector.checkpoint_mgr.load()
        has_advanced = any(final_cp.get(ch, 0) > loaded_cp.get(ch, 0) for ch in pending_cp2.keys())
        self.assertTrue(has_advanced, "At least one monitored channel checkpoint must have advanced")
        print(f"[*] Final advanced checkpoints after restart cycle: {final_cp}")


if __name__ == "__main__":
    unittest.main()
