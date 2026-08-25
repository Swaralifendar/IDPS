"""
HIDS Security Rule Engine & Allowlist.

Implements modular security rules mapped to MITRE ATT&CK techniques,
evaluating normalized Windows events with contextual detection, severity classification,
and auditable false-positive allowlist control.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Callable, Dict, List, Optional, Set, Union

from hids.normalizer import NormalizedEvent, normalize_event
from hids.severity import Severity


@dataclass
class RuleMatch:
    """
    Represents a detected security rule violation.
    """
    rule_id: str
    rule_name: str
    severity: Severity
    description: str
    mitre_attack: str
    event: NormalizedEvent
    details: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    suppressed: bool = False
    suppression_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert match to dictionary representation."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "description": self.description,
            "mitre_attack": self.mitre_attack,
            "details": self.details,
            "timestamp": self.timestamp,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "event": self.event.to_dict(),
        }


class AllowlistEngine:
    """
    Auditable False-Positive Suppression and Severity Downgrade Engine.
    Allows configuring trusted processes, services, users, and path patterns.
    """

    def __init__(
        self,
        trusted_users: Optional[Set[str]] = None,
        trusted_processes: Optional[Set[str]] = None,
        trusted_services: Optional[Set[str]] = None,
        downgrade_rules: Optional[Dict[str, Severity]] = None,
    ):
        self.trusted_users = {u.lower() for u in (trusted_users or [
            "nt authority\\system",
            "nt authority\\local service",
            "nt authority\\network service",
            "system",
            "local service",
            "network service",
        ])}
        self.trusted_processes = {p.lower() for p in (trusted_processes or [])}
        self.trusted_services = {s.lower() for s in (trusted_services or [])}
        self.downgrade_rules = downgrade_rules or {}

    def evaluate_allowlist(self, match: RuleMatch) -> RuleMatch:
        """
        Check match against allowlist and apply suppression or severity downgrade if matched.
        """
        event = match.event
        user_lower = (event.user or "").lower()
        process_lower = (event.process or "").lower()
        service_name = str(event.event_data.get("ServiceName", "")).lower()

        # Check trusted user for PRV-001 (sensitive privilege assignment for system services is normal)
        if match.rule_id == "PRV-001" and user_lower in self.trusted_users:
            match.suppressed = True
            match.suppression_reason = f"Suppressed: benign system account privilege assignment ({event.user})"
            match.severity = Severity.INFO
            return match

        # Check trusted processes
        for tp in self.trusted_processes:
            if tp in process_lower:
                match.suppressed = True
                match.suppression_reason = f"Suppressed: trusted process allowlist match ({tp})"
                match.severity = Severity.INFO
                return match

        # Check trusted services
        if service_name and service_name in self.trusted_services:
            match.suppressed = True
            match.suppression_reason = f"Suppressed: trusted service allowlist match ({service_name})"
            match.severity = Severity.INFO
            return match

        # Check rule downgrade rules
        if match.rule_id in self.downgrade_rules:
            new_sev = self.downgrade_rules[match.rule_id]
            match.suppression_reason = f"Downgraded from {match.severity.value} to {new_sev.value}"
            match.severity = new_sev

        return match


class SecurityRule:
    """
    Base definition for a modular security rule.
    """

    def __init__(
        self,
        rule_id: str,
        name: str,
        description: str,
        severity: Severity,
        mitre_attack: str,
        event_ids: Optional[List[int]] = None,
        channels: Optional[List[str]] = None,
    ):
        self.rule_id = rule_id
        self.name = name
        self.description = description
        self.severity = severity
        self.mitre_attack = mitre_attack
        self.event_ids = set(event_ids) if event_ids else set()
        self.channels = {c.lower() for c in channels} if channels else set()

    def applies_to(self, event: NormalizedEvent) -> bool:
        """Quick filter check before evaluating deep logic."""
        if self.event_ids and event.event_id not in self.event_ids:
            return False
        if self.channels and event.channel.lower() not in self.channels:
            return False
        return True

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        """Override in subclasses to perform specific detection logic."""
        raise NotImplementedError


# =========================================================================
# Specific Rule Implementations
# =========================================================================

class RuleFailedLogon(SecurityRule):
    """
    SEC-001: Detects single failed user logon attempts.
    Severity: LOW (repeated failed logons are elevated via Correlation Engine).
    """

    def __init__(self):
        super().__init__(
            rule_id="SEC-001",
            name="Failed User Logon",
            description="A user logon attempt failed (bad credentials, unknown user, or expired account).",
            severity=Severity.LOW,
            mitre_attack="T1078 - Valid Accounts / T1110.001 - Brute Force: Password Guessing",
            event_ids=[4625],
            channels=["Security"],
        )

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if not self.applies_to(event):
            return None

        user = event.user or "Unknown User"
        sub_status = event.event_data.get("SubStatus", "")
        status = event.event_data.get("Status", "")
        ip_addr = event.event_data.get("IpAddress", "")
        logon_type = event.event_data.get("LogonType", "")

        details = f"Logon failure for account '{user}'"
        if ip_addr and ip_addr != "-":
            details += f" from IP {ip_addr}"
        if logon_type and logon_type != "-":
            details += f" (LogonType: {logon_type})"
        if status or sub_status:
            details += f" [Status: {status}, SubStatus: {sub_status}]"

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=self.description,
            mitre_attack=self.mitre_attack,
            event=event,
            details=details,
        )


class RulePrivilegeAssignment(SecurityRule):
    """
    PRV-001: Detects assignment of sensitive administrator privileges upon logon.
    Severity: MEDIUM.
    """

    def __init__(self):
        super().__init__(
            rule_id="PRV-001",
            name="Sensitive Privilege Assigned to Logon",
            description="Special administrative privileges assigned to a new logon session.",
            severity=Severity.MEDIUM,
            mitre_attack="T1078.002 - Valid Accounts: Domain Accounts / T1068 - Privilege Escalation",
            event_ids=[4672],
            channels=["Security"],
        )

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if not self.applies_to(event):
            return None

        user = event.user or "Unknown User"
        priv_list = event.event_data.get("PrivilegeList", "")

        details = f"Special privileges assigned to user '{user}'"
        if priv_list:
            details += f" - Privileges: {priv_list[:120]}"

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=self.description,
            mitre_attack=self.mitre_attack,
            event=event,
            details=details,
        )


class RuleSecurityGroupModified(SecurityRule):
    """
    PRV-002: Detects user addition to privileged security groups (e.g. Administrators).
    Severity: HIGH.
    """

    def __init__(self):
        super().__init__(
            rule_id="PRV-002",
            name="Security Group Membership Modified",
            description="A member was added to a security-enabled local or global administrative group.",
            severity=Severity.HIGH,
            mitre_attack="T1098 - Account Manipulation / T1068 - Exploitation for Privilege Escalation",
            event_ids=[4728, 4732, 4756],
            channels=["Security"],
        )

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if not self.applies_to(event):
            return None

        member_name = event.event_data.get("MemberName") or event.event_data.get("MemberSid") or event.user
        group_name = event.event_data.get("TargetUserName") or event.event_data.get("GroupName") or "Security Group"

        details = f"Account '{member_name}' added to security group '{group_name}'"

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=self.description,
            mitre_attack=self.mitre_attack,
            event=event,
            details=details,
        )


class RuleUserAccountCreated(SecurityRule):
    """
    PRV-003: Detects creation of a new user account.
    Severity: MEDIUM.
    """

    def __init__(self):
        super().__init__(
            rule_id="PRV-003",
            name="New User Account Created",
            description="A new local or domain user account was created.",
            severity=Severity.MEDIUM,
            mitre_attack="T1136.001 - Create Account: Local Account",
            event_ids=[4720],
            channels=["Security"],
        )

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if not self.applies_to(event):
            return None

        target_user = event.event_data.get("TargetUserName") or event.user or "Unknown"
        creator_user = event.event_data.get("SubjectUserName") or "SYSTEM"

        details = f"New user account '{target_user}' created by '{creator_user}'"

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=self.description,
            mitre_attack=self.mitre_attack,
            event=event,
            details=details,
        )


class RuleSuspiciousProcess(SecurityRule):
    """
    PROC-001: Detects suspicious process creation or attack tool execution.
    Severity: HIGH.
    """

    SUSPICIOUS_PATTERNS = [
        (re.compile(r"vssadmin(\.exe)?\s+delete\s+shadows", re.IGNORECASE), "Ransomware shadow copy deletion"),
        (re.compile(r"wmic(\.exe)?\s+shadowcopy\s+delete", re.IGNORECASE), "Ransomware shadow copy deletion via WMIC"),
        (re.compile(r"wbadmin(\.exe)?\s+delete\s+catalog", re.IGNORECASE), "Backup catalog deletion"),
        (re.compile(r"certutil(\.exe)?\s+-(urlcache|decode|f\b)", re.IGNORECASE), "Certutil binary download or payload decode"),
        (re.compile(r"whoami(\.exe)?\s+/(priv|all|groups)", re.IGNORECASE), "Privilege enumeration via whoami"),
        (re.compile(r"nltest(\.exe)?\s+/(dclist|domain_trusts)", re.IGNORECASE), "Domain discovery via nltest"),
        (re.compile(r"mimikatz|sekurlsa|lsadump", re.IGNORECASE), "Credential dumping utility"),
        (re.compile(r"procdump(\.exe)?\s+.*lsass", re.IGNORECASE), "LSASS memory dump via procdump"),
        (re.compile(r"psexec(\.exe)?", re.IGNORECASE), "PsExec lateral movement tool"),
        (re.compile(r"regsvr32(\.exe)?\s+.*(scrobj\.dll|/s\s+/n\s+/u\s+/i)", re.IGNORECASE), "Regsvr32 Squiblydoo proxy execution"),
        (re.compile(r"rundll32(\.exe)?\s+.*(javascript|vbscript|url\.dll)", re.IGNORECASE), "Rundll32 script proxy execution"),
        (re.compile(r"net(\.exe)?\s+(user|localgroup\s+administrators)\s+.*(/add|/delete)", re.IGNORECASE), "Account modification via net.exe"),
        (re.compile(r"schtasks(\.exe)?\s+/create\s+.*(/sc\s+minute|/sc\s+onstart|/ru\s+system)", re.IGNORECASE), "Suspicious scheduled task creation"),
    ]

    def __init__(self):
        super().__init__(
            rule_id="PROC-001",
            name="Suspicious Process Execution",
            description="Execution of a recognized attack tool, recon command, or suspicious process creation.",
            severity=Severity.HIGH,
            mitre_attack="T1059 - Command and Scripting Interpreter / T1003 - OS Credential Dumping / T1070 - Indicator Removal",
            event_ids=[4688, 1],  # 4688: Windows Audit Process Creation, 1: Sysmon Process Creation
            channels=["Security", "Microsoft-Windows-Sysmon/Operational"],
        )

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if not self.applies_to(event):
            return None

        cmd_line = (
            event.event_data.get("CommandLine")
            or event.event_data.get("ProcessCommandLine")
            or event.process
            or event.message
        )

        if not cmd_line:
            return None

        for pattern, reason in self.SUSPICIOUS_PATTERNS:
            if pattern.search(cmd_line):
                details = f"Detected {reason} - Command: {cmd_line[:200]}"
                return RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=self.description,
                    mitre_attack=self.mitre_attack,
                    event=event,
                    details=details,
                )

        return None


class RuleServiceInstalled(SecurityRule):
    """
    SRV-001: Detects new Windows service installation.
    Severity: HIGH.
    """

    def __init__(self):
        super().__init__(
            rule_id="SRV-001",
            name="New Windows Service Installed",
            description="A new service was installed in the system (potential persistence or privilege escalation).",
            severity=Severity.HIGH,
            mitre_attack="T1543.003 - Create or Modify System Process: Windows Service",
            event_ids=[7045, 4697],
            channels=["System", "Security"],
        )

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if not self.applies_to(event):
            return None

        svc_name = event.event_data.get("ServiceName") or "Unknown"
        image_path = event.event_data.get("ImagePath") or event.process or "Unknown"
        svc_account = event.event_data.get("AccountName") or event.user or "LocalSystem"

        details = f"Service '{svc_name}' installed with binary '{image_path}' running as '{svc_account}'"

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=self.description,
            mitre_attack=self.mitre_attack,
            event=event,
            details=details,
        )


class RuleServiceTerminatedUnexpectedly(SecurityRule):
    """
    SRV-002: Detects unexpected termination or crash of Windows services.
    Severity: MEDIUM.
    """

    def __init__(self):
        super().__init__(
            rule_id="SRV-002",
            name="Service Terminated Unexpectedly",
            description="A Windows service crashed or terminated with an error.",
            severity=Severity.MEDIUM,
            mitre_attack="T1489 - Service Stop",
            event_ids=[7034, 7031, 7024],
            channels=["System"],
        )

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if not self.applies_to(event):
            return None

        svc_name = event.event_data.get("param1") or event.event_data.get("ServiceName") or event.process or "Service"
        details = f"Service '{svc_name}' terminated unexpectedly (Event ID {event.event_id})"

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=self.description,
            mitre_attack=self.mitre_attack,
            event=event,
            details=details,
        )


class RuleDefenderMalwareDetected(SecurityRule):
    """
    MAL-001: Detects Microsoft Defender malware detection events.
    Severity: CRITICAL.
    """

    def __init__(self):
        super().__init__(
            rule_id="MAL-001",
            name="Windows Defender Malware Detection",
            description="Microsoft Defender Antivirus detected malware or active threat on the host.",
            severity=Severity.CRITICAL,
            mitre_attack="T1204 - Malicious File/Payload Execution",
            event_ids=[1116, 1117, 1006, 1015],
            channels=["Microsoft-Windows-Windows Defender/Operational", "Application"],
        )

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if not self.applies_to(event):
            return None

        threat_name = (
            event.event_data.get("Threat Name")
            or event.event_data.get("param1")
            or event.event_data.get("ThreatName")
            or "Malware Threat"
        )
        path = event.event_data.get("Path") or event.event_data.get("param2") or event.process or "Unknown"

        details = f"Defender detected threat '{threat_name}' at path '{path}'"

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=self.description,
            mitre_attack=self.mitre_attack,
            event=event,
            details=details,
        )


class RuleDefenderProtectionDisabled(SecurityRule):
    """
    MAL-002: Detects disabling of Windows Defender real-time protection.
    Severity: CRITICAL.
    """

    def __init__(self):
        super().__init__(
            rule_id="MAL-002",
            name="Defender Real-Time Protection Disabled",
            description="Microsoft Defender real-time antivirus protection was turned off or tampered with.",
            severity=Severity.CRITICAL,
            mitre_attack="T1562.001 - Impair Defenses: Disable or Modify Tools",
            event_ids=[5001],
            channels=["Microsoft-Windows-Windows Defender/Operational", "Application"],
        )

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if not self.applies_to(event):
            return None

        details = "Microsoft Defender Real-Time Protection was disabled (Event ID 5001)"

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=self.description,
            mitre_attack=self.mitre_attack,
            event=event,
            details=details,
        )


class RuleSuspiciousPowerShell(SecurityRule):
    """
    PSH-001: Detects suspicious PowerShell script blocks or execution cradles.
    Severity: HIGH (only when suspicious content/context is actually present).
    """

    SUSPICIOUS_PS_PATTERNS = [
        (re.compile(r"DownloadString|DownloadFile|Net\.WebClient", re.IGNORECASE), "PowerShell download cradle"),
        (re.compile(r"Invoke-Expression|IEX\b", re.IGNORECASE), "PowerShell dynamic expression evaluation (IEX)"),
        (re.compile(r"-EncodedCommand|-enc\b|-e\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE), "Base64 encoded PowerShell command"),
        (re.compile(r"-ExecutionPolicy\s+(Bypass|Unrestricted)", re.IGNORECASE), "Execution policy bypass"),
        (re.compile(r"amsiInitFailed|AmsiUtils", re.IGNORECASE), "AMSI bypass attempt"),
        (re.compile(r"\[System\.Reflection\.Assembly\]::Load", re.IGNORECASE), "In-memory .NET assembly loading"),
        (re.compile(r"MiniDumpWriteDump", re.IGNORECASE), "LSASS memory dumping call in PowerShell"),
    ]

    def __init__(self):
        super().__init__(
            rule_id="PSH-001",
            name="Suspicious PowerShell Activity",
            description="PowerShell execution containing download cradles, encoding, or AMSI bypass indicators.",
            severity=Severity.HIGH,
            mitre_attack="T1059.001 - Command and Scripting Interpreter: PowerShell",
            event_ids=[4104, 4103, 400, 600],
            channels=["Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"],
        )

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if not self.applies_to(event):
            return None

        script_text = (
            event.event_data.get("ScriptBlockText")
            or event.event_data.get("param1")
            or event.event_data.get("CommandLine")
            or event.message
            or ""
        )

        if not script_text:
            return None

        for pattern, reason in self.SUSPICIOUS_PS_PATTERNS:
            if pattern.search(script_text):
                details = f"Detected {reason} - Script snippet: {script_text[:180]}"
                return RuleMatch(
                    rule_id=self.rule_id,
                    rule_name=self.name,
                    severity=self.severity,
                    description=self.description,
                    mitre_attack=self.mitre_attack,
                    event=event,
                    details=details,
                )

        return None


class RuleEventLogCleared(SecurityRule):
    """
    LOG-001: Detects clearing of Windows Event Logs.
    Severity: CRITICAL.
    """

    def __init__(self):
        super().__init__(
            rule_id="LOG-001",
            name="Windows Event Log Cleared",
            description="The Windows audit or system event log was deliberately cleared (defense evasion).",
            severity=Severity.CRITICAL,
            mitre_attack="T1070.001 - Indicator Removal on Host: Clear Windows Event Logs",
            event_ids=[1102, 104],
            channels=["Security", "System"],
        )

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        if not self.applies_to(event):
            return None

        cleared_by = event.user or "Unknown User"
        details = f"Windows Event Log was cleared by '{cleared_by}' (Event ID {event.event_id})"

        return RuleMatch(
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            description=self.description,
            mitre_attack=self.mitre_attack,
            event=event,
            details=details,
        )


# =========================================================================
# Rule Engine Manager
# =========================================================================

class RuleEngine:
    """
    Orchestrates security rule indexing, event evaluation, and allowlist processing.
    """

    def __init__(
        self,
        rules: Optional[List[SecurityRule]] = None,
        allowlist_engine: Optional[AllowlistEngine] = None,
    ):
        self.allowlist_engine = allowlist_engine or AllowlistEngine()
        self.rules: List[SecurityRule] = rules if rules is not None else self._default_rules()
        self._index_rules()

    def _default_rules(self) -> List[SecurityRule]:
        return [
            RuleFailedLogon(),
            RulePrivilegeAssignment(),
            RuleSecurityGroupModified(),
            RuleUserAccountCreated(),
            RuleSuspiciousProcess(),
            RuleServiceInstalled(),
            RuleServiceTerminatedUnexpectedly(),
            RuleDefenderMalwareDetected(),
            RuleDefenderProtectionDisabled(),
            RuleSuspiciousPowerShell(),
            RuleEventLogCleared(),
        ]

    def _index_rules(self):
        """Index rules by event ID for rapid lookups."""
        self.by_event_id: Dict[int, List[SecurityRule]] = {}
        self.wildcard_rules: List[SecurityRule] = []

        for r in self.rules:
            if r.event_ids:
                for eid in r.event_ids:
                    self.by_event_id.setdefault(eid, []).append(r)
            else:
                self.wildcard_rules.append(r)

    def evaluate(self, event: Union[Dict[str, Any], NormalizedEvent, str]) -> List[RuleMatch]:
        """
        Evaluate a single event against all matching security rules and apply allowlist filters.
        Returns a list of RuleMatch objects.
        """
        norm_event = normalize_event(event)
        matches: List[RuleMatch] = []

        # Find candidate rules
        candidate_rules = list(self.by_event_id.get(norm_event.event_id, []))
        candidate_rules.extend(self.wildcard_rules)

        for rule in candidate_rules:
            try:
                match = rule.evaluate(norm_event)
                if match:
                    # Apply allowlist
                    match = self.allowlist_engine.evaluate_allowlist(match)
                    matches.append(match)
            except Exception:
                continue

        return matches


# Backwards compatibility helper
_DEFAULT_ENGINE = None

def check_event(event: Any) -> str:
    """
    Backwards-compatible check_event function for IDPS prototype.
    Returns 'ALERT' if any unsuppressed high/critical/medium rule matched, else 'NORMAL'.
    """
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None:
        _DEFAULT_ENGINE = RuleEngine()

    matches = _DEFAULT_ENGINE.evaluate(event)
    for m in matches:
        if not m.suppressed and m.severity >= Severity.MEDIUM:
            return "ALERT"
    return "NORMAL"