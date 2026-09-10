"""
HIDS Security Rule Engine & Evaluation Architecture.

Interprets parsed HIDS rules, checks normalized events against rule channels,
event IDs, and condition evaluators, decorates detections with decoupled rule metadata,
and applies allowlist suppression / severity downgrade rules.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from hids.normalizer import NormalizedEvent, normalize_event
from hids.rule_metadata import RuleMetadata, get_rule_metadata, RULE_METADATA_REGISTRY
from hids.rules_parser import Rule, RuleParser
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
    category_type: List[str]
    attack_type: str
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
            "category_type": self.category_type,
            "attack_type": self.attack_type,
            "details": self.details,
            "timestamp": self.timestamp,
            "suppressed": self.suppressed,
            "suppression_reason": self.suppression_reason,
            "event": self.event.to_dict() if self.event else {},
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
        if not event:
            return match

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


class RuleEngine:
    """
    Interprets and evaluates parsed HIDS rules against normalized Windows events.
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

    SUSPICIOUS_PS_PATTERNS = [
        (re.compile(r"DownloadString|DownloadFile|Net\.WebClient", re.IGNORECASE), "PowerShell download cradle"),
        (re.compile(r"Invoke-Expression|IEX\b", re.IGNORECASE), "PowerShell dynamic expression evaluation (IEX)"),
        (re.compile(r"-EncodedCommand|-enc\b|-e\s+[A-Za-z0-9+/=]{20,}", re.IGNORECASE), "Base64 encoded PowerShell command"),
        (re.compile(r"-ExecutionPolicy\s+(Bypass|Unrestricted)", re.IGNORECASE), "Execution policy bypass"),
        (re.compile(r"amsiInitFailed|AmsiUtils", re.IGNORECASE), "AMSI bypass attempt"),
        (re.compile(r"\[System\.Reflection\.Assembly\]::Load", re.IGNORECASE), "In-memory .NET assembly loading"),
        (re.compile(r"MiniDumpWriteDump", re.IGNORECASE), "LSASS memory dumping call in PowerShell"),
    ]

    def __init__(
        self,
        rules: Optional[List[Rule]] = None,
        allowlist_engine: Optional[AllowlistEngine] = None,
        rules_file: Optional[Union[str, Path]] = None,
    ):
        self.allowlist_engine = allowlist_engine or AllowlistEngine()
        if rules is not None:
            self.rules = rules
        else:
            parser = RuleParser(rules_file=rules_file)
            self.rules = parser.parse()

        self._index_rules()

    def _index_rules(self):
        """Index rules by Event ID for fast candidate lookup."""
        self.by_event_id: Dict[int, List[Rule]] = {}
        self.wildcard_rules: List[Rule] = []

        for r in self.rules:
            if r.event_ids:
                for eid in r.event_ids:
                    self.by_event_id.setdefault(eid, []).append(r)
            else:
                self.wildcard_rules.append(r)

    def evaluate_condition(
        self,
        condition: str,
        event: NormalizedEvent,
        rule: Rule,
    ) -> Tuple[bool, Optional[str]]:
        """
        Evaluate named rule condition against the normalized event.
        Returns (is_matched, optional_reason_or_details).
        """
        cond = condition.strip().lower()

        if cond == "any":
            return True, None

        if cond == "suspicious_process":
            cmd_line = (
                event.event_data.get("CommandLine")
                or event.event_data.get("ProcessCommandLine")
                or event.process
                or event.message
            )
            if not cmd_line:
                return False, None

            for pattern, reason in self.SUSPICIOUS_PATTERNS:
                if pattern.search(cmd_line):
                    return True, f"Detected {reason} - Command: {cmd_line[:200]}"
            return False, None

        if cond == "suspicious_powershell":
            script_text = (
                event.event_data.get("ScriptBlockText")
                or event.event_data.get("param1")
                or event.event_data.get("CommandLine")
                or event.message
                or ""
            )
            if not script_text:
                return False, None

            for pattern, reason in self.SUSPICIOUS_PS_PATTERNS:
                if pattern.search(script_text):
                    return True, f"Detected {reason} - Script snippet: {script_text[:180]}"
            return False, None

        if cond in ("rdp_logon", "remote_interactive_logon"):
            logon_type = str(event.event_data.get("LogonType", ""))
            if logon_type == "10":
                return True, None
            return False, None

        # Fallback for unrecognized condition: treat as match
        return True, None

    def generate_details(
        self,
        rule: Rule,
        event: NormalizedEvent,
        condition_reason: Optional[str] = None,
    ) -> str:
        """
        Generate rich contextual alert details based on rule ID and event fields.
        """
        if condition_reason:
            return condition_reason

        rule_id = rule.rule_id.upper()

        if rule_id == "SEC-001":
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
            return details

        if rule_id == "PRV-001":
            user = event.user or "Unknown User"
            priv_list = event.event_data.get("PrivilegeList", "")
            details = f"Special privileges assigned to user '{user}'"
            if priv_list:
                details += f" - Privileges: {priv_list[:120]}"
            return details

        if rule_id == "PRV-002":
            member_name = event.event_data.get("MemberName") or event.event_data.get("MemberSid") or event.user
            group_name = event.event_data.get("TargetUserName") or event.event_data.get("GroupName") or "Security Group"
            return f"Account '{member_name}' added to security group '{group_name}'"

        if rule_id == "PRV-003":
            target_user = event.event_data.get("TargetUserName") or event.user or "Unknown"
            creator_user = event.event_data.get("SubjectUserName") or "SYSTEM"
            return f"New user account '{target_user}' created by '{creator_user}'"

        if rule_id == "SRV-001":
            svc_name = event.event_data.get("ServiceName") or "Unknown"
            image_path = event.event_data.get("ImagePath") or event.process or "Unknown"
            svc_account = event.event_data.get("AccountName") or event.user or "LocalSystem"
            return f"Service '{svc_name}' installed with binary '{image_path}' running as '{svc_account}'"

        if rule_id == "SRV-002":
            svc_name = event.event_data.get("param1") or event.event_data.get("ServiceName") or event.process or "Service"
            return f"Service '{svc_name}' terminated unexpectedly (Event ID {event.event_id})"

        if rule_id == "MAL-001":
            threat_name = (
                event.event_data.get("Threat Name")
                or event.event_data.get("param1")
                or event.event_data.get("ThreatName")
                or "Malware Threat"
            )
            path = event.event_data.get("Path") or event.event_data.get("param2") or event.process or "Unknown"
            return f"Defender detected threat '{threat_name}' at path '{path}'"

        if rule_id == "MAL-002":
            return f"Microsoft Defender Real-Time Protection was disabled (Event ID {event.event_id})"

        if rule_id == "MAL-003":
            details = f"Windows Defender configuration/exclusion change detected (EventID {event.event_id})"
            new_val = event.event_data.get("New Value", "")
            if new_val:
                details += f" | New Value: {new_val}"
            return details

        if rule_id == "LOG-001":
            cleared_by = event.user or "Unknown User"
            return f"Windows Event Log was cleared by '{cleared_by}' (Event ID {event.event_id})"

        if rule_id == "ACC-001":
            target_user = event.event_data.get("TargetUserName", event.user or "Unknown User")
            caller_computer = event.event_data.get("TargetDomainName", "")
            details = f"Account '{target_user}' was locked out"
            if caller_computer:
                details += f" (Domain: {caller_computer})"
            return details

        if rule_id == "ACC-002":
            target_user = event.event_data.get("TargetUserName", "Unknown User")
            return f"Account '{target_user}' was enabled by '{event.user or 'Unknown'}'"

        if rule_id == "ACC-003":
            target_user = event.event_data.get("TargetUserName", "Unknown User")
            return f"Account '{target_user}' was disabled by '{event.user or 'Unknown'}'"

        if rule_id == "ACC-004":
            target_user = event.event_data.get("TargetUserName", "Unknown User")
            return f"Password reset attempted for '{target_user}' by '{event.user or 'Unknown'}'"

        if rule_id == "AUTH-001":
            target_user = event.event_data.get("TargetUserName", "Unknown User")
            target_server = event.event_data.get("TargetServerName", "")
            caller_process = event.event_data.get("ProcessName", event.process or "")
            details = f"Explicit credentials for '{target_user}' used by process '{caller_process}'"
            if target_server:
                details += f" targeting '{target_server}'"
            return details

        if rule_id == "LOGON-001":
            user = event.user or event.event_data.get("TargetUserName", "Unknown User")
            ip_addr = event.event_data.get("IpAddress", "")
            details = f"RDP logon by '{user}'"
            if ip_addr and ip_addr != "-":
                details += f" from {ip_addr}"
            return details

        if rule_id == "SCHD-001":
            task_name = event.event_data.get("TaskName", "Unknown Task")
            return f"Scheduled task '{task_name}' created by '{event.user or 'Unknown'}'"

        if rule_id == "AUDIT-001":
            subcategory = event.event_data.get("SubcategoryGuid", event.event_data.get("Subcategory", "Unknown"))
            return f"Audit policy for '{subcategory}' changed by '{event.user or 'Unknown'}'"

        if rule_id == "FW-001":
            rule_name = event.event_data.get("RuleName", event.event_data.get("Name", "Unknown Rule"))
            return f"Firewall rule '{rule_name}' added/modified (EventID {event.event_id})"

        return f"Rule {rule.rule_id} triggered by Event ID {event.event_id} on channel {event.channel}"

    def create_match(
        self,
        rule: Rule,
        event: NormalizedEvent,
        condition_reason: Optional[str] = None,
    ) -> RuleMatch:
        """
        Create and populate a RuleMatch object with metadata from rule_metadata registry.
        """
        meta = get_rule_metadata(rule.rule_id)
        details = self.generate_details(rule, event, condition_reason)

        match = RuleMatch(
            rule_id=rule.rule_id,
            rule_name=meta.name,
            severity=meta.severity,
            description=meta.description,
            mitre_attack=meta.mitre_attack,
            category_type=meta.category_type,
            attack_type=meta.attack_type,
            event=event,
            details=details,
        )

        # Apply allowlist engine (suppression & severity downgrade)
        return self.allowlist_engine.evaluate_allowlist(match)

    def evaluate(self, event: Union[Dict[str, Any], NormalizedEvent, str]) -> List[RuleMatch]:
        """
        Evaluate an incoming raw or normalized event against indexed HIDS rules.
        """
        norm_event = normalize_event(event)
        if norm_event is None:
            return []

        matches: List[RuleMatch] = []

        # Candidate rules matching Event ID
        candidate_rules = list(self.by_event_id.get(norm_event.event_id, []))
        candidate_rules.extend(self.wildcard_rules)

        event_channel_lower = (norm_event.channel or "").lower()

        for rule in candidate_rules:
            if not rule.enabled:
                continue

            # Channel matching (case-insensitive)
            if rule.channels and event_channel_lower not in rule.channels_lower:
                continue

            # Event ID matching
            if rule.event_ids and norm_event.event_id not in rule.event_ids:
                continue

            # Condition evaluation
            matched, reason = self.evaluate_condition(rule.condition, norm_event, rule)
            if matched:
                match = self.create_match(rule, norm_event, reason)
                matches.append(match)

        return matches


# Backwards compatibility helper
_DEFAULT_ENGINE: Optional[RuleEngine] = None


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
