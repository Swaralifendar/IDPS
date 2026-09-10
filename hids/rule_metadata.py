"""
HIDS Rule Metadata Registry.

Maintains centralized, decoupled rule metadata (name, description, severity, MITRE ATT&CK)
indexed by Rule ID without cluttering detection rule definitions or global configuration.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Union

from hids.severity import Severity


@dataclass
class RuleMetadata:
    """
    Metadata associated with a HIDS detection rule.
    """
    rule_id: str
    name: str
    description: str
    severity: Severity
    mitre_attack: str
    category_type:List[str]
    attack_type: str

    @property
    def primary_category_type(self) -> str:
        """First (primary) category_type entry -- for callers that want a single value."""
        return self.category_type[0] if self.category_type else "BENIGN_TEST"
 
    @property
    def mitre_list(self) -> List[str]:
        """Return list of MITRE ATT&CK technique IDs."""
        if not self.mitre_attack:
            return []
        # Extract technique identifiers (e.g. T1059, T1110.001)
        tokens = [t.strip().split(" - ")[0].strip() for t in self.mitre_attack.split(",") if t.strip()]
        return tokens


# Centralized Metadata Registry for all 21 HIDS Rules
RULE_METADATA_REGISTRY: Dict[str, RuleMetadata] = {
    "SEC-001": RuleMetadata(
        rule_id="SEC-001",
        name="Failed User Logon",
        description="A user logon attempt failed due to bad credentials, an unknown user, or an expired account.",
        severity=Severity.LOW,
        mitre_attack="T1078, T1110.001",
        category_type=["UNAUTHORIZED_ACCESS"],
        attack_type="Brute Force",
    ),
    "PRV-001": RuleMetadata(
        rule_id="PRV-001",
        name="Sensitive Privilege Assigned to Logon",
        description="Special administrative privileges were assigned to a new logon session.",
        severity=Severity.MEDIUM,
        mitre_attack="T1078.002, T1068",
        category_type=["PRIVILEGE_ESCALATION"],
        attack_type="Privilege Escalation",
    ),
    "PRV-002": RuleMetadata(
        rule_id="PRV-002",
        name="Security Group Membership Modified",
        description="A member was added to a security-enabled local or global administrative group.",
        severity=Severity.HIGH,
        mitre_attack="T1098, T1068",
        category_type=["PRIVILEGE_ESCALATION", "PERSISTENCE"],
        attack_type="Account Manipulation",
    ),
    "PRV-003": RuleMetadata(
        rule_id="PRV-003",
        name="New User Account Created",
        description="A new local or domain user account was created.",
        severity=Severity.MEDIUM,
        mitre_attack="T1136.001",
        category_type=["PERSISTENCE"],
        attack_type="Account Manipulation",
    ),
    "PROC-001": RuleMetadata(
        rule_id="PROC-001",
        name="Suspicious Process Execution",
        description="A process creation event was detected and evaluated for suspicious execution characteristics.",
        severity=Severity.HIGH,
        mitre_attack="T1059, T1003, T1070",
        category_type=["EXPLOIT", "C2"],
        attack_type="Execution",
    ),
    "SRV-001": RuleMetadata(
        rule_id="SRV-001",
        name="New Windows Service Installed",
        description="A new Windows service was installed in the system, potentially indicating persistence or privilege escalation.",
        severity=Severity.HIGH,
        mitre_attack="T1543.003",
        category_type=["PERSISTENCE"],
        attack_type="Persistence",
    ),
    "SRV-002": RuleMetadata(
        rule_id="SRV-002",
        name="Service Terminated Unexpectedly",
        description="A Windows service crashed or terminated unexpectedly.",
        severity=Severity.MEDIUM,
        mitre_attack="T1489",
        category_type=["DEFENSE_EVASION"],
        attack_type="Persistence",
    ),
    "MAL-001": RuleMetadata(
        rule_id="MAL-001",
        name="Windows Defender Malware Detection",
        description="Microsoft Defender detected malware or an active security threat on the host.",
        severity=Severity.CRITICAL,
        mitre_attack="T1204",
        category_type=["MALWARE"],
        attack_type="Malware",
    ),
    "MAL-002": RuleMetadata(
        rule_id="MAL-002",
        name="Defender Real-Time Protection Disabled",
        description="Microsoft Defender real-time antivirus protection was turned off or tampered with.",
        severity=Severity.CRITICAL,
        mitre_attack="T1562.001",
        category_type=["DEFENSE_EVASION"],
        attack_type="Defense Evasion",
    ),
    "MAL-003": RuleMetadata(
        rule_id="MAL-003",
        name="Windows Defender Exclusion Added",
        description="A file, folder, or process exclusion was added to Windows Defender, potentially to evade malware detection.",
        severity=Severity.HIGH,
        mitre_attack="T1562.001",
        category_type=["DEFENSE_EVASION"],
        attack_type="Defense Evasion",
    ),
    "PSH-001": RuleMetadata(
        rule_id="PSH-001",
        name="Suspicious PowerShell Activity",
        description="Suspicious PowerShell commands or scripting activity was detected.",
        severity=Severity.HIGH,
        mitre_attack="T1059.001",
        category_type=["EXPLOIT", "C2"],
        attack_type="PowerShell",
    ),
    "LOG-001": RuleMetadata(
        rule_id="LOG-001",
        name="Windows Event Log Cleared",
        description="A Windows audit or system event log was deliberately cleared, potentially indicating defense evasion.",
        severity=Severity.CRITICAL,
        mitre_attack="T1070.001",
        category_type=["DEFENSE_EVASION"],
        attack_type="Defense Evasion",
    ),
    "ACC-001": RuleMetadata(
        rule_id="ACC-001",
        name="Account Locked Out",
        description="A user account was locked out after repeated failed logon attempts.",
        severity=Severity.MEDIUM,
        mitre_attack="T1110",
        category_type=["UNAUTHORIZED_ACCESS"],
        attack_type="Account Manipulation",
    ),
    "ACC-002": RuleMetadata(
        rule_id="ACC-002",
        name="User Account Enabled",
        description="A previously disabled user account was re-enabled.",
        severity=Severity.LOW,
        mitre_attack="T1098",
        category_type=["PERSISTENCE"],
        attack_type="Account Manipulation",
    ),
    "ACC-003": RuleMetadata(
        rule_id="ACC-003",
        name="User Account Disabled",
        description="A user account was disabled, potentially to hinder detection or as part of account manipulation.",
        severity=Severity.LOW,
        mitre_attack="T1531",
        category_type=["DEFENSE_EVASION"],
        attack_type="Account Manipulation",
    ),
    "ACC-004": RuleMetadata(
        rule_id="ACC-004",
        name="User Password Reset",
        description="An attempt was made to reset a user account's password.",
        severity=Severity.MEDIUM,
        mitre_attack="T1098",
        category_type=["PERSISTENCE"],
        attack_type="Credential Access",
    ),
    "AUTH-001": RuleMetadata(
        rule_id="AUTH-001",
        name="Explicit Credential Logon",
        description="A process attempted to logon using explicitly supplied credentials, a pattern associated with lateral movement or pass-the-hash activity.",
        severity=Severity.MEDIUM,
        mitre_attack="T1550.002",
        category_type=["LATERAL_MOVEMENT", "UNAUTHORIZED_ACCESS"],
        attack_type="Credential Access",
    ),
    "LOGON-001": RuleMetadata(
        rule_id="LOGON-001",
        name="Remote Interactive Logon",
        description="A remote interactive (RDP) logon was detected.",
        severity=Severity.MEDIUM,
        mitre_attack="T1021.001",
        category_type=["UNAUTHORIZED_ACCESS"],
        attack_type="Initial Access",
    ),
    "SCHD-001": RuleMetadata(
        rule_id="SCHD-001",
        name="Scheduled Task Created",
        description="A new scheduled task was created, potentially indicating a persistence mechanism.",
        severity=Severity.HIGH,
        mitre_attack="T1053.005",
        category_type=["PERSISTENCE"],
        attack_type="Persistence",
    ),
    "AUDIT-001": RuleMetadata(
        rule_id="AUDIT-001",
        name="Audit Policy Changed",
        description="The system audit policy was modified, potentially to evade detection.",
        severity=Severity.HIGH,
        mitre_attack="T1562.002",
        category_type=["DEFENSE_EVASION"],
        attack_type="Defense Evasion",
    ),
    "FW-001": RuleMetadata(
        rule_id="FW-001",
        name="Windows Firewall Rule Added",
        description="A new Windows Firewall rule was added or modified, potentially to enable unauthorized network access.",
        severity=Severity.MEDIUM,
        mitre_attack="T1562.004",
        category_type=["POLICY_VIOLATION", "DEFENSE_EVASION"],
        attack_type="Defense Evasion",
    ),
}


def get_rule_metadata(rule_id: str) -> RuleMetadata:
    """
    Retrieve metadata for a given rule ID.
    If not found in the registry, returns a default RuleMetadata object.
    """
    if rule_id in RULE_METADATA_REGISTRY:
        return RULE_METADATA_REGISTRY[rule_id]

    return RuleMetadata(
        rule_id=rule_id,
        name=f"Security Rule {rule_id}",
        description=f"Security detection rule {rule_id}",
        severity=Severity.MEDIUM,
        mitre_attack="N/A",
        category_type=["POLICY_VIOLATION", "DEFENSE_EVASION"],
        attack_type="N/A"
    )
