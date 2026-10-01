"""
HIDS Rules Module (Backward Compatibility & Integration Layer).

Re-exports the decoupled HIDS rule architecture components:
- RuleParser & Rule from hids.rules_parser
- RuleMetadata & Registry from hids.rule_metadata
- RuleEngine, RuleMatch, AllowlistEngine, check_event from hids.rule_engine
- Severity from hids.severity
- NormalizedEvent from hids.normalizer
"""

from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

from hids.normalizer import NormalizedEvent, normalize_event
from hids.rule_engine import AllowlistEngine, RuleEngine, RuleMatch, check_event
from hids.rule_metadata import (
    RULE_METADATA_REGISTRY,
    RuleMetadata,
    get_rule_metadata,
)
from hids.rules_parser import DEFAULT_RULES_FILE, Rule, RuleParser
from hids.severity import Severity

__all__ = [
    "AllowlistEngine",
    "RuleEngine",
    "RuleMatch",
    "RuleParser",
    "Rule",
    "RuleMetadata",
    "RULE_METADATA_REGISTRY",
    "get_rule_metadata",
    "Severity",
    "NormalizedEvent",
    "normalize_event",
    "check_event",
]


# =========================================================================
# Backward Compatibility Wrappers for Legacy Rule Class Names
# =========================================================================

class _LegacyRuleWrapper:
    """Compatibility wrapper that maps legacy class instantiations to RuleEngine evaluation."""
    def __init__(self, rule_id: str):
        self.rule_id = rule_id
        self._engine = RuleEngine()

    def evaluate(self, event: NormalizedEvent) -> Optional[RuleMatch]:
        matches = self._engine.evaluate(event)
        for m in matches:
            if m.rule_id == self.rule_id:
                return m
        return None


class RuleFailedLogon(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("SEC-001")


class RulePrivilegeAssignment(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("PRV-001")


class RuleSecurityGroupModified(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("PRV-002")


class RuleUserAccountCreated(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("PRV-003")


class RuleSuspiciousProcess(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("PROC-001")


class RuleServiceInstalled(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("SRV-001")


class RuleServiceTerminatedUnexpectedly(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("SRV-002")


class RuleDefenderMalwareDetected(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("MAL-001")


class RuleDefenderProtectionDisabled(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("MAL-002")


class RuleSuspiciousPowerShell(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("PSH-001")


class RuleEventLogCleared(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("LOG-001")


class RuleAccountLockedOut(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("ACC-001")


class RuleAccountEnabled(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("ACC-002")


class RuleAccountDisabled(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("ACC-003")


class RulePasswordReset(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("ACC-004")


class RuleExplicitCredentialLogon(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("AUTH-001")


class RuleRemoteInteractiveLogon(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("LOGON-001")


class RuleScheduledTaskCreated(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("SCHD-001")


class RuleAuditPolicyChanged(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("AUDIT-001")


class RuleFirewallRuleAdded(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("FW-001")


class RuleDefenderExclusionAdded(_LegacyRuleWrapper):
    def __init__(self):
        super().__init__("MAL-003")