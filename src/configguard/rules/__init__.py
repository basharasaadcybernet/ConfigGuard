"""Security rule contracts and the eight approved Phase 5A rules."""

from configguard.rules.contracts import (
    RuleCategory,
    RuleEvaluation,
    RuleMetadata,
    SecurityRule,
)
from configguard.rules.initial import (
    ManagementLineLoginAuthenticationRule,
    PlaintextCredentialStorageRule,
    PlaintextHttpManagementRule,
    SnmpCommunityAccessRestrictionRule,
    SnmpCommunityConfigurationRule,
    SshVersionOneRule,
    VtySourceRestrictionRule,
    VtyTelnetRule,
    initial_rules,
)

__all__ = [
    "ManagementLineLoginAuthenticationRule",
    "PlaintextCredentialStorageRule",
    "PlaintextHttpManagementRule",
    "RuleCategory",
    "RuleEvaluation",
    "RuleMetadata",
    "SecurityRule",
    "SnmpCommunityAccessRestrictionRule",
    "SnmpCommunityConfigurationRule",
    "SshVersionOneRule",
    "VtySourceRestrictionRule",
    "VtyTelnetRule",
    "initial_rules",
]
