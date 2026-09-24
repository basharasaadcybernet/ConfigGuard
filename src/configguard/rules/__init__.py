"""Security rule contracts and the eleven approved Phase 5B rules."""

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
from configguard.rules.layer2 import (
    AccessPortSecurityRule,
    DhcpSnoopingTrustRule,
    PortfastBpduGuardRule,
)

__all__ = [
    "AccessPortSecurityRule",
    "DhcpSnoopingTrustRule",
    "ManagementLineLoginAuthenticationRule",
    "PlaintextCredentialStorageRule",
    "PlaintextHttpManagementRule",
    "PortfastBpduGuardRule",
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
