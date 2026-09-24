"""Security rule contracts and the fourteen approved Phase 7A rules."""

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
from configguard.rules.interface_acl import (
    BroadInterfaceAclPermissionRule,
    InterfaceAclReferenceIntegrityRule,
)
from configguard.rules.layer2 import (
    AccessPortSecurityRule,
    DhcpSnoopingTrustRule,
    DynamicArpInspectionRule,
    PortfastBpduGuardRule,
)

__all__ = [
    "AccessPortSecurityRule",
    "BroadInterfaceAclPermissionRule",
    "DhcpSnoopingTrustRule",
    "DynamicArpInspectionRule",
    "InterfaceAclReferenceIntegrityRule",
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
