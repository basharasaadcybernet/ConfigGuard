"""Security rule contracts and the seventeen approved Phase 7B rules."""

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
from configguard.rules.routing import (
    EigrpAuthenticationRule,
    OspfAuthenticationRule,
    RipAuthenticationRule,
)

__all__ = [
    "AccessPortSecurityRule",
    "BroadInterfaceAclPermissionRule",
    "DhcpSnoopingTrustRule",
    "DynamicArpInspectionRule",
    "EigrpAuthenticationRule",
    "InterfaceAclReferenceIntegrityRule",
    "ManagementLineLoginAuthenticationRule",
    "OspfAuthenticationRule",
    "PlaintextCredentialStorageRule",
    "PlaintextHttpManagementRule",
    "PortfastBpduGuardRule",
    "RipAuthenticationRule",
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
