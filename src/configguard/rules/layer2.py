"""Deterministic Layer 2 switch checks approved through Phase 5C."""

from __future__ import annotations

from configguard.analysis.interface_resolution import (
    InterfaceResolution,
    InterfaceResolutionIssue,
    ResolvedInterfaceObservation,
    resolve_interface_configuration,
)
from configguard.domain import (
    AssessmentOutcome,
    Confidence,
    EvidenceReference,
    ParsedConfiguration,
    ParseStatus,
    Severity,
    StructuredObservation,
)
from configguard.rules.contracts import RuleCategory, RuleEvaluation, RuleMetadata

_OPERATIONAL_LIMITATION = (
    "Static configuration does not establish cabling, endpoint role, traffic, or runtime state."
)

type EvidenceObservation = StructuredObservation | ResolvedInterfaceObservation


class AccessPortSecurityRule:
    """Assess explicit Port Security posture on explicitly configured access ports."""

    metadata = RuleMetadata(
        rule_id="CG-L2-001",
        title="Access-port security posture",
        category=RuleCategory.LAYER_2,
        description="Evaluates explicit Port Security state on supported access ports.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        resolution = resolve_interface_configuration(configuration)
        relevant = _layer2_observations(
            configuration,
            {"interface.switchport_mode", "interface.port_security"},
        )
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "Access-port security cannot be established from incomplete input.",
                _references(relevant),
            )

        modes = _effective_interface_observations(resolution, "interface.switchport_mode")
        access_ports = {
            name
            for name, item in modes.items()
            if _boolean(item, "configured") is True and _string(item, "mode") == "access"
        }
        unsupported = _relevant_interface_unsupported(
            configuration,
            resolution,
            {
                "layer2.interface_role",
                "layer2.port_security",
            },
            access_ports,
            modes,
        )
        relationship_issues = resolution.relevant_issues(
            {"layer2.interface_role", "layer2.port_security"}
        )
        if not access_ports and unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported switchport or Port Security syntax prevents a reliable conclusion.",
                _references(unsupported),
            )
        if not access_ports and relationship_issues:
            return _resolution_uncertain(self.metadata.rule_id, relationship_issues)
        if not access_ports:
            if not _has_switch_evidence(configuration, resolution):
                return _not_applicable(
                    self.metadata.rule_id,
                    "No supported switchport evidence makes this Layer 2 check applicable.",
                )
            if _has_explicit_trunk(modes):
                return _not_applicable(
                    self.metadata.rule_id,
                    "No explicitly configured access port requires this Port Security check.",
                )
            return _unknown(
                self.metadata.rule_id,
                "No explicit supported access-port role was available for evaluation.",
                _references(tuple(modes.values())),
            )

        settings = _effective_port_security_settings(resolution)
        disabled: list[EvidenceObservation] = []
        protect: list[EvidenceObservation] = []
        uncertain: list[EvidenceObservation] = []
        passing: list[EvidenceObservation] = []
        for interface in sorted(access_ports):
            mode = modes[interface]
            state = settings.get(interface, {}).get("state")
            violation = settings.get(interface, {}).get("violation")
            if state is None:
                _append_unique(uncertain, mode)
                continue
            if _boolean(state, "enabled") is False:
                _append_unique(disabled, state)
                continue
            if _boolean(state, "enabled") is not True:
                _append_unique(uncertain, state)
                continue
            if violation is None or _boolean(violation, "configured") is False:
                _append_unique(uncertain, state)
                continue
            violation_mode = _string(violation, "value")
            if violation_mode == "protect":
                _append_unique(protect, violation)
            elif violation_mode in {"restrict", "shutdown"}:
                _append_unique(passing, mode)
                _append_unique(passing, state)
                _append_unique(passing, violation)
            else:
                _append_unique(uncertain, violation)

        if disabled:
            return _hardening(
                self.metadata.rule_id,
                Severity.LOW,
                Confidence.HIGH,
                "Port Security is explicitly disabled on at least one supported access port.",
                (
                    "The configuration lacks this specific endpoint-control mechanism on the "
                    "affected port; another approved control may be intentional."
                ),
                (
                    "Validate the port role and apply Port Security, 802.1X/NAC, or another "
                    "approved edge-access control when required."
                ),
                _references(tuple(disabled)),
            )
        if protect:
            return _hardening(
                self.metadata.rule_id,
                Severity.LOW,
                Confidence.MEDIUM,
                "An access port uses the explicit Port Security protect violation mode.",
                (
                    "Protect mode can silently discard violating traffic without the stronger "
                    "visibility or shutdown response offered by other supported modes."
                ),
                "Confirm that protect mode matches the approved monitoring and response policy.",
                _references(tuple(protect)),
            )
        if unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported switchport or Port Security syntax prevents a reliable conclusion.",
                _references(unsupported),
            )
        if relationship_issues:
            return _resolution_uncertain(self.metadata.rule_id, relationship_issues)
        if uncertain:
            return _unknown(
                self.metadata.rule_id,
                "Port Security state or violation behavior is not explicit on every access port.",
                _references(tuple(uncertain)),
            )
        return _secure(
            self.metadata.rule_id,
            "Every evaluated access port explicitly enables Port Security with a supported "
            "restrict or shutdown violation mode.",
            _references(tuple(passing)),
            (
                "Configuration presence does not prove enforcement, endpoint role, or an "
                "approved maximum-address policy.",
            ),
        )


class DhcpSnoopingTrustRule:
    """Assess explicit DHCP Snooping coverage and access-port trust state."""

    metadata = RuleMetadata(
        rule_id="CG-L2-002",
        title="DHCP Snooping trust configuration",
        category=RuleCategory.LAYER_2,
        description="Evaluates global/VLAN DHCP Snooping and explicit interface trust state.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        resolution = resolve_interface_configuration(configuration)
        relevant = _layer2_observations(
            configuration,
            {
                "interface.switchport_mode",
                "interface.access_vlan",
                "interface.dhcp_snooping_trust",
                "layer2.dhcp_snooping",
                "layer2.dhcp_snooping_vlan",
            },
        )
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "DHCP Snooping coverage cannot be established from incomplete input.",
                _references(relevant),
            )

        modes = _effective_interface_observations(resolution, "interface.switchport_mode")
        access_ports = {
            name
            for name, item in modes.items()
            if _boolean(item, "configured") is True and _string(item, "mode") == "access"
        }
        unsupported = _relevant_interface_unsupported(
            configuration,
            resolution,
            {
                "layer2.dhcp_snooping",
                "layer2.interface_role",
            },
            access_ports,
            modes,
        )
        relationship_issues = resolution.relevant_issues(
            {"layer2.dhcp_snooping", "layer2.interface_role"}
        )
        if not access_ports and unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported DHCP Snooping or access-VLAN syntax prevents a reliable conclusion.",
                _references(unsupported),
            )
        if not access_ports and relationship_issues:
            return _resolution_uncertain(self.metadata.rule_id, relationship_issues)
        if not access_ports:
            if not _has_switch_evidence(configuration, resolution):
                return _not_applicable(
                    self.metadata.rule_id,
                    "No supported switchport evidence makes this Layer 2 check applicable.",
                )
            if _has_explicit_trunk(modes):
                return _not_applicable(
                    self.metadata.rule_id,
                    "No explicitly configured access port requires DHCP Snooping coverage review.",
                )
            return _unknown(
                self.metadata.rule_id,
                "No explicit supported access-port role was available for evaluation.",
                _references(relevant),
            )

        global_state = _last(_observations(configuration, "layer2.dhcp_snooping"))
        if global_state is None:
            if unsupported:
                return _unsupported(
                    self.metadata.rule_id,
                    (
                        "Unsupported DHCP Snooping or access-VLAN syntax prevents a reliable "
                        "conclusion."
                    ),
                    _references(unsupported),
                )
            return _unknown(
                self.metadata.rule_id,
                "No explicit supported global DHCP Snooping state was observed.",
                _references(relevant),
            )
        if _boolean(global_state, "enabled") is False:
            return _hardening(
                self.metadata.rule_id,
                Severity.MEDIUM,
                Confidence.HIGH,
                "DHCP Snooping is explicitly disabled while supported access ports are present.",
                (
                    "The configuration does not provide this Layer 2 DHCP trust control; device "
                    "role and alternative enforcement remain unknown."
                ),
                (
                    "Confirm DHCP trust boundaries and enable DHCP Snooping only on applicable "
                    "client VLANs with validated trusted paths."
                ),
                _references((global_state,)),
            )
        if _boolean(global_state, "enabled") is not True:
            if unsupported:
                return _unsupported(
                    self.metadata.rule_id,
                    (
                        "Unsupported DHCP Snooping or access-VLAN syntax prevents a reliable "
                        "conclusion."
                    ),
                    _references(unsupported),
                )
            return _unknown(
                self.metadata.rule_id,
                "The global DHCP Snooping state could not be interpreted safely.",
                _references((global_state,)),
            )

        protected_vlans, vlan_evidence = _effective_dhcp_snooping_vlans(configuration)
        if not protected_vlans:
            if unsupported:
                return _unsupported(
                    self.metadata.rule_id,
                    (
                        "Unsupported DHCP Snooping or access-VLAN syntax prevents a reliable "
                        "conclusion."
                    ),
                    _references(unsupported),
                )
            return _unknown(
                self.metadata.rule_id,
                "Global DHCP Snooping is enabled, but no supported VLAN applicability is explicit.",
                _references((global_state, *vlan_evidence)),
            )

        access_vlans = _effective_interface_observations(resolution, "interface.access_vlan")
        trust = _effective_interface_observations(
            resolution,
            "interface.dhcp_snooping_trust",
        )
        trusted_access: list[EvidenceObservation] = []
        uncovered: list[EvidenceObservation] = []
        uncertain: list[EvidenceObservation] = []
        passing: list[EvidenceObservation] = [global_state, *vlan_evidence]
        for interface in sorted(access_ports):
            vlan = access_vlans.get(interface)
            if vlan is None or _boolean(vlan, "configured") is not True:
                _append_unique(uncertain, modes[interface])
                continue
            vlan_id = _string(vlan, "vlan")
            if vlan_id not in protected_vlans:
                _append_unique(uncovered, vlan)
                continue
            trust_state = trust.get(interface)
            if trust_state is None:
                _append_unique(uncertain, vlan)
            elif _boolean(trust_state, "enabled") is True:
                _append_unique(trusted_access, trust_state)
            elif _boolean(trust_state, "enabled") is False:
                _append_unique(passing, vlan)
                _append_unique(passing, trust_state)
            else:
                _append_unique(uncertain, trust_state)

        if trusted_access:
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.POTENTIAL_RISK,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                summary="DHCP Snooping trust is explicitly enabled on an access-mode interface.",
                impact=(
                    "Trusted interfaces can forward DHCP server messages without ordinary "
                    "untrusted-port validation; the port may still be a legitimate server path."
                ),
                recommendation=(
                    "Validate the physical and logical port role and retain trust only on "
                    "authorized DHCP server or uplink paths."
                ),
                evidence=_references(tuple(trusted_access)),
                limitations=(_OPERATIONAL_LIMITATION,),
            )
        if uncovered:
            return _hardening(
                self.metadata.rule_id,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "At least one explicit access VLAN is outside the configured snooping VLAN set.",
                (
                    "That VLAN lacks configuration-visible DHCP Snooping coverage, although its "
                    "client role and alternative controls are not established."
                ),
                (
                    "Confirm VLAN role and extend DHCP Snooping coverage only where the approved "
                    "DHCP trust design requires it."
                ),
                _references(tuple(uncovered)),
            )
        if unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported DHCP Snooping or access-VLAN syntax prevents a reliable conclusion.",
                _references(unsupported),
            )
        if relationship_issues:
            return _resolution_uncertain(self.metadata.rule_id, relationship_issues)
        if uncertain:
            return _unknown(
                self.metadata.rule_id,
                "Access VLAN applicability or explicit interface trust is unresolved.",
                _references(tuple(uncertain)),
            )
        return _secure(
            self.metadata.rule_id,
            "Every evaluated access port is in an explicit snooping VLAN and explicitly untrusted.",
            _references(tuple(passing)),
            (
                "Configuration evidence does not prove DHCP traffic flow, bindings, or runtime "
                "enforcement; trusted trunk roles are not judged by this rule.",
            ),
        )


class DynamicArpInspectionRule:
    """Assess explicit DAI VLAN coverage, trust, and binding prerequisites."""

    metadata = RuleMetadata(
        rule_id="CG-L2-003",
        title="Dynamic ARP Inspection coverage",
        category=RuleCategory.LAYER_2,
        description="Evaluates explicit DAI VLANs, interface trust, and DHCP Snooping evidence.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        resolution = resolve_interface_configuration(configuration)
        relevant = _layer2_observations(
            configuration,
            {
                "interface.switchport_mode",
                "interface.access_vlan",
                "interface.arp_inspection_trust",
                "interface.dhcp_snooping_trust",
                "interface.channel_group",
                "layer2.arp_inspection_vlan",
                "layer2.dhcp_snooping",
                "layer2.dhcp_snooping_vlan",
            },
        )
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "Dynamic ARP Inspection cannot be established from incomplete input.",
                _references(relevant),
            )

        modes = _effective_interface_observations(resolution, "interface.switchport_mode")
        trust = _effective_interface_observations(
            resolution,
            "interface.arp_inspection_trust",
        )

        access_ports = {
            name
            for name, item in modes.items()
            if _boolean(item, "configured") is True and _string(item, "mode") == "access"
        }
        unsupported = _relevant_interface_unsupported(
            configuration,
            resolution,
            {"layer2.dai", "layer2.interface_role"},
            access_ports,
            modes,
        )
        relationship_issues = resolution.relevant_issues({"layer2.dai", "layer2.interface_role"})
        if not access_ports and unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported DAI, validation-source, or interface syntax prevents evaluation.",
                _references(unsupported),
            )
        if not access_ports and relationship_issues:
            return _resolution_uncertain(self.metadata.rule_id, relationship_issues)
        if not access_ports:
            if not _has_switch_evidence(configuration, resolution):
                return _not_applicable(
                    self.metadata.rule_id,
                    "No supported switchport evidence makes this Layer 2 check applicable.",
                )
            if _has_explicit_trunk(modes):
                return _not_applicable(
                    self.metadata.rule_id,
                    "No explicit access port establishes a DAI client-VLAN trust boundary.",
                )
            return _unknown(
                self.metadata.rule_id,
                "No explicit supported access-port role was available for DAI evaluation.",
                _references(relevant),
            )

        dai_vlans, dai_actions, dai_evidence = _effective_vlan_configuration(
            configuration,
            "layer2.arp_inspection_vlan",
        )
        if not dai_evidence:
            if unsupported:
                return _unsupported(
                    self.metadata.rule_id,
                    "Unsupported DAI, validation-source, or interface syntax prevents evaluation.",
                    _references(unsupported),
                )
            return _unknown(
                self.metadata.rule_id,
                "No explicit supported DAI VLAN state was observed.",
                _references(relevant),
            )

        access_vlans = _effective_interface_observations(resolution, "interface.access_vlan")
        dhcp_global = _last(_observations(configuration, "layer2.dhcp_snooping"))
        dhcp_vlans, dhcp_evidence = _effective_dhcp_snooping_vlans(configuration)
        dhcp_trust = _effective_interface_observations(
            resolution,
            "interface.dhcp_snooping_trust",
        )
        trusted_access: list[EvidenceObservation] = []
        explicitly_disabled: list[EvidenceObservation] = []
        uncertain: list[EvidenceObservation] = []
        passing: list[EvidenceObservation] = [*dai_evidence]

        for interface in sorted(access_ports):
            vlan = access_vlans.get(interface)
            if vlan is None or _boolean(vlan, "configured") is not True:
                _append_unique(uncertain, modes[interface])
                continue
            vlan_id = _string(vlan, "vlan")
            if vlan_id is None:
                _append_unique(uncertain, vlan)
                continue
            dai_action = dai_actions.get(vlan_id)
            if dai_action is not None and _boolean(dai_action, "configured") is False:
                _append_unique(explicitly_disabled, dai_action)
                continue
            if vlan_id not in dai_vlans:
                _append_unique(uncertain, vlan)
                continue

            trust_state = trust.get(interface)
            if trust_state is None:
                _append_unique(uncertain, vlan)
                continue
            if _boolean(trust_state, "enabled") is True:
                _append_unique(trusted_access, trust_state)
                continue
            if _boolean(trust_state, "enabled") is not False:
                _append_unique(uncertain, trust_state)
                continue

            dhcp_trust_state = dhcp_trust.get(interface)
            if (
                dhcp_global is None
                or _boolean(dhcp_global, "enabled") is not True
                or vlan_id not in dhcp_vlans
                or dhcp_trust_state is None
                or _boolean(dhcp_trust_state, "enabled") is not False
            ):
                _append_unique(uncertain, trust_state)
                continue
            _append_unique(passing, vlan)
            _append_unique(passing, trust_state)
            _append_unique(passing, dhcp_trust_state)
            _append_unique(passing, dhcp_global)
            for item in dhcp_evidence:
                _append_unique(passing, item)

        if trusted_access:
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.POTENTIAL_RISK,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                summary="DAI trust is explicitly enabled on an access-mode interface.",
                impact=(
                    "A trusted interface bypasses ordinary DAI validation, but it may be an "
                    "intentional infrastructure or static-host path."
                ),
                recommendation=(
                    "Validate the physical and logical role and retain DAI trust only on "
                    "documented infrastructure paths that require it."
                ),
                evidence=_references(tuple(trusted_access)),
                limitations=(_OPERATIONAL_LIMITATION,),
            )
        if explicitly_disabled:
            return _hardening(
                self.metadata.rule_id,
                Severity.MEDIUM,
                Confidence.MEDIUM,
                "DAI is explicitly removed from at least one identified access VLAN.",
                (
                    "The affected VLAN lacks this configuration-visible ARP validation control; "
                    "its host model and alternative validation are not established."
                ),
                (
                    "Confirm the VLAN trust and addressing design, then enable DAI or document "
                    "the supported alternative validation mechanism."
                ),
                _references(tuple(explicitly_disabled)),
            )
        if unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported DAI, validation-source, or interface syntax prevents evaluation.",
                _references(unsupported),
            )
        if relationship_issues:
            return _resolution_uncertain(self.metadata.rule_id, relationship_issues)
        if uncertain:
            return _unknown(
                self.metadata.rule_id,
                "DAI VLAN, trust, or supported binding-source prerequisites are unresolved.",
                _references(tuple(uncertain)),
            )
        return _secure(
            self.metadata.rule_id,
            "DAI is explicitly selected for every evaluated access VLAN, access ports are "
            "explicitly untrusted for DAI and DHCP Snooping, and supported DHCP Snooping "
            "VLAN declarations are present.",
            _references(tuple(passing)),
            (
                "Configuration declarations do not prove a valid DHCP Snooping binding database, "
                "runtime DAI enforcement, static-host validation, or protection from every ARP "
                "attack.",
            ),
        )


class PortfastBpduGuardRule:
    """Assess effective BPDU Guard state on explicit PortFast or edge ports."""

    metadata = RuleMetadata(
        rule_id="CG-L2-004",
        title="BPDU Guard on PortFast edge ports",
        category=RuleCategory.LAYER_2,
        description="Evaluates global and interface BPDU Guard state on explicit edge ports.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        resolution = resolve_interface_configuration(configuration)
        relevant = _layer2_observations(
            configuration,
            {
                "interface.spanning_tree_portfast",
                "interface.bpdu_guard",
                "layer2.bpdu_guard_default",
            },
        )
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "BPDU Guard state cannot be established from incomplete input.",
                _references(relevant),
            )

        portfast = _effective_interface_observations(
            resolution,
            "interface.spanning_tree_portfast",
        )
        edge_ports = {name for name, item in portfast.items() if _boolean(item, "enabled") is True}
        unsupported = _relevant_interface_unsupported(
            configuration,
            resolution,
            {"layer2.bpdu_guard"},
            edge_ports,
            portfast,
        )
        relationship_issues = resolution.relevant_issues({"layer2.bpdu_guard"})
        if not edge_ports and unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported PortFast or BPDU Guard syntax prevents a reliable conclusion.",
                _references(unsupported),
            )
        if not edge_ports and relationship_issues:
            return _resolution_uncertain(self.metadata.rule_id, relationship_issues)
        if not edge_ports:
            if portfast or _has_switch_evidence(configuration, resolution):
                return _not_applicable(
                    self.metadata.rule_id,
                    "No interface has an explicit effective PortFast or edge-port state.",
                )
            return _not_applicable(
                self.metadata.rule_id,
                "No supported switchport evidence makes this Layer 2 check applicable.",
            )

        global_default = _last(_observations(configuration, "layer2.bpdu_guard_default"))
        per_interface = _effective_interface_observations(resolution, "interface.bpdu_guard")
        disabled: list[EvidenceObservation] = []
        uncertain: list[EvidenceObservation] = []
        passing: list[EvidenceObservation] = []
        for interface in sorted(edge_ports):
            override = per_interface.get(interface)
            if override is not None and _boolean(override, "configured") is True:
                if _boolean(override, "enabled") is True:
                    _append_unique(passing, portfast[interface])
                    _append_unique(passing, override)
                elif _boolean(override, "enabled") is False:
                    _append_unique(disabled, override)
                else:
                    _append_unique(uncertain, override)
                continue

            if global_default is None:
                _append_unique(uncertain, override or portfast[interface])
            elif _boolean(global_default, "enabled") is True:
                _append_unique(passing, portfast[interface])
                _append_unique(passing, global_default)
            elif _boolean(global_default, "enabled") is False:
                _append_unique(disabled, override or global_default)
            else:
                _append_unique(uncertain, override or global_default)

        if disabled:
            return _hardening(
                self.metadata.rule_id,
                Severity.MEDIUM,
                Confidence.HIGH,
                "BPDU Guard is explicitly disabled for at least one PortFast or edge port.",
                (
                    "The affected edge-mode interface lacks this specific STP protection; its "
                    "actual downstream role may make the state intentional."
                ),
                (
                    "Validate the connected role and enable BPDU Guard on approved edge ports, "
                    "documenting intentional exceptions."
                ),
                _references(tuple(disabled)),
            )
        if unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported PortFast or BPDU Guard syntax prevents a reliable conclusion.",
                _references(unsupported),
            )
        if relationship_issues:
            return _resolution_uncertain(self.metadata.rule_id, relationship_issues)
        if uncertain:
            return _unknown(
                self.metadata.rule_id,
                "BPDU Guard is not explicitly resolved for every PortFast or edge port.",
                _references(tuple(uncertain)),
            )
        return _secure(
            self.metadata.rule_id,
            "BPDU Guard is explicitly effective on every evaluated PortFast or edge port.",
            _references(tuple(passing)),
            (
                "BPDU Guard does not prevent every Layer 2 attack and runtime STP state is not "
                "verified.",
            ),
        )


def layer2_rules() -> tuple[
    AccessPortSecurityRule,
    DhcpSnoopingTrustRule,
    DynamicArpInspectionRule,
    PortfastBpduGuardRule,
]:
    """Return the four Layer 2 rules approved through Phase 5C."""

    return (
        AccessPortSecurityRule(),
        DhcpSnoopingTrustRule(),
        DynamicArpInspectionRule(),
        PortfastBpduGuardRule(),
    )


def _observations(
    configuration: ParsedConfiguration,
    kind: str,
) -> tuple[StructuredObservation, ...]:
    return tuple(item for item in configuration.observations if item.kind == kind)


def _layer2_observations(
    configuration: ParsedConfiguration,
    kinds: set[str],
) -> tuple[StructuredObservation, ...]:
    return tuple(item for item in configuration.observations if item.kind in kinds)


def _effective_interface_observations(
    resolution: InterfaceResolution,
    kind: str,
) -> dict[str, ResolvedInterfaceObservation]:
    return resolution.effective(kind)


def _effective_port_security_settings(
    resolution: InterfaceResolution,
) -> dict[str, dict[str, ResolvedInterfaceObservation]]:
    return resolution.effective_settings("interface.port_security", "setting")


def _effective_dhcp_snooping_vlans(
    configuration: ParsedConfiguration,
) -> tuple[set[str], tuple[StructuredObservation, ...]]:
    effective: set[str] = set()
    evidence: list[StructuredObservation] = []
    for item in _observations(configuration, "layer2.dhcp_snooping_vlan"):
        vlans = _strings(item, "vlans")
        if _boolean(item, "configured") is True:
            effective.update(vlans)
        else:
            effective.difference_update(vlans)
        evidence.append(item)
    return effective, tuple(evidence)


def _effective_vlan_configuration(
    configuration: ParsedConfiguration,
    kind: str,
) -> tuple[
    set[str],
    dict[str, StructuredObservation],
    tuple[StructuredObservation, ...],
]:
    effective: set[str] = set()
    actions: dict[str, StructuredObservation] = {}
    evidence: list[StructuredObservation] = []
    for item in _observations(configuration, kind):
        vlans = _strings(item, "vlans")
        configured = _boolean(item, "configured") is True
        for vlan in vlans:
            actions[vlan] = item
        if configured:
            effective.update(vlans)
        else:
            effective.difference_update(vlans)
        evidence.append(item)
    return effective, actions, tuple(evidence)


def _relevant_interface_unsupported(
    configuration: ParsedConfiguration,
    resolution: InterfaceResolution,
    rule_scopes: set[str],
    relevant_interfaces: set[str],
    roles: dict[str, ResolvedInterfaceObservation],
) -> tuple[StructuredObservation, ...]:
    unsupported: list[StructuredObservation] = []
    for item in configuration.observations:
        if item.kind != "command.unclassified" or _string(item, "rule_scope") not in rule_scopes:
            continue
        if _string(item, "context_kind") == "interface_template":
            continue
        interface = _string(item, "context_identifier")
        resolved_targets = resolution.targets_for_context(interface)
        candidate_interfaces = resolved_targets or ((interface,) if interface is not None else ())
        known_roles = tuple(roles.get(target) for target in candidate_interfaces)
        if (
            interface is None
            or not candidate_interfaces
            or any(target in relevant_interfaces for target in candidate_interfaces)
            or any(role is None or _string(role, "mode") != "trunk" for role in known_roles)
        ):
            unsupported.append(item)
    return tuple(unsupported)


def _has_explicit_trunk(modes: dict[str, ResolvedInterfaceObservation]) -> bool:
    return any(
        _boolean(item, "configured") is True and _string(item, "mode") == "trunk"
        for item in modes.values()
    )


def _has_switch_evidence(
    configuration: ParsedConfiguration,
    resolution: InterfaceResolution,
) -> bool:
    return any(
        fact.observation.kind != "interface.access_group" for fact in resolution.facts
    ) or any(item.kind.startswith("layer2.") for item in configuration.observations)


def _last(
    observations: tuple[StructuredObservation, ...],
) -> StructuredObservation | None:
    return observations[-1] if observations else None


def _structured(observation: EvidenceObservation) -> StructuredObservation:
    if isinstance(observation, ResolvedInterfaceObservation):
        return observation.observation
    return observation


def _string(observation: EvidenceObservation, key: str) -> str | None:
    value = _structured(observation).attributes.get(key)
    return value if isinstance(value, str) else None


def _strings(observation: StructuredObservation, key: str) -> tuple[str, ...]:
    value = observation.attributes.get(key)
    return value if isinstance(value, tuple) else ()


def _boolean(observation: EvidenceObservation, key: str) -> bool | None:
    value = _structured(observation).attributes.get(key)
    return value if isinstance(value, bool) else None


def _append_unique(
    items: list[EvidenceObservation],
    observation: EvidenceObservation,
) -> None:
    if observation not in items:
        items.append(observation)


def _references(
    observations: tuple[EvidenceObservation, ...],
) -> tuple[EvidenceReference, ...]:
    references: list[EvidenceReference] = []
    for item in observations:
        observation = _structured(item)
        if isinstance(item, ResolvedInterfaceObservation) and item.origin_observation is not None:
            origin_reference = EvidenceReference(
                observation_id=item.origin_observation.observation_id,
                source_command_ids=item.origin_observation.source_command_ids,
                target_interface=item.target_interface,
                resolution_origin=item.origin.value,
            )
            if origin_reference not in references:
                references.append(origin_reference)
        reference = EvidenceReference(
            observation_id=observation.observation_id,
            source_command_ids=observation.source_command_ids,
            target_interface=(
                item.target_interface if isinstance(item, ResolvedInterfaceObservation) else None
            ),
            resolution_origin=(
                item.origin.value if isinstance(item, ResolvedInterfaceObservation) else None
            ),
        )
        if reference not in references:
            references.append(reference)
    return tuple(references)


def _resolution_uncertain(
    rule_id: str,
    issues: tuple[InterfaceResolutionIssue, ...],
) -> RuleEvaluation:
    evidence: list[EvidenceObservation] = []
    for issue in issues:
        for item in issue.evidence:
            _append_unique(evidence, item)
    if any(issue.unsupported_syntax for issue in issues):
        return _unsupported(
            rule_id,
            _resolution_summary("Unsupported interface relationship syntax", issues),
            _references(tuple(evidence)),
        )
    return _unknown(
        rule_id,
        _resolution_summary("Interface relationship behavior is unresolved", issues),
        _references(tuple(evidence)),
    )


def _resolution_summary(
    prefix: str,
    issues: tuple[InterfaceResolutionIssue, ...],
) -> str:
    reasons: list[str] = []
    for issue in issues:
        if issue.reason not in reasons:
            reasons.append(issue.reason)
    detail = " ".join(reasons[:2])
    if len(reasons) > 2:
        detail += " Additional unresolved relationships exist."
    return f"{prefix}. {detail}".strip()


def _unknown(
    rule_id: str,
    summary: str,
    evidence: tuple[EvidenceReference, ...],
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        outcome=AssessmentOutcome.UNKNOWN,
        severity=None,
        confidence=Confidence.LOW,
        summary=summary,
        impact=None,
        recommendation=None,
        evidence=evidence,
        limitations=("No Layer 2 security conclusion was inferred from insufficient evidence.",),
    )


def _unsupported(
    rule_id: str,
    summary: str,
    evidence: tuple[EvidenceReference, ...],
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        outcome=AssessmentOutcome.UNSUPPORTED_SYNTAX,
        severity=None,
        confidence=Confidence.LOW,
        summary=summary,
        impact=None,
        recommendation=None,
        evidence=evidence,
        limitations=("Relevant unsupported syntax was not treated as secure.",),
    )


def _hardening(
    rule_id: str,
    severity: Severity,
    confidence: Confidence,
    summary: str,
    impact: str,
    recommendation: str,
    evidence: tuple[EvidenceReference, ...],
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        outcome=AssessmentOutcome.HARDENING,
        severity=severity,
        confidence=confidence,
        summary=summary,
        impact=impact,
        recommendation=recommendation,
        evidence=evidence,
        limitations=(_OPERATIONAL_LIMITATION,),
    )


def _secure(
    rule_id: str,
    summary: str,
    evidence: tuple[EvidenceReference, ...],
    limitations: tuple[str, ...],
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        outcome=AssessmentOutcome.SECURE,
        severity=None,
        confidence=Confidence.HIGH,
        summary=summary,
        impact=None,
        recommendation=None,
        evidence=evidence,
        limitations=limitations,
    )


def _not_applicable(rule_id: str, summary: str) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        outcome=AssessmentOutcome.NOT_APPLICABLE,
        severity=None,
        confidence=Confidence.HIGH,
        summary=summary,
        impact=None,
        recommendation=None,
    )
