"""Deterministic Layer 2 switch checks approved for Phase 5B."""

from __future__ import annotations

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


class AccessPortSecurityRule:
    """Assess explicit Port Security posture on explicitly configured access ports."""

    metadata = RuleMetadata(
        rule_id="CG-L2-001",
        title="Access-port security posture",
        category=RuleCategory.LAYER_2,
        description="Evaluates explicit Port Security state on supported access ports.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
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

        modes = _effective_interface_observations(configuration, "interface.switchport_mode")
        if _has_interface_range(modes):
            return _unknown(
                self.metadata.rule_id,
                "Interface-range expansion is not modeled for Port Security evaluation.",
                _references(tuple(modes.values())),
            )
        access_ports = {
            name
            for name, item in modes.items()
            if _boolean(item, "configured") is True and _string(item, "mode") == "access"
        }
        unsupported = _relevant_interface_unsupported(
            configuration,
            {"layer2.interface_role", "layer2.port_security"},
            access_ports,
            modes,
        )
        if unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported switchport or Port Security syntax prevents a reliable conclusion.",
                _references(unsupported),
            )
        if not access_ports:
            if not _has_switch_evidence(configuration):
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

        settings = _effective_port_security_settings(configuration)
        disabled: list[StructuredObservation] = []
        protect: list[StructuredObservation] = []
        uncertain: list[StructuredObservation] = []
        passing: list[StructuredObservation] = []
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

        modes = _effective_interface_observations(configuration, "interface.switchport_mode")
        if _has_interface_range(modes):
            return _unknown(
                self.metadata.rule_id,
                "Interface-range expansion is not modeled for DHCP Snooping evaluation.",
                _references(tuple(modes.values())),
            )
        access_ports = {
            name
            for name, item in modes.items()
            if _boolean(item, "configured") is True and _string(item, "mode") == "access"
        }
        unsupported = _relevant_interface_unsupported(
            configuration,
            {"layer2.dhcp_snooping", "layer2.interface_role"},
            access_ports,
            modes,
        )
        if unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported DHCP Snooping or access-VLAN syntax prevents a reliable conclusion.",
                _references(unsupported),
            )
        if not access_ports:
            if not _has_switch_evidence(configuration):
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
            return _unknown(
                self.metadata.rule_id,
                "The global DHCP Snooping state could not be interpreted safely.",
                _references((global_state,)),
            )

        protected_vlans, vlan_evidence = _effective_dhcp_snooping_vlans(configuration)
        if not protected_vlans:
            return _unknown(
                self.metadata.rule_id,
                "Global DHCP Snooping is enabled, but no supported VLAN applicability is explicit.",
                _references((global_state, *vlan_evidence)),
            )

        access_vlans = _effective_interface_observations(configuration, "interface.access_vlan")
        trust = _effective_interface_observations(
            configuration,
            "interface.dhcp_snooping_trust",
        )
        trusted_access: list[StructuredObservation] = []
        uncovered: list[StructuredObservation] = []
        uncertain: list[StructuredObservation] = []
        passing: list[StructuredObservation] = [global_state, *vlan_evidence]
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


class PortfastBpduGuardRule:
    """Assess effective BPDU Guard state on explicit PortFast or edge ports."""

    metadata = RuleMetadata(
        rule_id="CG-L2-004",
        title="BPDU Guard on PortFast edge ports",
        category=RuleCategory.LAYER_2,
        description="Evaluates global and interface BPDU Guard state on explicit edge ports.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
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
            configuration,
            "interface.spanning_tree_portfast",
        )
        if _has_interface_range(portfast):
            return _unknown(
                self.metadata.rule_id,
                "Interface-range expansion is not modeled for BPDU Guard evaluation.",
                _references(tuple(portfast.values())),
            )
        edge_ports = {
            name for name, item in portfast.items() if _boolean(item, "enabled") is True
        }
        unsupported = _relevant_interface_unsupported(
            configuration,
            {"layer2.bpdu_guard"},
            edge_ports,
            portfast,
        )
        if unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported PortFast or BPDU Guard syntax prevents a reliable conclusion.",
                _references(unsupported),
            )
        if not edge_ports:
            if portfast or _has_switch_evidence(configuration):
                return _not_applicable(
                    self.metadata.rule_id,
                    "No interface has an explicit effective PortFast or edge-port state.",
                )
            return _not_applicable(
                self.metadata.rule_id,
                "No supported switchport evidence makes this Layer 2 check applicable.",
            )

        global_default = _last(_observations(configuration, "layer2.bpdu_guard_default"))
        per_interface = _effective_interface_observations(configuration, "interface.bpdu_guard")
        disabled: list[StructuredObservation] = []
        uncertain: list[StructuredObservation] = []
        passing: list[StructuredObservation] = []
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


def layer2_rules() -> tuple[AccessPortSecurityRule, DhcpSnoopingTrustRule, PortfastBpduGuardRule]:
    """Return exactly the three Phase 5B rules in deterministic product order."""

    return AccessPortSecurityRule(), DhcpSnoopingTrustRule(), PortfastBpduGuardRule()


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
    configuration: ParsedConfiguration,
    kind: str,
) -> dict[str, StructuredObservation]:
    effective: dict[str, StructuredObservation] = {}
    for item in _observations(configuration, kind):
        interface = _string(item, "interface")
        if interface is not None:
            effective[interface] = item
    return effective


def _effective_port_security_settings(
    configuration: ParsedConfiguration,
) -> dict[str, dict[str, StructuredObservation]]:
    effective: dict[str, dict[str, StructuredObservation]] = {}
    for item in _observations(configuration, "interface.port_security"):
        interface = _string(item, "interface")
        setting = _string(item, "setting")
        if interface is not None and setting is not None:
            effective.setdefault(interface, {})[setting] = item
    return effective


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


def _relevant_interface_unsupported(
    configuration: ParsedConfiguration,
    rule_scopes: set[str],
    relevant_interfaces: set[str],
    roles: dict[str, StructuredObservation],
) -> tuple[StructuredObservation, ...]:
    unsupported: list[StructuredObservation] = []
    for item in configuration.observations:
        if (
            item.kind != "command.unclassified"
            or _string(item, "rule_scope") not in rule_scopes
        ):
            continue
        interface = _string(item, "context_identifier")
        known_role = roles.get(interface or "")
        if (
            interface is None
            or interface in relevant_interfaces
            or known_role is None
            or _string(known_role, "mode") != "trunk"
        ):
            unsupported.append(item)
    return tuple(unsupported)


def _has_interface_range(observations: dict[str, StructuredObservation]) -> bool:
    return any(name.lower().startswith("range ") for name in observations)


def _has_explicit_trunk(modes: dict[str, StructuredObservation]) -> bool:
    return any(
        _boolean(item, "configured") is True and _string(item, "mode") == "trunk"
        for item in modes.values()
    )


def _has_switch_evidence(configuration: ParsedConfiguration) -> bool:
    return any(
        item.kind.startswith("interface.switchport")
        or item.kind.startswith("interface.spanning_tree")
        or item.kind.startswith("interface.bpdu_guard")
        or item.kind.startswith("layer2.")
        for item in configuration.observations
    )


def _last(
    observations: tuple[StructuredObservation, ...],
) -> StructuredObservation | None:
    return observations[-1] if observations else None


def _string(observation: StructuredObservation, key: str) -> str | None:
    value = observation.attributes.get(key)
    return value if isinstance(value, str) else None


def _strings(observation: StructuredObservation, key: str) -> tuple[str, ...]:
    value = observation.attributes.get(key)
    return value if isinstance(value, tuple) else ()


def _boolean(observation: StructuredObservation, key: str) -> bool | None:
    value = observation.attributes.get(key)
    return value if isinstance(value, bool) else None


def _append_unique(
    items: list[StructuredObservation],
    observation: StructuredObservation,
) -> None:
    if observation not in items:
        items.append(observation)


def _references(
    observations: tuple[StructuredObservation, ...],
) -> tuple[EvidenceReference, ...]:
    return tuple(
        EvidenceReference(
            observation_id=item.observation_id,
            source_command_ids=item.source_command_ids,
        )
        for item in observations
    )


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
