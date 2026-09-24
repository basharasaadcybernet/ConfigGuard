"""Deterministic routing-protocol authentication checks."""

from __future__ import annotations

from configguard.analysis.interface_resolution import ResolvedInterfaceObservation
from configguard.analysis.routing_resolution import (
    ResolvedRoutingTarget,
    RoutingAuthenticationResolution,
    RoutingAuthenticationStatus,
    RoutingEvidence,
    resolve_routing_authentication,
)
from configguard.domain import (
    AssessmentOutcome,
    Confidence,
    EvidenceReference,
    ParsedConfiguration,
    ParseStatus,
    Severity,
)
from configguard.rules.contracts import RuleCategory, RuleEvaluation, RuleMetadata

_STATIC_LIMITATIONS = (
    "Static configuration does not prove peer key agreement, adjacency state, packet "
    "exchange, or operational authentication success.",
    "Key material presence is checked without assessing secret strength, lifetime, or "
    "external key-management controls.",
)


class OspfAuthenticationRule:
    """Assess supported OSPFv2 interface and area authentication settings."""

    metadata = RuleMetadata(
        rule_id="CG-ROUTE-001",
        title="OSPFv2 neighbor authentication",
        category=RuleCategory.ROUTING_PROTOCOL,
        description="Checks supported OSPFv2 authentication mode and matching interface keys.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        return _evaluate(configuration, self.metadata.rule_id, "ospf", "OSPFv2")


class EigrpAuthenticationRule:
    """Assess supported classic IPv4 EIGRP MD5 authentication settings."""

    metadata = RuleMetadata(
        rule_id="CG-ROUTE-002",
        title="Classic IPv4 EIGRP authentication",
        category=RuleCategory.ROUTING_PROTOCOL,
        description="Checks supported classic IPv4 EIGRP MD5 and key-chain configuration.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        return _evaluate(configuration, self.metadata.rule_id, "eigrp", "classic IPv4 EIGRP")


class RipAuthenticationRule:
    """Assess supported RIPv2 interface authentication settings."""

    metadata = RuleMetadata(
        rule_id="CG-ROUTE-003",
        title="RIPv2 authentication",
        category=RuleCategory.ROUTING_PROTOCOL,
        description="Checks supported RIPv2 authentication mode and key-chain configuration.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        return _evaluate(configuration, self.metadata.rule_id, "rip", "RIPv2")


def routing_rules() -> tuple[
    OspfAuthenticationRule,
    EigrpAuthenticationRule,
    RipAuthenticationRule,
]:
    """Return the three routing authentication rules approved for Phase 7B."""

    return OspfAuthenticationRule(), EigrpAuthenticationRule(), RipAuthenticationRule()


def _evaluate(
    configuration: ParsedConfiguration,
    rule_id: str,
    protocol: str,
    label: str,
) -> RuleEvaluation:
    resolution = resolve_routing_authentication(configuration, protocol)
    all_evidence = _resolution_evidence(resolution)
    if configuration.status is ParseStatus.INCOMPLETE:
        return _unknown(
            rule_id,
            f"{label} authentication cannot be established from incomplete input.",
            all_evidence,
        )
    if resolution.unsupported_process_mode:
        return _unsupported(
            rule_id,
            f"Active {label} process syntax is outside the implemented supported subset.",
            all_evidence,
        )
    if not resolution.processes:
        if resolution.unsupported:
            return _unsupported(
                rule_id,
                f"Relevant {label} syntax could not be interpreted safely.",
                all_evidence,
            )
        if _has_protocol_auth_evidence(configuration, protocol):
            return _unknown(
                rule_id,
                f"{label} authentication commands exist without a supported active process.",
                all_evidence,
            )
        return _not_applicable(rule_id, f"No supported active {label} process is configured.")
    if not resolution.targets:
        if resolution.passive_only:
            return _not_applicable(
                rule_id,
                f"All supported {label} participating interfaces are explicitly passive.",
                all_evidence,
            )
        if resolution.unsupported or resolution.issues:
            return _unsupported(
                rule_id,
                f"Relevant syntax or interface inheritance prevents {label} target resolution.",
                all_evidence,
            )
        if resolution.uncertain:
            return _unknown(
                rule_id,
                f"Supported {label} association removal does not match the active statement.",
                all_evidence,
            )
        return _unknown(
            rule_id,
            f"No non-passive {label} participating interface can be established from "
            "supported evidence.",
            all_evidence,
        )

    disabled = tuple(
        item for item in resolution.targets if item.status is RoutingAuthenticationStatus.DISABLED
    )
    weak = tuple(
        item for item in resolution.targets if item.status is RoutingAuthenticationStatus.WEAK
    )
    unknown = tuple(
        item for item in resolution.targets if item.status is RoutingAuthenticationStatus.UNKNOWN
    )
    if disabled:
        return RuleEvaluation(
            rule_id=rule_id,
            outcome=AssessmentOutcome.POTENTIAL_RISK,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            summary=f"{label} authentication is explicitly disabled on a participating interface.",
            impact=(
                "Routing control-plane exchanges on the identified interface may lack the "
                "configured peer-authentication protection expected by this check."
            ),
            recommendation=(
                f"Configure a supported strong {label} authentication mode and matching key "
                "material after validating peer compatibility."
            ),
            evidence=_target_references(disabled),
            limitations=_adverse_limitations(resolution),
        )
    if weak:
        return RuleEvaluation(
            rule_id=rule_id,
            outcome=AssessmentOutcome.HARDENING,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            summary=f"A weaker supported {label} authentication form is configured.",
            impact=(
                "The configured authentication form provides less protection than the "
                "stronger supported alternative."
            ),
            recommendation=(
                f"Migrate to the stronger supported {label} authentication form after "
                "coordinated peer validation."
            ),
            evidence=_target_references(weak),
            limitations=_adverse_limitations(resolution),
        )
    if resolution.unsupported or resolution.issues:
        return _unsupported(
            rule_id,
            f"Relevant syntax or interface inheritance prevents a complete {label} conclusion.",
            all_evidence,
        )
    if resolution.uncertain or unknown:
        return _unknown(
            rule_id,
            f"At least one participating interface or association lacks sufficient supported "
            f"{label} authentication evidence.",
            all_evidence,
        )
    return RuleEvaluation(
        rule_id=rule_id,
        outcome=AssessmentOutcome.SECURE,
        severity=None,
        confidence=Confidence.HIGH,
        summary=(
            f"Every supported non-passive {label} target has complete supported "
            "authentication configuration."
        ),
        impact=None,
        recommendation=None,
        evidence=_target_references(resolution.targets),
        limitations=_STATIC_LIMITATIONS,
    )


def _adverse_limitations(
    resolution: RoutingAuthenticationResolution,
) -> tuple[str, ...]:
    if resolution.unsupported or resolution.issues or resolution.uncertain:
        return (
            *_STATIC_LIMITATIONS,
            "Other relevant routing targets remain unresolved and were not treated as passing.",
        )
    return _STATIC_LIMITATIONS


def _has_protocol_auth_evidence(configuration: ParsedConfiguration, protocol: str) -> bool:
    prefixes = {
        "rip": ("routing.rip_",),
        "ospf": ("routing.ospf_",),
        "eigrp": ("routing.eigrp_",),
    }
    return any(item.kind.startswith(prefixes[protocol]) for item in configuration.observations)


def _resolution_evidence(
    resolution: RoutingAuthenticationResolution,
) -> tuple[EvidenceReference, ...]:
    evidence: list[RoutingEvidence] = [*resolution.processes, *resolution.unsupported]
    evidence.extend(resolution.uncertain)
    evidence.extend(resolution.context_evidence)
    for target in resolution.targets:
        evidence.extend(target.evidence)
    for issue in resolution.issues:
        evidence.extend(issue.evidence)
    return _references(tuple(evidence))


def _target_references(
    targets: tuple[ResolvedRoutingTarget, ...],
) -> tuple[EvidenceReference, ...]:
    return _references(tuple(item for target in targets for item in target.evidence))


def _references(items: tuple[RoutingEvidence, ...]) -> tuple[EvidenceReference, ...]:
    references: list[EvidenceReference] = []
    for item in items:
        observation = item.observation if isinstance(item, ResolvedInterfaceObservation) else item
        if isinstance(item, ResolvedInterfaceObservation) and item.origin_observation is not None:
            origin = EvidenceReference(
                observation_id=item.origin_observation.observation_id,
                source_command_ids=item.origin_observation.source_command_ids,
                target_interface=item.target_interface,
                resolution_origin=item.origin.value,
            )
            if origin not in references:
                references.append(origin)
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


def _unknown(rule_id: str, summary: str, evidence: tuple[EvidenceReference, ...]) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        outcome=AssessmentOutcome.UNKNOWN,
        severity=None,
        confidence=Confidence.LOW,
        summary=summary,
        impact=None,
        recommendation=None,
        evidence=evidence,
        limitations=(
            "No security conclusion was inferred from missing or unresolved routing evidence.",
        ),
    )


def _unsupported(
    rule_id: str, summary: str, evidence: tuple[EvidenceReference, ...]
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
        limitations=("Unsupported relevant syntax was not treated as secure or insecure.",),
    )


def _not_applicable(
    rule_id: str,
    summary: str,
    evidence: tuple[EvidenceReference, ...] = (),
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        outcome=AssessmentOutcome.NOT_APPLICABLE,
        severity=None,
        confidence=Confidence.HIGH,
        summary=summary,
        impact=None,
        recommendation=None,
        evidence=evidence,
    )
