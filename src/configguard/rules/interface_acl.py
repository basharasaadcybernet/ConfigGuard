"""Conservative IPv4 ACL checks for explicit interface attachments."""

from __future__ import annotations

from configguard.analysis.acl_resolution import (
    AclPermitBreadth,
    AclPolicyStatus,
    resolve_ipv4_interface_acls,
)
from configguard.analysis.interface_resolution import (
    InterfaceResolutionIssue,
    ResolvedInterfaceObservation,
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

type AclEvidence = StructuredObservation | ResolvedInterfaceObservation

_STATIC_LIMITATION = (
    "Static ACL structure does not establish interface runtime state, topology, NAT behavior, "
    "routing, upstream controls, or end-to-end reachability."
)


class BroadInterfaceAclPermissionRule:
    """Assess reachable broad permits in supported interface IPv4 ACLs."""

    metadata = RuleMetadata(
        rule_id="CG-ACL-001",
        title="Broad permissions in interface IPv4 ACLs",
        category=RuleCategory.NETWORK_ACCESS,
        description=(
            "Evaluates supported broad permit entries in IPv4 ACLs explicitly attached to "
            "interfaces."
        ),
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        resolution = resolve_ipv4_interface_acls(configuration)
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "Interface ACL permissions cannot be established from incomplete input.",
                _references(resolution.attachments),
            )
        if not resolution.attachments:
            if resolution.issues:
                return _issue_evaluation(self.metadata.rule_id, resolution.issues)
            return _not_applicable(
                self.metadata.rule_id,
                "No effective supported IPv4 ACL is explicitly attached to an interface.",
            )

        potential: list[AclEvidence] = []
        hardening: list[AclEvidence] = []
        unsupported: list[AclEvidence] = []
        uncertain: list[AclEvidence] = []
        passing: list[AclEvidence] = []
        for attachment in resolution.attachments:
            name = _attachment_name(attachment)
            policy = resolution.policy(name) if name is not None else None
            if policy is None:
                _append_unique(uncertain, attachment)
                continue
            if policy.status is AclPolicyStatus.UNSUPPORTED:
                _append_unique(unsupported, attachment)
                for item in policy.unsupported_evidence:
                    _append_unique(unsupported, item)
                continue
            if policy.status is AclPolicyStatus.EMPTY:
                _append_unique(uncertain, attachment)
                if policy.definition is not None:
                    _append_unique(uncertain, policy.definition)
                continue

            broad = policy.broad_permits()
            if not broad:
                _append_unique(passing, attachment)
                if policy.definition is not None:
                    _append_unique(passing, policy.definition)
                continue
            direction = _attachment_direction(attachment)
            for entry, breadth in broad:
                target = (
                    potential
                    if breadth is AclPermitBreadth.UNIVERSAL and direction == "in"
                    else hardening
                )
                _append_unique(target, attachment)
                _append_unique(target, entry.observation)

        adverse_limitations: tuple[str, ...] = (_STATIC_LIMITATION,)
        if unsupported or uncertain or resolution.issues:
            adverse_limitations += (
                "Other effective attachments or relationships remain unresolved and were "
                "not treated as passing.",
            )
        if potential:
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.POTENTIAL_RISK,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                summary=(
                    "A supported inbound interface IPv4 ACL has a reachable universal permit "
                    "for remaining traffic."
                ),
                impact=(
                    "The applied filter may admit a broad set of inbound traffic, but static "
                    "configuration does not establish exposure or business intent."
                ),
                recommendation=(
                    "Validate the interface trust boundary and narrow the permit to approved "
                    "protocols, sources, and destinations without disrupting required traffic."
                ),
                evidence=_references(tuple((*potential, *hardening))),
                limitations=adverse_limitations,
            )
        if hardening:
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.HARDENING,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                summary=(
                    "A supported interface IPv4 ACL has a reachable protocol-wide or outbound "
                    "broad permit for remaining traffic."
                ),
                impact=(
                    "The entry is broad within its direction or protocol, while topology and "
                    "the intended traffic policy remain unknown."
                ),
                recommendation=(
                    "Confirm the required traffic scope and replace broad remaining permits "
                    "with documented least-privilege entries where appropriate."
                ),
                evidence=_references(tuple(hardening)),
                limitations=adverse_limitations,
            )
        if unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "A referenced interface IPv4 ACL contains unsupported relevant syntax.",
                _references(tuple(unsupported)),
            )
        if resolution.issues:
            return _issue_evaluation(self.metadata.rule_id, resolution.issues)
        if uncertain:
            return _unknown(
                self.metadata.rule_id,
                "An interface ACL reference is missing or has no supported evaluable entries.",
                _references(tuple(uncertain)),
            )
        return RuleEvaluation(
            rule_id=self.metadata.rule_id,
            outcome=AssessmentOutcome.SECURE,
            severity=None,
            confidence=Confidence.HIGH,
            summary=(
                "No reachable broad permit was identified in the fully supported IPv4 ACLs "
                "explicitly attached to interfaces."
            ),
            impact=None,
            recommendation=None,
            evidence=_references(tuple(passing)),
            limitations=(
                _STATIC_LIMITATION,
                "This result covers only the documented supported ACL syntax subset.",
            ),
        )


class InterfaceAclReferenceIntegrityRule:
    """Assess whether effective interface IPv4 ACL references can be evaluated."""

    metadata = RuleMetadata(
        rule_id="CG-ACL-002",
        title="Interface IPv4 ACL reference integrity",
        category=RuleCategory.NETWORK_ACCESS,
        description="Checks effective interface IPv4 ACL attachments and referenced policies.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        resolution = resolve_ipv4_interface_acls(configuration)
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "Interface ACL reference integrity cannot be established from incomplete input.",
                _references(resolution.attachments),
            )
        if not resolution.attachments:
            if resolution.issues:
                return _issue_evaluation(self.metadata.rule_id, resolution.issues)
            return _not_applicable(
                self.metadata.rule_id,
                "No effective supported IPv4 ACL is explicitly attached to an interface.",
            )

        unsupported: list[AclEvidence] = []
        unresolved: list[AclEvidence] = []
        passing: list[AclEvidence] = []
        for attachment in resolution.attachments:
            name = _attachment_name(attachment)
            policy = resolution.policy(name) if name is not None else None
            if policy is None:
                _append_unique(unresolved, attachment)
                continue
            if policy.status is AclPolicyStatus.UNSUPPORTED:
                _append_unique(unsupported, attachment)
                for item in policy.unsupported_evidence:
                    _append_unique(unsupported, item)
                continue
            if policy.status is AclPolicyStatus.EMPTY:
                _append_unique(unresolved, attachment)
                if policy.definition is not None:
                    _append_unique(unresolved, policy.definition)
                continue
            _append_unique(passing, attachment)
            if policy.definition is not None:
                _append_unique(passing, policy.definition)

        if unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "A referenced interface IPv4 ACL contains unsupported relevant syntax.",
                _references(tuple(unsupported)),
            )
        if resolution.issues:
            return _issue_evaluation(self.metadata.rule_id, resolution.issues)
        if unresolved:
            return _unknown(
                self.metadata.rule_id,
                "An effective interface IPv4 ACL reference is absent or not evaluable.",
                _references(tuple(unresolved)),
            )
        return RuleEvaluation(
            rule_id=self.metadata.rule_id,
            outcome=AssessmentOutcome.SECURE,
            severity=None,
            confidence=Confidence.HIGH,
            summary=(
                "Every effective supported interface IPv4 ACL attachment references a present, "
                "fully evaluated policy."
            ),
            impact=None,
            recommendation=None,
            evidence=_references(tuple(passing)),
            limitations=(
                "Reference integrity does not assert that the ACL policy is appropriate or "
                "operationally enforced.",
                _STATIC_LIMITATION,
            ),
        )


def interface_acl_rules() -> tuple[
    BroadInterfaceAclPermissionRule,
    InterfaceAclReferenceIntegrityRule,
]:
    """Return the two interface ACL rules approved for Phase 7A."""

    return BroadInterfaceAclPermissionRule(), InterfaceAclReferenceIntegrityRule()


def _attachment_name(item: ResolvedInterfaceObservation) -> str | None:
    return _string(item.observation, "access_list")


def _attachment_direction(item: ResolvedInterfaceObservation) -> str | None:
    return _string(item.observation, "direction")


def _append_unique(items: list[AclEvidence], item: AclEvidence) -> None:
    if item not in items:
        items.append(item)


def _references(items: tuple[AclEvidence, ...]) -> tuple[EvidenceReference, ...]:
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


def _issue_evaluation(
    rule_id: str,
    issues: tuple[InterfaceResolutionIssue, ...],
) -> RuleEvaluation:
    evidence: list[AclEvidence] = []
    reasons: list[str] = []
    for issue in issues:
        if issue.reason not in reasons:
            reasons.append(issue.reason)
        for item in issue.evidence:
            _append_unique(evidence, item)
    summary = " ".join(reasons[:2])
    if len(reasons) > 2:
        summary += " Additional unresolved relationships exist."
    if any(issue.unsupported_syntax for issue in issues):
        return _unsupported(rule_id, summary, _references(tuple(evidence)))
    return _unknown(rule_id, summary, _references(tuple(evidence)))


def _string(observation: StructuredObservation, key: str) -> str | None:
    value = observation.attributes.get(key)
    return value if isinstance(value, str) else None


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
        limitations=("Insufficient evidence was not interpreted as secure or vulnerable.",),
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
        limitations=("Relevant unsupported ACL syntax was not treated as a security result.",),
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
