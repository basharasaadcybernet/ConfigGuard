"""The five deterministic security checks approved for Phase 3."""

from __future__ import annotations

from configguard.domain import (
    AssessmentOutcome,
    Confidence,
    ContextKind,
    EvidenceReference,
    ParsedConfiguration,
    ParseStatus,
    Severity,
    StructuredObservation,
)
from configguard.rules.contracts import (
    RuleCategory,
    RuleEvaluation,
    RuleMetadata,
    SecurityRule,
)

_RFC_854 = "https://www.rfc-editor.org/rfc/rfc854"
_RFC_9110 = "https://www.rfc-editor.org/rfc/rfc9110"
_RFC_4253 = "https://www.rfc-editor.org/rfc/rfc4253"
_RFC_3414 = "https://www.rfc-editor.org/rfc/rfc3414"
_RFC_3415 = "https://www.rfc-editor.org/rfc/rfc3415"
_REACHABILITY_LIMITATION = (
    "Configuration evidence does not establish network reachability or Internet exposure."
)


class VtyTelnetRule:
    """Detect effective VTY ranges that explicitly permit Telnet."""

    metadata = RuleMetadata(
        rule_id="CG-MGMT-001",
        title="Insecure VTY transport",
        category=RuleCategory.MANAGEMENT_PLANE,
        description="Evaluates explicit inbound VTY transport configuration.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        declarations = tuple(
            item
            for item in _observations(configuration, "line.declaration")
            if _string(item, "line_type") == "vty"
        )
        transports = tuple(
            item
            for item in _observations(configuration, "line.transport")
            if _string(item, "direction") == "input"
        )
        evidence = _references(transports)

        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "The VTY transport state cannot be established from an incomplete configuration.",
                evidence,
            )
        if _has_unclassified_context(configuration, ContextKind.LINE):
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported line configuration prevents a reliable VTY transport conclusion.",
                evidence,
            )
        if not declarations:
            return _unknown(
                self.metadata.rule_id,
                "No supported VTY line declaration was available for evaluation.",
                (),
            )

        effective: dict[str, StructuredObservation] = {}
        for transport in transports:
            line = _string(transport, "line")
            if line is not None:
                effective[line] = transport

        telnet: list[StructuredObservation] = []
        uncertain: list[StructuredObservation] = []
        unsupported: list[StructuredObservation] = []
        for declaration in declarations:
            line = _line_identifier(declaration)
            effective_transport = effective.get(line)
            if effective_transport is None:
                uncertain.append(declaration)
                continue
            configured = _boolean(effective_transport, "configured")
            protocols = _strings(effective_transport, "protocols")
            if configured is False or not protocols:
                uncertain.append(effective_transport)
            elif "telnet" in protocols or "all" in protocols:
                telnet.append(effective_transport)
            elif protocols == ("none",) or set(protocols) <= {"ssh"}:
                continue
            else:
                unsupported.append(effective_transport)

        if telnet:
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.CONFIRMED_INSECURE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                summary="At least one VTY range explicitly permits Telnet management access.",
                impact=(
                    "Telnet does not protect management credentials or session traffic with "
                    "SSH-style encryption."
                ),
                recommendation=(
                    "Remove Telnet from every applicable VTY range, permit SSH only, and apply "
                    "least-privilege source restrictions."
                ),
                evidence=_references(tuple(telnet)),
                references=(_RFC_854,),
                limitations=(_REACHABILITY_LIMITATION,),
            )
        if unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "At least one VTY range uses an unsupported inbound transport value.",
                _references(tuple(unsupported)),
            )
        if uncertain:
            return _unknown(
                self.metadata.rule_id,
                "One or more VTY ranges depend on defaults or unsupported transport values.",
                _references(tuple(uncertain)),
            )
        return _secure(
            self.metadata.rule_id,
            "Every supported VTY range explicitly excludes Telnet inbound transport.",
            evidence,
            (_REACHABILITY_LIMITATION,),
        )


class PlaintextHttpManagementRule:
    """Resolve the last supported explicit state of the plaintext HTTP server."""

    metadata = RuleMetadata(
        rule_id="CG-MGMT-006",
        title="Plaintext HTTP management service",
        category=RuleCategory.MANAGEMENT_PLANE,
        description="Evaluates explicit ip http server enable and disable commands.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        observations = tuple(
            item
            for item in _observations(configuration, "management.http_setting")
            if _string(item, "setting") == "server"
        )
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "The effective HTTP service state cannot be established from incomplete input.",
                _references(observations),
            )
        if not observations:
            return _unknown(
                self.metadata.rule_id,
                "No explicit supported plaintext HTTP service state was observed.",
                (),
            )
        effective = observations[-1]
        enabled = _boolean(effective, "enabled")
        if enabled is True:
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.CONFIRMED_INSECURE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                summary="The effective supported configuration explicitly enables HTTP management.",
                impact=(
                    "Plaintext HTTP does not provide transport encryption for management traffic."
                ),
                recommendation=(
                    "Disable the plaintext HTTP server. If browser management is required, use "
                    "HTTPS with approved authentication and source restrictions."
                ),
                evidence=_references((effective,)),
                references=(_RFC_9110,),
                limitations=(_REACHABILITY_LIMITATION,),
            )
        if enabled is False:
            return _secure(
                self.metadata.rule_id,
                "The effective supported configuration explicitly disables plaintext HTTP.",
                _references((effective,)),
                (_REACHABILITY_LIMITATION,),
            )
        return _unknown(
            self.metadata.rule_id,
            "The explicit HTTP service state could not be interpreted safely.",
            _references((effective,)),
        )


class SshVersionOneRule:
    """Detect an explicit effective SSH protocol version 1 selection."""

    metadata = RuleMetadata(
        rule_id="CG-MGMT-002",
        title="SSH protocol version 1 configured",
        category=RuleCategory.MANAGEMENT_PLANE,
        description="Evaluates explicit ip ssh version configuration only.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        observations = tuple(
            item
            for item in _observations(configuration, "management.ssh_setting")
            if _string(item, "setting") == "version"
        )
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "The effective SSH version cannot be established from incomplete input.",
                _references(observations),
            )
        if not observations:
            return _unknown(
                self.metadata.rule_id,
                "No explicit supported SSH protocol version selection was observed.",
                (),
            )
        effective = observations[-1]
        if _boolean(effective, "configured") is False:
            return _unknown(
                self.metadata.rule_id,
                "The SSH version command is negated, so behavior depends on platform defaults.",
                _references((effective,)),
            )
        arguments = _strings(effective, "arguments")
        if arguments == ("1",):
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.CONFIRMED_INSECURE,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                summary="The effective supported configuration explicitly selects SSH version 1.",
                impact="SSH version 1 is obsolete and does not provide SSHv2 security properties.",
                recommendation=(
                    "Configure SSH version 2 and validate supported cryptographic algorithms "
                    "against the organization's device baseline."
                ),
                evidence=_references((effective,)),
                references=(_RFC_4253,),
                limitations=(
                    "The version command alone does not prove that the SSH service is reachable.",
                ),
            )
        if arguments == ("2",):
            return _secure(
                self.metadata.rule_id,
                "The effective supported configuration explicitly selects SSH version 2.",
                _references((effective,)),
                ("This rule does not evaluate SSH service reachability, keys, or algorithms.",),
            )
        return _unsupported(
            self.metadata.rule_id,
            "The explicit SSH version value is unsupported by this rule.",
            _references((effective,)),
        )


class SnmpCommunityConfigurationRule:
    """Identify effective SNMP community-based management configuration."""

    metadata = RuleMetadata(
        rule_id="CG-SNMP-001",
        title="SNMP community-based management configured",
        category=RuleCategory.SNMP,
        description="Evaluates effective supported SNMP community declarations.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        effective = _effective_communities(configuration)
        evidence = _references(tuple(effective.values()))
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "SNMP community state cannot be established from incomplete input.",
                evidence,
            )
        active = tuple(item for item in effective.values() if _boolean(item, "configured") is True)
        if not active:
            if _has_unclassified_context(configuration, ContextKind.GLOBAL):
                return _unsupported(
                    self.metadata.rule_id,
                    "Unsupported global syntax prevents a complete SNMP community conclusion.",
                    (),
                )
            return _not_applicable(
                self.metadata.rule_id,
                "No effective supported SNMP community declaration was observed.",
            )

        has_write = any(_string(item, "access_mode") == "rw" for item in active)
        severity = Severity.MEDIUM if has_write else Severity.LOW
        modes = tuple(sorted({_string(item, "access_mode") or "unknown" for item in active}))
        return RuleEvaluation(
            rule_id=self.metadata.rule_id,
            outcome=AssessmentOutcome.POTENTIAL_RISK,
            severity=severity,
            confidence=Confidence.HIGH,
            summary=(
                "The configuration contains effective SNMP community-based management "
                f"declarations with observed modes: {', '.join(modes)}."
            ),
            impact=(
                "Community-based SNMP does not provide the authenticated and private user-based "
                "security model available in SNMPv3."
            ),
            recommendation=(
                "Migrate to an approved SNMPv3 authentication/privacy design; during migration, "
                "restrict sources and use read-only access wherever possible."
            ),
            evidence=_references(active),
            references=(_RFC_3414,),
            limitations=(_REACHABILITY_LIMITATION,),
        )


class SnmpCommunityAccessRestrictionRule:
    """Assess explicit SNMP community ACL references without topology claims."""

    metadata = RuleMetadata(
        rule_id="CG-SNMP-002",
        title="SNMP community source restriction",
        category=RuleCategory.SNMP,
        description="Checks supported community declarations for resolvable ACL references.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        effective = _effective_communities(configuration)
        active = tuple(item for item in effective.values() if _boolean(item, "configured") is True)
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "SNMP restriction state cannot be established from incomplete input.",
                _references(active),
            )
        if not active:
            return _not_applicable(
                self.metadata.rule_id,
                "No effective supported SNMP community requires source-restriction evaluation.",
            )
        if any(_string(item, "access_mode") not in {"ro", "rw"} for item in active):
            return _unsupported(
                self.metadata.rule_id,
                "At least one community declaration has unsupported permission syntax.",
                _references(active),
            )

        acl_observations = tuple(
            item
            for item in configuration.observations
            if item.kind in {"acl.definition", "acl.entry"}
        )
        acl_names = {
            name
            for item in acl_observations
            if (name := _string(item, "name") or _string(item, "access_list")) is not None
        }
        missing = tuple(item for item in active if _string(item, "access_list") is None)
        unresolved = tuple(
            item
            for item in active
            if (reference := _string(item, "access_list")) is not None
            and reference not in acl_names
        )
        if unresolved:
            return _unknown(
                self.metadata.rule_id,
                "At least one SNMP community references an ACL not present in the parsed input.",
                _references(unresolved),
            )
        if missing:
            has_write = any(_string(item, "access_mode") == "rw" for item in missing)
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.POTENTIAL_RISK,
                severity=Severity.MEDIUM if has_write else Severity.LOW,
                confidence=Confidence.HIGH,
                summary=(
                    "At least one effective SNMP community has no supported source ACL reference."
                ),
                impact=(
                    "The configuration does not show a community-specific source-address "
                    "restriction; actual reachability may still be constrained elsewhere."
                ),
                recommendation=(
                    "Attach a least-privilege source ACL to each retained community and prefer "
                    "migration to authenticated, private SNMPv3 management."
                ),
                evidence=_references(missing),
                references=(_RFC_3415,),
                limitations=(
                    "This rule does not evaluate topology, ACL reachability, or external controls.",
                ),
            )

        referenced_names = {
            reference for item in active if (reference := _string(item, "access_list")) is not None
        }
        matching_acl_evidence = tuple(
            item
            for item in acl_observations
            if (_string(item, "name") or _string(item, "access_list")) in referenced_names
        )
        return _secure(
            self.metadata.rule_id,
            "Every effective supported SNMP community references an ACL present in the input.",
            _references((*active, *matching_acl_evidence)),
            ("ACL presence does not prove effective reachability, correctness, or topology.",),
        )


def initial_rules() -> tuple[SecurityRule, ...]:
    """Return exactly the five Phase 3 rules in deterministic product order."""

    return (
        VtyTelnetRule(),
        PlaintextHttpManagementRule(),
        SshVersionOneRule(),
        SnmpCommunityConfigurationRule(),
        SnmpCommunityAccessRestrictionRule(),
    )


def _observations(
    configuration: ParsedConfiguration,
    kind: str,
) -> tuple[StructuredObservation, ...]:
    return tuple(item for item in configuration.observations if item.kind == kind)


def _string(observation: StructuredObservation, key: str) -> str | None:
    value = observation.attributes.get(key)
    return value if isinstance(value, str) else None


def _strings(observation: StructuredObservation, key: str) -> tuple[str, ...]:
    value = observation.attributes.get(key)
    return value if isinstance(value, tuple) else ()


def _boolean(observation: StructuredObservation, key: str) -> bool | None:
    value = observation.attributes.get(key)
    return value if isinstance(value, bool) else None


def _line_identifier(observation: StructuredObservation) -> str:
    line_type = _string(observation, "line_type") or "vty"
    line_range = _strings(observation, "range")
    return " ".join((line_type, *line_range))


def _references(observations: tuple[StructuredObservation, ...]) -> tuple[EvidenceReference, ...]:
    return tuple(
        EvidenceReference(
            observation_id=item.observation_id,
            source_command_ids=item.source_command_ids,
        )
        for item in observations
    )


def _has_unclassified_context(
    configuration: ParsedConfiguration,
    context_kind: ContextKind,
) -> bool:
    return any(
        item.kind == "command.unclassified" and _string(item, "context_kind") == context_kind.value
        for item in configuration.observations
    )


def _effective_communities(
    configuration: ParsedConfiguration,
) -> dict[str, StructuredObservation]:
    effective: dict[str, StructuredObservation] = {}
    for item in _observations(configuration, "snmp.community"):
        community_id = _string(item, "community_id")
        if community_id is not None:
            effective[community_id] = item
    return effective


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
        limitations=("No security conclusion was inferred from insufficient evidence.",),
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
        limitations=("Unsupported syntax was not treated as secure.",),
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
