"""Deterministic security-rule interfaces and result contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from configguard.domain import (
    AssessmentOutcome,
    Confidence,
    EvidenceReference,
    ParsedConfiguration,
    Severity,
)


class RuleCategory(StrEnum):
    """Initial security-check catalog categories."""

    MANAGEMENT_PLANE = "management_plane"
    SNMP = "snmp"
    NETWORK_ACCESS = "network_access"
    LAYER_2 = "layer_2"
    ROUTING_PROTOCOL = "routing_protocol"
    DEVICE_HARDENING = "device_hardening"


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    """Stable rule identity and human-readable purpose."""

    rule_id: str
    title: str
    category: RuleCategory
    description: str


@dataclass(frozen=True, slots=True)
class RuleEvaluation:
    """One rule's explainable conclusion before evidence is rendered."""

    rule_id: str
    outcome: AssessmentOutcome
    severity: Severity | None
    confidence: Confidence
    summary: str
    impact: str | None
    recommendation: str | None
    evidence: tuple[EvidenceReference, ...] = ()
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        adverse = {
            AssessmentOutcome.CONFIRMED_INSECURE,
            AssessmentOutcome.POTENTIAL_RISK,
            AssessmentOutcome.HARDENING,
        }
        if self.outcome in adverse and self.severity is None:
            raise ValueError("adverse outcomes require a qualitative severity")
        if self.outcome not in adverse and self.severity is not None:
            raise ValueError("non-adverse outcomes must not carry a severity")


@runtime_checkable
class SecurityRule(Protocol):
    """A deterministic rule operating only on the parser's representation."""

    @property
    def metadata(self) -> RuleMetadata:
        """Return immutable rule metadata."""
        ...

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        """Evaluate structured configuration without file or network access."""
        ...
