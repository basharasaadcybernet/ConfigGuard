"""Immutable public findings and operational diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from configguard.domain import (
    AssessmentOutcome,
    Confidence,
    ParseStatus,
    SanitizedEvidence,
    Severity,
    SourceLocation,
)
from configguard.rules.contracts import RuleCategory


class AnalysisDiagnosticKind(StrEnum):
    """Safe operational failures that are not security findings."""

    RULE_FAILURE = "rule_failure"
    EVIDENCE_FAILURE = "evidence_failure"
    CONTRACT_VIOLATION = "contract_violation"


@dataclass(frozen=True, slots=True)
class AnalysisDiagnostic:
    """A sanitized engine diagnostic with no exception or source content."""

    rule_id: str
    kind: AnalysisDiagnosticKind
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class Finding:
    """One rule's public, sanitized, explainable assessment result."""

    rule_id: str
    title: str
    category: RuleCategory
    outcome: AssessmentOutcome
    severity: Severity | None
    confidence: Confidence
    description: str
    evidence: tuple[SanitizedEvidence, ...]
    source_locations: tuple[SourceLocation, ...]
    impact: str | None
    recommendation: str | None
    technical_references: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_public_dict(self) -> dict[str, object]:
        """Return a JSON-compatible structure containing sanitized data only."""

        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category.value,
            "outcome": self.outcome.value,
            "severity": self.severity.value if self.severity is not None else None,
            "confidence": self.confidence.value,
            "description": self.description,
            "evidence": [
                {
                    "line_start": item.location.line_start,
                    "line_end": item.location.line_end,
                    "context": item.context.kind.value,
                    "context_identifier": item.context.identifier,
                    "excerpt": item.redacted_excerpt,
                    "target_interface": item.target_interface,
                    "resolution_origin": item.resolution_origin,
                }
                for item in self.evidence
            ],
            "source_locations": [
                {"line_start": item.line_start, "line_end": item.line_end}
                for item in self.source_locations
            ],
            "impact": self.impact,
            "recommendation": self.recommendation,
            "technical_references": list(self.technical_references),
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True, slots=True)
class AnalysisResult:
    """Deterministically ordered findings plus separate engine diagnostics."""

    parser_status: ParseStatus
    findings: tuple[Finding, ...]
    diagnostics: tuple[AnalysisDiagnostic, ...] = ()

    def to_public_dict(self) -> dict[str, object]:
        """Return a JSON-compatible, secret-free analysis representation."""

        return {
            "parser_status": self.parser_status.value,
            "findings": [finding.to_public_dict() for finding in self.findings],
            "diagnostics": [
                {
                    "rule_id": item.rule_id,
                    "kind": item.kind.value,
                    "code": item.code,
                    "message": item.message,
                }
                for item in self.diagnostics
            ],
        }
