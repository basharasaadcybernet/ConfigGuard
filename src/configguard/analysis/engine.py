"""Shared deterministic security analysis engine."""

from __future__ import annotations

from configguard.analysis.models import (
    AnalysisDiagnostic,
    AnalysisDiagnosticKind,
    AnalysisResult,
    Finding,
)
from configguard.analysis.registry import RuleRegistry
from configguard.domain import (
    AssessmentOutcome,
    Confidence,
    ParsedConfiguration,
    SourceLocation,
)
from configguard.rules.contracts import RuleEvaluation, SecurityRule
from configguard.sanitization.contracts import EvidenceSanitizer


class AnalysisEngine:
    """Evaluate structured observations and sanitize evidence centrally."""

    def __init__(self, registry: RuleRegistry, sanitizer: EvidenceSanitizer) -> None:
        self._registry = registry
        self._sanitizer = sanitizer

    def analyze(self, configuration: ParsedConfiguration) -> AnalysisResult:
        findings: list[Finding] = []
        diagnostics: list[AnalysisDiagnostic] = []
        for rule in self._registry:
            evaluation, diagnostic = self._evaluate_isolated(rule, configuration)
            if diagnostic is not None:
                diagnostics.append(diagnostic)
            finding, evidence_diagnostic = self._build_finding(
                rule,
                evaluation,
                configuration,
            )
            findings.append(finding)
            if evidence_diagnostic is not None:
                diagnostics.append(evidence_diagnostic)
        return AnalysisResult(
            parser_status=configuration.status,
            findings=tuple(findings),
            diagnostics=tuple(diagnostics),
        )

    def _evaluate_isolated(
        self,
        rule: SecurityRule,
        configuration: ParsedConfiguration,
    ) -> tuple[RuleEvaluation, AnalysisDiagnostic | None]:
        try:
            evaluation = rule.evaluate(configuration)
            if evaluation.rule_id != rule.metadata.rule_id:
                raise ValueError("rule result ID does not match registered metadata")
        except Exception:
            return (
                _not_evaluated(rule),
                AnalysisDiagnostic(
                    rule_id=rule.metadata.rule_id,
                    kind=AnalysisDiagnosticKind.RULE_FAILURE,
                    code="CG-ENGINE-RULE-FAILURE",
                    message="A rule could not be evaluated safely.",
                ),
            )
        return evaluation, None

    def _build_finding(
        self,
        rule: SecurityRule,
        evaluation: RuleEvaluation,
        configuration: ParsedConfiguration,
    ) -> tuple[Finding, AnalysisDiagnostic | None]:
        evidence_diagnostic: AnalysisDiagnostic | None = None
        try:
            sanitized_evidence = self._sanitizer.sanitize(configuration, evaluation.evidence)
        except Exception:
            evaluation = _not_evaluated(rule)
            sanitized_evidence = ()
            evidence_diagnostic = AnalysisDiagnostic(
                rule_id=rule.metadata.rule_id,
                kind=AnalysisDiagnosticKind.EVIDENCE_FAILURE,
                code="CG-ENGINE-EVIDENCE-FAILURE",
                message="Rule evidence could not be sanitized safely.",
            )

        locations: list[SourceLocation] = []
        for item in sanitized_evidence:
            if item.location not in locations:
                locations.append(item.location)
        source_locations = tuple(locations)

        return (
            Finding(
                rule_id=evaluation.rule_id,
                title=rule.metadata.title,
                category=rule.metadata.category,
                outcome=evaluation.outcome,
                severity=evaluation.severity,
                confidence=evaluation.confidence,
                description=evaluation.summary,
                evidence=sanitized_evidence,
                source_locations=source_locations,
                impact=evaluation.impact,
                recommendation=evaluation.recommendation,
                technical_references=evaluation.references,
                limitations=evaluation.limitations,
            ),
            evidence_diagnostic,
        )


def _not_evaluated(rule: SecurityRule) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule.metadata.rule_id,
        outcome=AssessmentOutcome.NOT_EVALUATED,
        severity=None,
        confidence=Confidence.LOW,
        summary="The rule could not be evaluated due to an internal operational error.",
        impact=None,
        recommendation=None,
        limitations=("No security conclusion was produced for this rule.",),
    )
