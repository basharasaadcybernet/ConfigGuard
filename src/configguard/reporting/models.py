"""Sanitized, deterministic assessment-report contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from configguard import __version__
from configguard.analysis import AnalysisResult, Finding
from configguard.domain import AssessmentOutcome, ParsedConfiguration, Severity
from configguard.parsing import ParserSupport

REPORT_SCHEMA_VERSION = "1.0.0"


class AssessmentStatus(StrEnum):
    """Overall execution completeness, independent of security outcomes."""

    COMPLETED = "completed"
    PARTIAL = "partial"


@dataclass(frozen=True, slots=True)
class OperationalDiagnostic:
    """One safe parser or analysis diagnostic for public reporting."""

    source: str
    code: str
    message: str
    rule_id: str | None = None
    line_start: int | None = None
    line_end: int | None = None

    def to_public_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "code": self.code,
            "message": self.message,
            "rule_id": self.rule_id,
            "line_start": self.line_start,
            "line_end": self.line_end,
        }


@dataclass(frozen=True, slots=True)
class AssessmentReport:
    """Public report model containing no raw configuration or private path."""

    assessment_status: AssessmentStatus
    source_basename: str = field(repr=False)
    platform_family: str
    platform_support: str
    platform_identification: str
    platform_confidence: float
    parser_name: str
    parser_version: str
    parser_status: str
    input_line_count: int
    command_count: int
    classified_command_count: int
    unsupported_command_count: int
    observation_count: int
    evaluated_rule_ids: tuple[str, ...]
    findings: tuple[Finding, ...]
    diagnostics: tuple[OperationalDiagnostic, ...]
    limitations: tuple[str, ...]

    def severity_summary(self) -> dict[str, int]:
        """Count adverse findings by qualitative severity."""

        return {
            severity.value: sum(finding.severity is severity for finding in self.findings)
            for severity in Severity
        }

    def outcome_summary(self) -> dict[str, int]:
        """Count all rule outcomes without conflating uncertainty with success."""

        return {
            outcome.value: sum(finding.outcome is outcome for finding in self.findings)
            for outcome in AssessmentOutcome
        }

    def to_public_dict(self) -> dict[str, object]:
        """Return the versioned JSON-compatible report representation."""

        return {
            "report_schema_version": REPORT_SCHEMA_VERSION,
            "configguard_version": __version__,
            "assessment_status": self.assessment_status.value,
            "platform": {
                "family": self.platform_family,
                "support": self.platform_support,
                "identification": self.platform_identification,
                "confidence": self.platform_confidence,
            },
            "parser": {
                "name": self.parser_name,
                "version": self.parser_version,
                "status": self.parser_status,
                "completeness": {
                    "input_line_count": self.input_line_count,
                    "command_count": self.command_count,
                    "classified_command_count": self.classified_command_count,
                    "unsupported_command_count": self.unsupported_command_count,
                    "observation_count": self.observation_count,
                },
            },
            "evaluated_rule_ids": list(self.evaluated_rule_ids),
            "severity_summary": self.severity_summary(),
            "outcome_summary": self.outcome_summary(),
            "findings": [finding.to_public_dict() for finding in self.findings],
            "assessment_limitations": list(self.limitations),
            "operational_diagnostics": [
                diagnostic.to_public_dict() for diagnostic in self.diagnostics
            ],
        }


_ASSESSMENT_LIMITATIONS = (
    "This is a static configuration assessment, not an exploitation test or verification "
    "of the device's runtime security.",
    "Only seventeen documented management-plane, SNMP, Layer 2, interface ACL, and routing "
    "authentication rules were evaluated.",
    "Configuration evidence cannot establish live reachability, topology, runtime defaults, "
    "software patch state, or compensating controls.",
    "No findings, or no confirmed weaknesses, must not be interpreted as proof that the "
    "device is secure.",
    "Reports contain minimized evidence but may still include sensitive operational metadata.",
)


def build_assessment_report(
    support: ParserSupport,
    configuration: ParsedConfiguration,
    analysis: AnalysisResult,
) -> AssessmentReport:
    """Build one sanitized report from existing parser and engine results."""

    uncertain_outcomes = {
        AssessmentOutcome.UNKNOWN,
        AssessmentOutcome.NOT_EVALUATED,
        AssessmentOutcome.UNSUPPORTED_SYNTAX,
    }
    partial = configuration.status.value != "parsed" or any(
        finding.outcome in uncertain_outcomes for finding in analysis.findings
    )

    parser_diagnostics = tuple(
        OperationalDiagnostic(
            source="parser",
            code=item.code,
            message=item.message,
            line_start=item.location.line_start if item.location is not None else None,
            line_end=item.location.line_end if item.location is not None else None,
        )
        for item in configuration.diagnostics
    )
    analysis_diagnostics = tuple(
        OperationalDiagnostic(
            source="analysis",
            code=item.code,
            message=item.message,
            rule_id=item.rule_id,
        )
        for item in analysis.diagnostics
    )

    return AssessmentReport(
        assessment_status=AssessmentStatus.PARTIAL if partial else AssessmentStatus.COMPLETED,
        source_basename=_safe_source_basename(configuration.source_label),
        platform_family=configuration.platform.value,
        platform_support="supported" if support.compatible else "unsupported",
        platform_identification=support.reason,
        platform_confidence=support.confidence,
        parser_name=configuration.parser_name,
        parser_version=configuration.parser_version,
        parser_status=configuration.status.value,
        input_line_count=configuration.metrics.input_line_count,
        command_count=configuration.metrics.command_count,
        classified_command_count=configuration.metrics.classified_command_count,
        unsupported_command_count=configuration.metrics.unsupported_command_count,
        observation_count=configuration.metrics.observation_count,
        evaluated_rule_ids=tuple(finding.rule_id for finding in analysis.findings),
        findings=analysis.findings,
        diagnostics=(*parser_diagnostics, *analysis_diagnostics),
        limitations=_ASSESSMENT_LIMITATIONS,
    )


def _safe_source_basename(label: str) -> str:
    basename = label.replace("\\", "/").rsplit("/", maxsplit=1)[-1]
    cleaned = "".join(
        character if character.isprintable() and character not in "\r\n\t" else "_"
        for character in basename
    )
    return (cleaned or "configuration")[:128]
