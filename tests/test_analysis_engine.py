"""Registry, failure isolation, public model, and engine-boundary tests."""

from __future__ import annotations

import json

import pytest

from configguard.analysis import (
    AnalysisEngine,
    DuplicateRuleError,
    RuleRegistry,
    default_analysis_engine,
    default_rule_registry,
)
from configguard.domain import AssessmentOutcome, Confidence, ParsedConfiguration
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource
from configguard.rules import RuleCategory, RuleEvaluation, RuleMetadata, VtyTelnetRule
from configguard.sanitization import CiscoEvidenceSanitizer


def _parsed() -> ParsedConfiguration:
    return CiscoConfigurationParser().parse(
        ConfigurationSource(
            "synthetic.txt",
            "version 15.7\n"
            "hostname TEST\n"
            "interface Loopback0\n"
            " description TEST\n"
            "!\n"
            "line vty 0 4\n"
            " transport input ssh\n"
            "end\n",
        )
    )


class ExplodingRule:
    metadata = RuleMetadata(
        rule_id="TEST-FAILURE",
        title="Synthetic failure",
        category=RuleCategory.DEVICE_HARDENING,
        description="Exercises safe failure isolation.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        del configuration
        raise RuntimeError("SYNTHETIC-RULE-EXCEPTION-SECRET")


class ExplodingSanitizer:
    def sanitize(self, configuration: object, references: object) -> tuple[()]:
        del configuration, references
        raise RuntimeError("SYNTHETIC-SANITIZER-EXCEPTION-SECRET")


def test_default_registry_contains_exactly_eleven_unique_rules_in_order() -> None:
    registry = default_rule_registry()

    assert len(registry) == 11
    assert [rule.metadata.rule_id for rule in registry] == [
        "CG-MGMT-001",
        "CG-MGMT-006",
        "CG-MGMT-002",
        "CG-SNMP-001",
        "CG-SNMP-002",
        "CG-MGMT-003",
        "CG-MGMT-005",
        "CG-MGMT-004",
        "CG-L2-001",
        "CG-L2-002",
        "CG-L2-004",
    ]


def test_duplicate_registration_is_rejected() -> None:
    with pytest.raises(DuplicateRuleError, match="CG-MGMT-001"):
        RuleRegistry((VtyTelnetRule(), VtyTelnetRule()))


def test_rule_failure_is_isolated_and_exception_details_are_not_public() -> None:
    engine = AnalysisEngine(
        RuleRegistry((ExplodingRule(), VtyTelnetRule())),
        CiscoEvidenceSanitizer(),
    )

    result = engine.analyze(_parsed())
    public = json.dumps(result.to_public_dict(), sort_keys=True)

    assert result.findings[0].outcome is AssessmentOutcome.NOT_EVALUATED
    assert result.findings[0].severity is None
    assert result.findings[1].outcome is AssessmentOutcome.SECURE
    assert len(result.diagnostics) == 1
    assert "SYNTHETIC-RULE-EXCEPTION-SECRET" not in repr(result)
    assert "SYNTHETIC-RULE-EXCEPTION-SECRET" not in public


def test_evidence_failure_is_not_misrepresented_as_security_finding() -> None:
    engine = AnalysisEngine(RuleRegistry((VtyTelnetRule(),)), ExplodingSanitizer())

    result = engine.analyze(_parsed())
    public = json.dumps(result.to_public_dict(), sort_keys=True)

    assert result.findings[0].outcome is AssessmentOutcome.NOT_EVALUATED
    assert result.findings[0].confidence is Confidence.LOW
    assert result.findings[0].evidence == ()
    assert len(result.diagnostics) == 1
    assert "SYNTHETIC-SANITIZER-EXCEPTION-SECRET" not in repr(result)
    assert "SYNTHETIC-SANITIZER-EXCEPTION-SECRET" not in public


def test_public_finding_model_contains_only_sanitized_evidence() -> None:
    secret = "SYNTHETIC-PUBLIC-MODEL-COMMUNITY"
    parsed = CiscoConfigurationParser().parse(
        ConfigurationSource(
            "synthetic.txt",
            "version 15.7\n"
            "hostname TEST\n"
            "interface Loopback0\n"
            " description TEST\n"
            "!\n"
            f"snmp-server community {secret} RW\n"
            "end\n",
        )
    )

    result = default_analysis_engine().analyze(parsed)
    public = json.dumps(result.to_public_dict(), sort_keys=True)

    assert secret not in repr(result)
    assert secret not in public
    assert "[REDACTED]" in public
    assert "technical_references" in public
