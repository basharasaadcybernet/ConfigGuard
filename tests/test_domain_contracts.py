"""Architecture regression tests for ConfigGuard's Phase 1 contracts."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from configguard.domain import (
    AssessmentOutcome,
    CommandRecord,
    Confidence,
    ConfigurationContext,
    ContextKind,
    ParsedConfiguration,
    PlatformFamily,
    Severity,
    SourceLocation,
    StructuredObservation,
)
from configguard.parsing import ConfigurationParser, ConfigurationSource, ParserSupport
from configguard.rules import RuleCategory, RuleEvaluation, RuleMetadata, SecurityRule


class SyntheticParser:
    """Small contract double; it is not a production configuration parser."""

    name = "synthetic-test-parser"
    version = "0"

    def identify(self, source: ConfigurationSource) -> ParserSupport:
        return ParserSupport(PlatformFamily.CISCO_IOS, 1.0, f"synthetic: {source.label}")

    def parse(self, source: ConfigurationSource) -> ParsedConfiguration:
        command = CommandRecord(
            command_id="cmd-1",
            text=source.text,
            location=SourceLocation(1, 1),
            context=ConfigurationContext(ContextKind.GLOBAL),
        )
        observation = StructuredObservation.create(
            observation_id="obs-1",
            kind="test.synthetic",
            attributes={"present": True},
            source_command_ids=(command.command_id,),
        )
        return ParsedConfiguration(
            source_label=source.label,
            platform=PlatformFamily.CISCO_IOS,
            parser_name=self.name,
            parser_version=self.version,
            commands=(command,),
            observations=(observation,),
        )


class SyntheticRule:
    """Small contract double; it is not a ConfigGuard security check."""

    metadata = RuleMetadata(
        rule_id="TEST-001",
        title="Synthetic contract test",
        category=RuleCategory.DEVICE_HARDENING,
        description="Exercises the rule protocol only.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        return RuleEvaluation(
            rule_id=self.metadata.rule_id,
            outcome=AssessmentOutcome.NOT_EVALUATED,
            severity=None,
            confidence=Confidence.HIGH,
            summary=f"Contract only: {configuration.source_label}",
            impact=None,
            recommendation=None,
            limitations=("No security logic exists in Phase 1.",),
        )


def test_parser_and_rule_doubles_satisfy_runtime_protocols() -> None:
    parser = SyntheticParser()
    rule = SyntheticRule()

    assert isinstance(parser, ConfigurationParser)
    assert isinstance(rule, SecurityRule)

    configuration = parser.parse(ConfigurationSource("synthetic.txt", "hostname TEST-R1"))
    result = rule.evaluate(configuration)

    assert configuration.observation("obs-1") is not None
    assert result.outcome is AssessmentOutcome.NOT_EVALUATED


def test_observation_attributes_are_immutable() -> None:
    observation = StructuredObservation.create(
        observation_id="obs-1",
        kind="test.synthetic",
        attributes={"secret": "not-a-real-secret"},
    )

    with pytest.raises(TypeError):
        observation.attributes["secret"] = "changed"  # type: ignore[index]


def test_source_locations_reject_invalid_ranges() -> None:
    with pytest.raises(ValueError, match="one or greater"):
        SourceLocation(0, 1)

    with pytest.raises(ValueError, match="must not precede"):
        SourceLocation(2, 1)


def test_domain_records_are_frozen() -> None:
    location = SourceLocation(1, 1)

    with pytest.raises(FrozenInstanceError):
        location.line_start = 2  # type: ignore[misc]


def test_rule_evaluation_requires_severity_only_for_adverse_outcomes() -> None:
    with pytest.raises(ValueError, match="require a qualitative severity"):
        RuleEvaluation(
            rule_id="TEST-002",
            outcome=AssessmentOutcome.POTENTIAL_RISK,
            severity=None,
            confidence=Confidence.LOW,
            summary="Synthetic only.",
            impact=None,
            recommendation=None,
        )

    with pytest.raises(ValueError, match="must not carry"):
        RuleEvaluation(
            rule_id="TEST-003",
            outcome=AssessmentOutcome.UNKNOWN,
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            summary="Synthetic only.",
            impact=None,
            recommendation=None,
        )


def test_parser_confidence_is_bounded() -> None:
    with pytest.raises(ValueError, match="between"):
        ParserSupport(PlatformFamily.UNKNOWN, 1.1, "synthetic invalid confidence")
