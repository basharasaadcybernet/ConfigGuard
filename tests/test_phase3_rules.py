"""Focused synthetic tests for the five approved Phase 3 rules."""

from __future__ import annotations

import json

import pytest

from configguard.analysis import AnalysisResult, default_analysis_engine
from configguard.domain import AssessmentOutcome, Severity
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource


def _configuration(*commands: str) -> str:
    return "\n".join(
        (
            "version 15.7",
            "hostname TEST-DEVICE",
            "interface Loopback0",
            " description SYNTHETIC",
            "!",
            *commands,
            "end",
        )
    )


def _analyze(text: str) -> AnalysisResult:
    parsed = CiscoConfigurationParser().parse(ConfigurationSource("synthetic.txt", text))
    return default_analysis_engine().analyze(parsed)


def _finding(result: AnalysisResult, rule_id: str):  # type: ignore[no-untyped-def]
    return next(item for item in result.findings if item.rule_id == rule_id)


@pytest.mark.parametrize("transport", ["telnet", "all"])
def test_telnet_rule_detects_only_effective_vty_transport(transport: str) -> None:
    result = _analyze(
        _configuration(
            "line vty 0 4",
            f" transport input {transport}",
        )
    )
    finding = _finding(result, "CG-MGMT-001")

    assert finding.outcome is AssessmentOutcome.CONFIRMED_INSECURE
    assert finding.severity is Severity.HIGH
    assert finding.confidence.value == "high"
    assert finding.evidence[0].context.identifier == "vty 0 4"


@pytest.mark.parametrize("transport", ["ssh", "none"])
def test_telnet_rule_accepts_explicit_ssh_only_or_disabled_transport(transport: str) -> None:
    result = _analyze(
        _configuration(
            "line vty 0 4",
            f" transport input {transport}",
        )
    )

    assert _finding(result, "CG-MGMT-001").outcome is AssessmentOutcome.SECURE


def test_telnet_rule_handles_multiple_ranges_and_ignores_unrelated_word() -> None:
    result = _analyze(
        _configuration(
            "interface GigabitEthernet0/0",
            " description TELNET-LABEL-ONLY",
            "!",
            "line vty 0 4",
            " transport input ssh",
            "!",
            "line vty 5 15",
            " transport input all",
        )
    )
    finding = _finding(result, "CG-MGMT-001")

    assert finding.outcome is AssessmentOutcome.CONFIRMED_INSECURE
    assert len(finding.evidence) == 1
    assert finding.evidence[0].context.identifier == "vty 5 15"


def test_telnet_rule_resolves_overlapping_vty_ranges_in_source_order() -> None:
    later_broad_secure = _analyze(
        _configuration(
            "line vty 0 4",
            " transport input telnet",
            "!",
            "line vty 0 15",
            " transport input ssh",
        )
    )
    later_narrow_telnet = _analyze(
        _configuration(
            "line vty 0 15",
            " transport input ssh",
            "!",
            "line vty 0 4",
            " transport input telnet",
        )
    )

    assert _finding(later_broad_secure, "CG-MGMT-001").outcome is AssessmentOutcome.SECURE
    assert (
        _finding(later_narrow_telnet, "CG-MGMT-001").outcome is AssessmentOutcome.CONFIRMED_INSECURE
    )


def test_telnet_rule_resolves_repeated_commands_and_missing_defaults() -> None:
    disabled = _analyze(
        _configuration(
            "line vty 0 4",
            " transport input telnet",
            " transport input ssh",
        )
    )
    missing = _analyze(_configuration("line vty 0 4", " login local"))
    reset = _analyze(
        _configuration(
            "line vty 0 4",
            " transport input telnet",
            " no transport input",
        )
    )
    unsupported = _analyze(
        _configuration(
            "line vty 0 4",
            " transport input ssh synthetic-protocol",
        )
    )

    assert _finding(disabled, "CG-MGMT-001").outcome is AssessmentOutcome.SECURE
    assert _finding(missing, "CG-MGMT-001").outcome is AssessmentOutcome.UNKNOWN
    assert _finding(reset, "CG-MGMT-001").outcome is AssessmentOutcome.UNKNOWN
    assert _finding(unsupported, "CG-MGMT-001").outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX


def test_http_rule_resolves_enable_disable_and_does_not_confuse_https() -> None:
    enabled = _analyze(_configuration("ip http server"))
    disabled = _analyze(_configuration("ip http server", "no ip http server"))
    https_only = _analyze(_configuration("ip http secure-server"))
    reenabled = _analyze(_configuration("no ip http server", "ip http server"))

    assert _finding(enabled, "CG-MGMT-006").outcome is AssessmentOutcome.CONFIRMED_INSECURE
    assert _finding(enabled, "CG-MGMT-006").severity is Severity.HIGH
    assert _finding(disabled, "CG-MGMT-006").outcome is AssessmentOutcome.SECURE
    assert _finding(https_only, "CG-MGMT-006").outcome is AssessmentOutcome.UNKNOWN
    assert _finding(reenabled, "CG-MGMT-006").outcome is AssessmentOutcome.CONFIRMED_INSECURE


def test_ssh_rule_handles_v1_v2_missing_reset_and_repetition() -> None:
    version_one = _analyze(_configuration("ip ssh version 1"))
    version_two = _analyze(_configuration("ip ssh version 2"))
    missing = _analyze(_configuration("ip domain name synthetic.example"))
    reset = _analyze(_configuration("ip ssh version 1", "no ip ssh version"))
    repeated = _analyze(_configuration("ip ssh version 1", "ip ssh version 2"))

    assert _finding(version_one, "CG-MGMT-002").outcome is AssessmentOutcome.CONFIRMED_INSECURE
    assert _finding(version_one, "CG-MGMT-002").severity is Severity.MEDIUM
    assert _finding(version_two, "CG-MGMT-002").outcome is AssessmentOutcome.SECURE
    assert _finding(missing, "CG-MGMT-002").outcome is AssessmentOutcome.UNKNOWN
    assert _finding(reset, "CG-MGMT-002").outcome is AssessmentOutcome.UNKNOWN
    assert _finding(repeated, "CG-MGMT-002").outcome is AssessmentOutcome.SECURE


@pytest.mark.parametrize(
    ("mode", "expected_severity"),
    [("RO", Severity.LOW), ("RW", Severity.MEDIUM)],
)
def test_snmp_community_rule_distinguishes_ro_and_rw(
    mode: str,
    expected_severity: Severity,
) -> None:
    result = _analyze(_configuration(f"snmp-server community SYNTHETIC-COMMUNITY-{mode} {mode}"))
    finding = _finding(result, "CG-SNMP-001")

    assert finding.outcome is AssessmentOutcome.POTENTIAL_RISK
    assert finding.severity is expected_severity
    assert "SYNTHETIC-COMMUNITY" not in repr(result)
    assert "[REDACTED]" in finding.evidence[0].redacted_excerpt


def test_removed_snmp_community_is_not_applicable_and_never_serializes_secret() -> None:
    secret = "SYNTHETIC-REMOVED-COMMUNITY"
    result = _analyze(
        _configuration(
            f"snmp-server community {secret} RO",
            f"no snmp-server community {secret}",
        )
    )
    serialized = json.dumps(result.to_public_dict(), sort_keys=True)

    assert _finding(result, "CG-SNMP-001").outcome is AssessmentOutcome.NOT_APPLICABLE
    assert _finding(result, "CG-SNMP-002").outcome is AssessmentOutcome.NOT_APPLICABLE
    assert secret not in repr(result)
    assert secret not in serialized


def test_unrelated_unsupported_syntax_does_not_invalidate_rule_conclusions() -> None:
    result = _analyze(
        _configuration(
            "synthetic-global-setting enabled",
            "line vty 0 4",
            " transport input ssh",
            " synthetic-line-setting enabled",
        )
    )

    assert result.parser_status.value == "partial"
    assert _finding(result, "CG-MGMT-001").outcome is AssessmentOutcome.SECURE
    assert _finding(result, "CG-SNMP-001").outcome is AssessmentOutcome.NOT_APPLICABLE
    assert _finding(result, "CG-SNMP-002").outcome is AssessmentOutcome.NOT_APPLICABLE
    assert all(
        finding.outcome
        not in {AssessmentOutcome.CONFIRMED_INSECURE, AssessmentOutcome.POTENTIAL_RISK}
        for finding in result.findings
    )


def test_rule_relevant_unsupported_syntax_cannot_create_false_secure_or_na() -> None:
    malformed_transport = _analyze(
        _configuration(
            "line vty 0 4",
            " transport input ssh",
            " transport",
        )
    )
    malformed_community = _analyze(_configuration("snmp-server community"))

    assert (
        _finding(malformed_transport, "CG-MGMT-001").outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX
    )
    assert (
        _finding(malformed_community, "CG-SNMP-001").outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX
    )
    assert (
        _finding(malformed_community, "CG-SNMP-002").outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX
    )


def test_snmp_restriction_requires_acl_on_the_same_community() -> None:
    unrestricted = _analyze(
        _configuration(
            "access-list 10 permit 192.0.2.0 0.0.0.255",
            "snmp-server community SYNTHETIC-UNRESTRICTED RO",
        )
    )
    restricted = _analyze(
        _configuration(
            "access-list 10 permit 192.0.2.0 0.0.0.255",
            "snmp-server community SYNTHETIC-RESTRICTED RO 10",
        )
    )
    unresolved = _analyze(_configuration("snmp-server community SYNTHETIC-MISSING-ACL RW 99"))

    assert _finding(unrestricted, "CG-SNMP-002").outcome is AssessmentOutcome.POTENTIAL_RISK
    assert _finding(restricted, "CG-SNMP-002").outcome is AssessmentOutcome.SECURE
    assert _finding(unresolved, "CG-SNMP-002").outcome is AssessmentOutcome.UNKNOWN


def test_named_acl_is_recognized_as_community_restriction_reference() -> None:
    result = _analyze(
        _configuration(
            "ip access-list standard MGMT-SOURCES",
            " permit 192.0.2.0 0.0.0.255",
            "!",
            "snmp-server community SYNTHETIC-NAMED RO MGMT-SOURCES",
        )
    )

    assert _finding(result, "CG-SNMP-002").outcome is AssessmentOutcome.SECURE


def test_incomplete_configuration_does_not_create_positive_security_conclusions() -> None:
    text = "\n".join(
        (
            "version 15.7",
            "hostname TEST",
            "interface Loopback0",
            " description TEST",
            "!",
            "ip http server",
            "ip ssh version 1",
            "snmp-server community SYNTHETIC-INCOMPLETE RW",
            "line vty 0 4",
            " transport input telnet",
            "!",
            "banner motd ^C",
            "SYNTHETIC-TRUNCATED",
        )
    )
    result = _analyze(text)

    assert all(finding.outcome is AssessmentOutcome.UNKNOWN for finding in result.findings)
    assert all(finding.severity is None for finding in result.findings)


def test_five_rule_output_is_deterministic_and_contains_no_critical_severity() -> None:
    text = _configuration(
        "ip http server",
        "ip ssh version 1",
        "snmp-server community SYNTHETIC-DETERMINISTIC RW",
        "line vty 0 4",
        " transport input telnet",
    )

    first = _analyze(text)
    second = _analyze(text)

    assert first == second
    assert [item.rule_id for item in first.findings] == [
        "CG-MGMT-001",
        "CG-MGMT-006",
        "CG-MGMT-002",
        "CG-SNMP-001",
        "CG-SNMP-002",
    ]
    assert all(item.severity is not Severity.CRITICAL for item in first.findings)
