"""Acceptance-mutation regressions for the narrowly scoped Phase 8A.1 fixes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from configguard.analysis import default_analysis_engine
from configguard.domain import AssessmentOutcome, ContextKind, ParseStatus, Severity
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource
from configguard.reporting import build_assessment_report, render_html, render_json, render_terminal
from configguard.rules import AccessPortSecurityRule

FIXTURES = Path(__file__).parent / "fixtures"


def _configuration(*commands: str) -> str:
    return "\n".join(("version 17.9", "hostname SYNTHETIC-ACCEPTANCE", *commands, "end", ""))


def _parse(text: str):  # type: ignore[no-untyped-def]
    return CiscoConfigurationParser().parse(ConfigurationSource("synthetic-acceptance.txt", text))


def _outcomes(text: str) -> dict[str, AssessmentOutcome]:
    return {
        item.rule_id: item.outcome
        for item in default_analysis_engine().analyze(_parse(text)).findings
    }


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        ("shutdown", AssessmentOutcome.SECURE),
        ("restrict", AssessmentOutcome.SECURE),
        ("protect", AssessmentOutcome.HARDENING),
    ],
)
def test_unindented_supported_violation_mutation_stays_in_active_interface(
    mode: str,
    expected: AssessmentOutcome,
) -> None:
    parsed = _parse(
        _configuration(
            "interface GigabitEthernet0/1",
            " switchport mode access",
            " switchport port-security",
            f"switchport port-security violation {mode}",
            "!",
        )
    )
    violation = next(
        item
        for item in parsed.observations
        if item.kind == "interface.port_security" and item.attributes.get("setting") == "violation"
    )
    command = next(
        item for item in parsed.commands if item.command_id == violation.source_command_ids[0]
    )

    assert parsed.status is ParseStatus.PARSED
    assert command.context.kind is ContextKind.INTERFACE
    assert command.context.identifier == "GigabitEthernet0/1"
    assert violation.attributes.get("value") == mode
    assert not any(item.code == "CG-PARSE-UNSUPPORTED-COMMAND" for item in parsed.diagnostics)
    assert AccessPortSecurityRule().evaluate(parsed).outcome is expected


def test_unindented_unsupported_violation_variant_remains_scoped_uncertainty() -> None:
    parsed = _parse(
        _configuration(
            "interface GigabitEthernet0/1",
            " switchport mode access",
            " switchport port-security",
            "switchport port-security violation synthetic-mode",
            "!",
        )
    )
    diagnostic = next(
        item for item in parsed.diagnostics if item.code == "CG-PARSE-UNSUPPORTED-COMMAND"
    )
    unclassified = next(
        item
        for item in parsed.observations
        if item.kind == "command.unclassified"
        and item.source_command_ids == (diagnostic.command_id,)
    )

    assert parsed.status is ParseStatus.PARTIAL
    assert unclassified.attributes.get("context_kind") == ContextKind.INTERFACE.value
    assert unclassified.attributes.get("rule_scope") == "layer2.port_security"
    assert AccessPortSecurityRule().evaluate(parsed).outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX


def test_unindented_port_security_repetition_and_negations_resolve_in_order() -> None:
    parsed = _parse(
        _configuration(
            "interface GigabitEthernet0/1",
            " switchport mode access",
            "switchport port-security",
            "no switchport port-security",
            "switchport port-security",
            "switchport port-security violation restrict",
            "no switchport port-security violation",
            "switchport port-security violation shutdown",
            "!",
        )
    )

    assert parsed.status is ParseStatus.PARSED
    assert not any(item.code == "CG-PARSE-UNSUPPORTED-COMMAND" for item in parsed.diagnostics)
    assert AccessPortSecurityRule().evaluate(parsed).outcome is AssessmentOutcome.SECURE


def test_port_security_repetition_negation_and_range_provenance() -> None:
    parsed = _parse(
        _configuration(
            "interface range GigabitEthernet1/0/1 - 2",
            " switchport mode access",
            " switchport port-security",
            " switchport port-security violation restrict",
            " no switchport port-security violation",
            " switchport port-security violation shutdown",
            "!",
        )
    )
    result = AccessPortSecurityRule().evaluate(parsed)

    assert result.outcome is AssessmentOutcome.SECURE
    assert {item.target_interface for item in result.evidence} == {
        "GigabitEthernet1/0/1",
        "GigabitEthernet1/0/2",
    }
    assert {item.resolution_origin for item in result.evidence} == {"range"}


def test_management_acceptance_mutations_change_only_the_target_rule() -> None:
    baseline = _configuration(
        "ip http server",
        "line vty 0 4",
        " transport input telnet ssh",
        "!",
    )
    transport_mutation = baseline.replace("transport input telnet ssh", "transport input ssh")
    http_mutation = baseline.replace("ip http server", "no ip http server")
    before = _outcomes(baseline)
    after_transport = _outcomes(transport_mutation)
    after_http = _outcomes(http_mutation)

    assert before["CG-MGMT-001"] is AssessmentOutcome.CONFIRMED_INSECURE
    assert after_transport["CG-MGMT-001"] is AssessmentOutcome.SECURE
    assert before["CG-MGMT-006"] is AssessmentOutcome.CONFIRMED_INSECURE
    assert after_http["CG-MGMT-006"] is AssessmentOutcome.SECURE
    assert all(
        after_transport[rule_id] is outcome
        for rule_id, outcome in before.items()
        if rule_id != "CG-MGMT-001"
    )
    assert all(
        after_http[rule_id] is outcome
        for rule_id, outcome in before.items()
        if rule_id != "CG-MGMT-006"
    )


def test_bpdu_guard_acceptance_mutation_is_isolated() -> None:
    baseline = (FIXTURES / "synthetic_ios_xe_layer2_switch.txt").read_text(encoding="utf-8")
    mutation = baseline.replace(
        " spanning-tree bpduguard enable",
        " spanning-tree bpduguard disable",
    )
    before = default_analysis_engine().analyze(_parse(baseline))
    after = default_analysis_engine().analyze(_parse(mutation))
    before_by_id = {item.rule_id: item for item in before.findings}
    after_by_id = {item.rule_id: item for item in after.findings}

    assert before_by_id["CG-L2-004"].outcome is AssessmentOutcome.SECURE
    assert after_by_id["CG-L2-004"].outcome is AssessmentOutcome.HARDENING
    assert after_by_id["CG-L2-004"].severity is Severity.MEDIUM
    assert all(
        after_by_id[rule_id].outcome is finding.outcome
        for rule_id, finding in before_by_id.items()
        if rule_id != "CG-L2-004"
    )


def test_port_security_acceptance_observation_reaches_all_report_formats() -> None:
    source = ConfigurationSource(
        "synthetic-acceptance.txt",
        _configuration(
            "interface GigabitEthernet0/1",
            " switchport mode access",
            " switchport port-security",
            "switchport port-security violation shutdown",
            "!",
        ),
    )
    parser = CiscoConfigurationParser()
    parsed = parser.parse(source)
    analysis = default_analysis_engine().analyze(parsed)
    report = build_assessment_report(parser.identify(source), parsed, analysis)
    terminal = render_terminal(report)
    json_output = render_json(report)
    html = render_html(report)
    payload = json.loads(json_output)
    finding = next(item for item in payload["findings"] if item["rule_id"] == "CG-L2-001")

    assert len(analysis.findings) == 17
    assert finding["outcome"] == AssessmentOutcome.SECURE.value
    assert any(item["line_start"] == 6 for item in finding["evidence"])
    for rendered in (terminal, json_output, html):
        assert "CG-L2-001" in rendered
        assert "CG-PARSE-UNSUPPORTED-COMMAND" not in rendered


def test_routing_cli_rule_boundaries_do_not_mix_summaries() -> None:
    source = ConfigurationSource(
        "synthetic-routing-output.txt",
        _configuration(
            "interface GigabitEthernet0/1",
            " ip address 10.0.0.1 255.255.255.0",
            "!",
            "router ospf 10",
            " network 10.0.0.0 0.0.0.255 area 0",
            "!",
        ),
    )
    parser = CiscoConfigurationParser()
    parsed = parser.parse(source)
    report = build_assessment_report(
        parser.identify(source),
        parsed,
        default_analysis_engine().analyze(parsed),
    )
    terminal = render_terminal(report)
    ospf_start = terminal.index("[CG-ROUTE-001]")
    eigrp_start = terminal.index("[CG-ROUTE-002]")
    rip_start = terminal.index("[CG-ROUTE-003]")
    diagnostics_start = terminal.index("\nOperational diagnostics", rip_start)
    ospf_section = terminal[ospf_start:eigrp_start]
    eigrp_section = terminal[eigrp_start:rip_start]
    rip_section = terminal[rip_start:diagnostics_start]

    assert "Outcome: unknown" in ospf_section
    assert "participating interface" in ospf_section
    assert "RIPv2" not in ospf_section
    assert "Outcome: not_applicable" in eigrp_section
    assert "classic IPv4 EIGRP" in eigrp_section
    assert "RIPv2" not in eigrp_section
    assert "Outcome: not_applicable" in rip_section
    assert "No supported active RIPv2 process is configured." in rip_section
