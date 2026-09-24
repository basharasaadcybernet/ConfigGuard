"""Focused synthetic regressions for Phase 6 interface resolution."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from configguard.analysis import default_analysis_engine
from configguard.analysis.interface_resolution import (
    InterfaceFactOrigin,
    resolve_interface_configuration,
)
from configguard.cli import ExitCode, main
from configguard.domain import AssessmentOutcome, ParseStatus
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource
from configguard.reporting import build_assessment_report, render_html, render_json, render_terminal
from configguard.rules import (
    AccessPortSecurityRule,
    DhcpSnoopingTrustRule,
    DynamicArpInspectionRule,
    PortfastBpduGuardRule,
)


def _text(*commands: str) -> str:
    return "\n".join(
        (
            "version 17.9",
            "platform punt-keepalive disable-kernel-core",
            "hostname SYNTHETIC-PHASE6",
            *commands,
            "end",
            "",
        )
    )


def _parse(*commands: str):  # type: ignore[no-untyped-def]
    return CiscoConfigurationParser().parse(
        ConfigurationSource("synthetic-phase6.txt", _text(*commands))
    )


def _port_security_outcome(*commands: str) -> AssessmentOutcome:
    return AccessPortSecurityRule().evaluate(_parse(*commands)).outcome


def test_supported_contiguous_comma_and_abbreviated_ranges_are_bounded_and_deduplicated() -> None:
    parsed = _parse(
        "interface range Gi0/1 - 2, GigabitEthernet0/2, Gi0/5",
        " switchport mode access",
        "!",
    )
    resolution = resolve_interface_configuration(parsed)
    modes = resolution.effective("interface.switchport_mode")

    assert tuple(modes) == (
        "GigabitEthernet0/1",
        "GigabitEthernet0/2",
        "GigabitEthernet0/5",
    )
    assert all(item.origin is InterfaceFactOrigin.RANGE for item in modes.values())
    assert all(item.source_context.identifier.startswith("range ") for item in modes.values())


def test_range_port_security_affects_only_members_and_preserves_target_provenance() -> None:
    parsed = _parse(
        "interface range GigabitEthernet0/1 - 2",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security violation restrict",
        "!",
        "interface GigabitEthernet0/5",
        " switchport mode trunk",
        "!",
    )
    evaluation = AccessPortSecurityRule().evaluate(parsed)
    finding = {item.rule_id: item for item in default_analysis_engine().analyze(parsed).findings}[
        "CG-L2-001"
    ]

    assert evaluation.outcome is AssessmentOutcome.SECURE
    assert {item.target_interface for item in finding.evidence} == {
        "GigabitEthernet0/1",
        "GigabitEthernet0/2",
    }
    assert {item.resolution_origin for item in finding.evidence} == {"range"}
    assert all(item.context.identifier.startswith("range ") for item in finding.evidence)


def test_direct_and_range_commands_follow_source_order_and_negation() -> None:
    direct_last = _port_security_outcome(
        "interface range GigabitEthernet0/1 - 2",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security violation restrict",
        "!",
        "interface GigabitEthernet0/1",
        " no switchport port-security",
        "!",
    )
    range_last = _port_security_outcome(
        "interface GigabitEthernet0/1",
        " switchport mode access",
        " no switchport port-security",
        "!",
        "interface range GigabitEthernet0/1 - 2",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security violation shutdown",
        "!",
    )

    assert direct_last is AssessmentOutcome.HARDENING
    assert range_last is AssessmentOutcome.SECURE


def test_all_four_layer2_rules_consume_resolved_range_facts() -> None:
    parsed = _parse(
        "ip dhcp snooping",
        "ip dhcp snooping vlan 10",
        "ip arp inspection vlan 10",
        "spanning-tree portfast bpduguard default",
        "interface range GigabitEthernet0/1 - 2",
        " switchport mode access",
        " switchport access vlan 10",
        " switchport port-security",
        " switchport port-security violation restrict",
        " no ip dhcp snooping trust",
        " no ip arp inspection trust",
        " spanning-tree portfast edge",
        "!",
    )

    for rule in (
        AccessPortSecurityRule(),
        DhcpSnoopingTrustRule(),
        DynamicArpInspectionRule(),
        PortfastBpduGuardRule(),
    ):
        assert rule.evaluate(parsed).outcome is AssessmentOutcome.SECURE


def test_malformed_and_oversized_ranges_are_partial_and_never_empty_passes() -> None:
    malformed = _parse(
        "interface range GigabitEthernet0/1 - FastEthernet0/2",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security violation restrict",
        "!",
    )
    oversized = _parse(
        "interface range GigabitEthernet0/1 - 999999999",
        " switchport mode access",
        "!",
    )

    for parsed in (malformed, oversized):
        assert parsed.status is ParseStatus.PARTIAL
        assert parsed.metrics.unsupported_command_count == 1
        assert any(
            item.code == "CG-PARSE-UNSUPPORTED-INTERFACE-RANGE" for item in parsed.diagnostics
        )
        assert (
            AccessPortSecurityRule().evaluate(parsed).outcome
            is AssessmentOutcome.UNSUPPORTED_SYNTAX
        )


def test_unused_template_has_no_effect_but_applied_or_missing_template_is_unknown() -> None:
    unused = _port_security_outcome(
        "template UNUSED-EDGE",
        " switchport mode access",
        " no switchport port-security",
        " switchport port-security violation synthetic-mode",
        "!",
        "interface GigabitEthernet0/1",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security violation restrict",
        "!",
    )
    applied = _port_security_outcome(
        "template EDGE",
        " switchport mode access",
        " switchport port-security",
        "!",
        "interface GigabitEthernet0/1",
        " source template EDGE",
        "!",
    )
    missing_evaluation = AccessPortSecurityRule().evaluate(
        _parse(
            "interface GigabitEthernet0/1",
            " source template MISSING",
            "!",
        )
    )

    assert unused is AssessmentOutcome.SECURE
    assert applied is AssessmentOutcome.UNKNOWN
    assert missing_evaluation.outcome is AssessmentOutcome.UNKNOWN
    assert "no matching definition" in missing_evaluation.summary


def test_nested_and_cyclic_templates_are_detected_without_recursive_expansion() -> None:
    parsed = _parse(
        "template EDGE-A",
        " source template EDGE-B",
        " switchport mode access",
        "!",
        "template EDGE-B",
        " source template EDGE-A",
        "!",
        "interface GigabitEthernet0/1",
        " source template EDGE-A",
        "!",
    )
    resolution = resolve_interface_configuration(parsed)

    assert {item.code for item in resolution.issues} >= {
        "cyclic_template_relationship",
        "template_inheritance_unresolved",
    }
    assert AccessPortSecurityRule().evaluate(parsed).outcome is AssessmentOutcome.UNKNOWN
    assert not resolution.effective("interface.switchport_mode")


def test_unused_cyclic_templates_do_not_affect_a_direct_interface() -> None:
    outcome = _port_security_outcome(
        "template UNUSED-A",
        " source template UNUSED-B",
        "!",
        "template UNUSED-B",
        " source template UNUSED-A",
        "!",
        "interface GigabitEthernet0/1",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security violation restrict",
        "!",
    )

    assert outcome is AssessmentOutcome.SECURE


def test_port_channel_membership_never_copies_logical_trunk_state_to_member() -> None:
    parsed = _parse(
        "interface GigabitEthernet0/1",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security violation restrict",
        " channel-group 1 mode active",
        "!",
        "interface Port-channel1",
        " switchport mode trunk",
        "!",
    )
    resolution = resolve_interface_configuration(parsed)
    modes = resolution.effective("interface.switchport_mode")

    assert modes["GigabitEthernet0/1"].observation.attributes["mode"] == "access"
    assert modes["Port-channel1"].observation.attributes["mode"] == "trunk"
    assert len(resolution.port_channels) == 1
    assert AccessPortSecurityRule().evaluate(parsed).outcome is AssessmentOutcome.UNKNOWN


def test_removed_membership_resolves_normally_and_missing_logical_definition_is_unknown() -> None:
    removed = _port_security_outcome(
        "interface GigabitEthernet0/1",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security violation restrict",
        " channel-group 1 mode active",
        " no channel-group 1",
        "!",
    )
    missing = _port_security_outcome(
        "interface GigabitEthernet0/1",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security violation restrict",
        " channel-group 99 mode active",
        "!",
    )

    assert removed is AssessmentOutcome.SECURE
    assert missing is AssessmentOutcome.UNKNOWN


def test_unsupported_channel_group_mode_is_not_treated_as_a_relationship() -> None:
    parsed = _parse(
        "interface GigabitEthernet0/1",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security violation restrict",
        " channel-group 1 mode synthetic",
        "!",
    )
    resolution = resolve_interface_configuration(parsed)

    assert parsed.status is ParseStatus.PARTIAL
    assert not resolution.port_channels
    assert AccessPortSecurityRule().evaluate(parsed).outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX


def test_relationship_uncertainty_does_not_suppress_independent_adverse_result() -> None:
    outcome = _port_security_outcome(
        "interface GigabitEthernet0/1",
        " switchport mode access",
        " no switchport port-security",
        "!",
        "interface GigabitEthernet0/2",
        " channel-group 1 mode active",
        "!",
        "interface Port-channel1",
        " switchport mode trunk",
        "!",
    )

    assert outcome is AssessmentOutcome.HARDENING


def test_range_and_template_uncertainty_do_not_suppress_independent_adverse_result() -> None:
    outcome = _port_security_outcome(
        "template EDGE",
        " switchport mode access",
        "!",
        "interface GigabitEthernet0/1",
        " source template EDGE",
        "!",
        "interface range GigabitEthernet0/2 - 3",
        " switchport mode access",
        " switchport port-security violation unsupported-mode",
        "!",
        "interface GigabitEthernet0/5",
        " switchport mode access",
        " no switchport port-security",
        "!",
    )

    assert outcome is AssessmentOutcome.HARDENING


def test_all_seventeen_rules_remain_ordered_and_management_results_ignore_l2_uncertainty() -> None:
    parsed = _parse(
        "no ip http server",
        "ip ssh version 2",
        "line vty 0 4",
        " transport input ssh",
        "!",
        "interface GigabitEthernet0/1",
        " source template MISSING",
        "!",
    )
    first = default_analysis_engine().analyze(parsed)
    second = default_analysis_engine().analyze(parsed)
    findings = {item.rule_id: item for item in first.findings}

    assert first == second
    assert len(first.findings) == 17
    assert tuple(item.rule_id for item in first.findings) == tuple(
        item.rule_id for item in second.findings
    )
    assert findings["CG-MGMT-001"].outcome is AssessmentOutcome.SECURE
    assert findings["CG-L2-001"].outcome is AssessmentOutcome.UNKNOWN


def test_cli_json_and_html_render_range_provenance_without_leaking_secrets() -> None:
    secret = "SYNTHETIC-PHASE6-PRIVATE"
    parser = CiscoConfigurationParser()
    source = ConfigurationSource(
        "synthetic-phase6.txt",
        _text(
            f"username SYNTHETIC-USER secret 9 {secret}",
            "interface range GigabitEthernet0/1 - 2",
            " switchport mode access",
            " switchport port-security",
            " switchport port-security violation restrict",
            "!",
        ),
    )
    parsed = parser.parse(source)
    report = build_assessment_report(
        parser.identify(source), parsed, default_analysis_engine().analyze(parsed)
    )
    outputs = (render_terminal(report), render_json(report), render_html(report))
    payload = json.loads(outputs[1])
    finding = next(item for item in payload["findings"] if item["rule_id"] == "CG-L2-001")

    assert all(secret not in output for output in outputs)
    assert all("target: GigabitEthernet0/1, range" in output for output in (outputs[0], outputs[2]))
    assert {item["resolution_origin"] for item in finding["evidence"]} == {"range"}
    assert {item["target_interface"] for item in finding["evidence"]} == {
        "GigabitEthernet0/1",
        "GigabitEthernet0/2",
    }


def test_cli_paths_preserve_range_provenance(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = tmp_path / "synthetic-phase6.txt"
    report_path = tmp_path / "synthetic-phase6.html"
    source.write_text(
        _text(
            "interface range GigabitEthernet0/1 - 2",
            " switchport mode access",
            " switchport port-security",
            " switchport port-security violation restrict",
            "!",
        ),
        encoding="utf-8",
    )

    assert main(["scan", str(source)]) is ExitCode.PARTIAL_ASSESSMENT
    terminal = capsys.readouterr().out
    assert main(["scan", str(source), "--format", "json"]) is ExitCode.PARTIAL_ASSESSMENT
    payload = json.loads(capsys.readouterr().out)
    assert main(["scan", str(source), "--report", str(report_path)]) is ExitCode.PARTIAL_ASSESSMENT
    capsys.readouterr()
    html = report_path.read_text(encoding="utf-8")

    finding = next(item for item in payload["findings"] if item["rule_id"] == "CG-L2-001")
    assert "target: GigabitEthernet0/1, range" in terminal
    assert "target: GigabitEthernet0/1, range" in html
    assert {item["resolution_origin"] for item in finding["evidence"]} == {"range"}


def test_partial_input_remains_incomplete_after_range_expansion() -> None:
    text = _text(
        "interface range GigabitEthernet0/1 - 2",
        " switchport mode access",
        "banner motd ^C",
        "SYNTHETIC-UNTERMINATED",
    ).removesuffix("end\n")
    parsed = CiscoConfigurationParser().parse(ConfigurationSource("synthetic-incomplete.txt", text))

    assert parsed.status is ParseStatus.INCOMPLETE
    assert AccessPortSecurityRule().evaluate(parsed).outcome is AssessmentOutcome.UNKNOWN
