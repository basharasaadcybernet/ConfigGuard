"""Focused synthetic regression tests for the Phase 5B Layer 2 rules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from configguard.analysis import default_analysis_engine
from configguard.cli import ExitCode, main
from configguard.domain import AssessmentOutcome, ParseStatus, Severity
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource
from configguard.rules import (
    AccessPortSecurityRule,
    DhcpSnoopingTrustRule,
    PortfastBpduGuardRule,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _configuration(*commands: str) -> str:
    return "\n".join(
        (
            "version 17.9",
            "platform punt-keepalive disable-kernel-core",
            "hostname SYNTHETIC-L2",
            *commands,
            "end",
            "",
        )
    )


def _parsed(text: str):  # type: ignore[no-untyped-def]
    return CiscoConfigurationParser().parse(ConfigurationSource("synthetic-l2.txt", text))


def _evaluate(rule, *commands: str):  # type: ignore[no-untyped-def]
    return rule.evaluate(_parsed(_configuration(*commands)))


@pytest.mark.parametrize("violation", ("restrict", "shutdown"))
def test_port_security_accepts_explicit_supported_enforcement_modes(
    violation: str,
) -> None:
    result = _evaluate(
        AccessPortSecurityRule(),
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security maximum 2",
        f" switchport port-security violation {violation}",
        "!",
    )

    assert result.outcome is AssessmentOutcome.SECURE
    assert result.severity is None


def test_port_security_distinguishes_protect_disable_missing_and_trunk() -> None:
    protect = _evaluate(
        AccessPortSecurityRule(),
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security violation protect",
        "!",
    )
    disabled = _evaluate(
        AccessPortSecurityRule(),
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " no switchport port-security",
        "!",
    )
    missing = _evaluate(
        AccessPortSecurityRule(),
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        "!",
    )
    trunk = _evaluate(
        AccessPortSecurityRule(),
        "interface GigabitEthernet1/0/48",
        " switchport mode trunk",
        "!",
    )

    assert protect.outcome is AssessmentOutcome.HARDENING
    assert protect.severity is Severity.LOW
    assert disabled.outcome is AssessmentOutcome.HARDENING
    assert missing.outcome is AssessmentOutcome.UNKNOWN
    assert trunk.outcome is AssessmentOutcome.NOT_APPLICABLE


def test_port_security_resolves_order_negation_and_relevant_unsupported_syntax() -> None:
    enabled_last = _evaluate(
        AccessPortSecurityRule(),
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " no switchport port-security",
        " switchport port-security",
        " switchport port-security violation restrict",
        "!",
    )
    disabled_last = _evaluate(
        AccessPortSecurityRule(),
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport port-security",
        " no switchport port-security",
        "!",
    )
    unsupported = _evaluate(
        AccessPortSecurityRule(),
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport port-security",
        " switchport port-security violation synthetic-mode",
        "!",
    )

    assert enabled_last.outcome is AssessmentOutcome.SECURE
    assert disabled_last.outcome is AssessmentOutcome.HARDENING
    assert unsupported.outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX


def test_dhcp_snooping_requires_explicit_global_vlan_and_access_trust_evidence() -> None:
    secure = _evaluate(
        DhcpSnoopingTrustRule(),
        "ip dhcp snooping",
        "ip dhcp snooping vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " no ip dhcp snooping trust",
        "!",
    )
    missing_global = _evaluate(
        DhcpSnoopingTrustRule(),
        "ip dhcp snooping vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " no ip dhcp snooping trust",
        "!",
    )
    missing_trust = _evaluate(
        DhcpSnoopingTrustRule(),
        "ip dhcp snooping",
        "ip dhcp snooping vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        "!",
    )

    assert secure.outcome is AssessmentOutcome.SECURE
    assert missing_global.outcome is AssessmentOutcome.UNKNOWN
    assert missing_trust.outcome is AssessmentOutcome.UNKNOWN


def test_dhcp_snooping_flags_access_trust_but_not_trusted_trunk() -> None:
    trusted_access = _evaluate(
        DhcpSnoopingTrustRule(),
        "ip dhcp snooping",
        "ip dhcp snooping vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " ip dhcp snooping trust",
        "!",
    )
    trusted_trunk = _evaluate(
        DhcpSnoopingTrustRule(),
        "ip dhcp snooping",
        "ip dhcp snooping vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " no ip dhcp snooping trust",
        "!",
        "interface GigabitEthernet1/0/48",
        " switchport mode trunk",
        " ip dhcp snooping trust",
        "!",
    )

    assert trusted_access.outcome is AssessmentOutcome.POTENTIAL_RISK
    assert trusted_access.severity is Severity.MEDIUM
    assert trusted_trunk.outcome is AssessmentOutcome.SECURE


def test_dhcp_snooping_handles_disable_vlan_removal_and_unsupported_syntax() -> None:
    disabled = _evaluate(
        DhcpSnoopingTrustRule(),
        "no ip dhcp snooping",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        "!",
    )
    removed = _evaluate(
        DhcpSnoopingTrustRule(),
        "ip dhcp snooping",
        "ip dhcp snooping vlan 10,20",
        "no ip dhcp snooping vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " no ip dhcp snooping trust",
        "!",
    )
    unsupported = _evaluate(
        DhcpSnoopingTrustRule(),
        "ip dhcp snooping",
        "ip dhcp snooping vlan synthetic",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " no ip dhcp snooping trust",
        "!",
    )

    assert disabled.outcome is AssessmentOutcome.HARDENING
    assert removed.outcome is AssessmentOutcome.HARDENING
    assert unsupported.outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX


def test_bpdu_guard_resolves_per_interface_and_global_precedence() -> None:
    explicit = _evaluate(
        PortfastBpduGuardRule(),
        "interface GigabitEthernet1/0/1",
        " spanning-tree portfast",
        " spanning-tree bpduguard enable",
        "!",
    )
    inherited = _evaluate(
        PortfastBpduGuardRule(),
        "spanning-tree portfast bpduguard default",
        "interface GigabitEthernet1/0/1",
        " spanning-tree portfast edge",
        " no spanning-tree bpduguard",
        "!",
    )
    override = _evaluate(
        PortfastBpduGuardRule(),
        "spanning-tree portfast bpduguard default",
        "interface GigabitEthernet1/0/1",
        " spanning-tree portfast",
        " spanning-tree bpduguard disable",
        "!",
    )

    assert explicit.outcome is AssessmentOutcome.SECURE
    assert inherited.outcome is AssessmentOutcome.SECURE
    assert override.outcome is AssessmentOutcome.HARDENING


def test_bpdu_guard_distinguishes_absent_disabled_and_unsupported_states() -> None:
    absent = _evaluate(
        PortfastBpduGuardRule(),
        "interface GigabitEthernet1/0/1",
        " spanning-tree portfast",
        "!",
    )
    disabled_default = _evaluate(
        PortfastBpduGuardRule(),
        "no spanning-tree portfast bpduguard default",
        "interface GigabitEthernet1/0/1",
        " spanning-tree portfast",
        "!",
    )
    no_edge = _evaluate(
        PortfastBpduGuardRule(),
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        "!",
    )
    unsupported = _evaluate(
        PortfastBpduGuardRule(),
        "interface GigabitEthernet1/0/1",
        " spanning-tree portfast trunk",
        "!",
    )

    assert absent.outcome is AssessmentOutcome.UNKNOWN
    assert disabled_default.outcome is AssessmentOutcome.HARDENING
    assert no_edge.outcome is AssessmentOutcome.NOT_APPLICABLE
    assert unsupported.outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX


def test_incomplete_input_keeps_all_layer2_rules_unknown() -> None:
    text = _configuration(
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport port-security",
        "banner motd ^C",
        "SYNTHETIC-TRUNCATED",
    ).removesuffix("end\n")
    parsed = _parsed(text)

    assert parsed.status is ParseStatus.INCOMPLETE
    for rule in (
        AccessPortSecurityRule(),
        DhcpSnoopingTrustRule(),
        PortfastBpduGuardRule(),
    ):
        assert rule.evaluate(parsed).outcome is AssessmentOutcome.UNKNOWN


def test_router_without_switch_evidence_is_not_applicable() -> None:
    parsed = _parsed((FIXTURES / "synthetic_ios_router.txt").read_text(encoding="utf-8"))

    for rule in (
        AccessPortSecurityRule(),
        DhcpSnoopingTrustRule(),
        PortfastBpduGuardRule(),
    ):
        assert rule.evaluate(parsed).outcome is AssessmentOutcome.NOT_APPLICABLE


def test_unrelated_unsupported_layer2_syntax_does_not_invalidate_supported_results() -> None:
    parsed = _parsed(
        _configuration(
            "ip dhcp snooping",
            "ip dhcp snooping vlan 10",
            "spanning-tree portfast bpduguard default",
            "interface GigabitEthernet1/0/1",
            " switchport mode access",
            " switchport access vlan 10",
            " switchport port-security",
            " switchport port-security violation restrict",
            " no ip dhcp snooping trust",
            " spanning-tree portfast edge",
            " synthetic-layer-two-option enabled",
            "!",
        )
    )
    result = default_analysis_engine().analyze(parsed)
    findings = {item.rule_id: item for item in result.findings}

    assert parsed.status is ParseStatus.PARTIAL
    assert findings["CG-L2-001"].outcome is AssessmentOutcome.SECURE
    assert findings["CG-L2-002"].outcome is AssessmentOutcome.SECURE
    assert findings["CG-L2-004"].outcome is AssessmentOutcome.SECURE


def test_unsupported_interface_role_blocks_only_rules_that_depend_on_it() -> None:
    parsed = _parsed(
        _configuration(
            "interface GigabitEthernet1/0/1",
            " switchport mode synthetic-role",
            "!",
        )
    )

    assert AccessPortSecurityRule().evaluate(parsed).outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX
    assert DhcpSnoopingTrustRule().evaluate(parsed).outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX
    assert PortfastBpduGuardRule().evaluate(parsed).outcome is AssessmentOutcome.NOT_APPLICABLE


def test_complete_switch_fixture_regresses_all_seventeen_rules_deterministically() -> None:
    text = (FIXTURES / "synthetic_ios_xe_layer2_switch.txt").read_text(encoding="utf-8")
    parsed = _parsed(text)
    first = default_analysis_engine().analyze(parsed)
    second = default_analysis_engine().analyze(parsed)
    outcomes = {item.rule_id: item.outcome for item in first.findings}

    assert parsed.status is ParseStatus.PARSED
    assert first == second
    assert len(first.findings) == 17
    assert outcomes == {
        "CG-MGMT-001": AssessmentOutcome.SECURE,
        "CG-MGMT-006": AssessmentOutcome.SECURE,
        "CG-MGMT-002": AssessmentOutcome.SECURE,
        "CG-SNMP-001": AssessmentOutcome.POTENTIAL_RISK,
        "CG-SNMP-002": AssessmentOutcome.SECURE,
        "CG-MGMT-003": AssessmentOutcome.SECURE,
        "CG-MGMT-005": AssessmentOutcome.NOT_APPLICABLE,
        "CG-MGMT-004": AssessmentOutcome.SECURE,
        "CG-L2-001": AssessmentOutcome.SECURE,
        "CG-L2-002": AssessmentOutcome.SECURE,
        "CG-L2-003": AssessmentOutcome.SECURE,
        "CG-L2-004": AssessmentOutcome.SECURE,
        "CG-ACL-001": AssessmentOutcome.NOT_APPLICABLE,
        "CG-ACL-002": AssessmentOutcome.NOT_APPLICABLE,
        "CG-ROUTE-001": AssessmentOutcome.NOT_APPLICABLE,
        "CG-ROUTE-002": AssessmentOutcome.NOT_APPLICABLE,
        "CG-ROUTE-003": AssessmentOutcome.NOT_APPLICABLE,
    }
    assert all(item.severity is not Severity.CRITICAL for item in first.findings)


def test_layer2_report_paths_preserve_secret_redaction(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    principal = "SYNTHETIC-L2-PRIVATE-PRINCIPAL"
    credential = "SYNTHETIC-L2-PRIVATE-CREDENTIAL"
    source = tmp_path / "synthetic-layer2.txt"
    html_path = tmp_path / "layer2-report.html"
    source.write_text(
        _configuration(
            f"username {principal} password 0 {credential}",
            "ip dhcp snooping",
            "ip dhcp snooping vlan 10",
            "spanning-tree portfast bpduguard default",
            "interface GigabitEthernet1/0/1",
            " switchport mode access",
            " switchport access vlan 10",
            " switchport port-security",
            " switchport port-security violation restrict",
            " no ip dhcp snooping trust",
            " spanning-tree portfast edge",
            "!",
        ),
        encoding="utf-8",
    )

    assert main(["scan", str(source)]) is ExitCode.PARTIAL_ASSESSMENT
    terminal = capsys.readouterr().out
    assert main(["scan", str(source), "--format", "json"]) is ExitCode.PARTIAL_ASSESSMENT
    json_output = capsys.readouterr().out
    assert main(["scan", str(source), "--report", str(html_path)]) is ExitCode.PARTIAL_ASSESSMENT
    capsys.readouterr()
    html = html_path.read_text(encoding="utf-8")

    assert len(json.loads(json_output)["findings"]) == 17
    for rendered in (terminal, json_output, html):
        assert principal not in rendered
        assert credential not in rendered
        assert "[REDACTED]" in rendered
