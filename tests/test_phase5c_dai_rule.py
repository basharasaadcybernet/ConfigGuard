"""Focused synthetic regression tests for the Phase 5C DAI rule."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from configguard.analysis import default_analysis_engine
from configguard.cli import ExitCode, main
from configguard.domain import AssessmentOutcome, ParseStatus, Severity
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource
from configguard.rules import DynamicArpInspectionRule

FIXTURES = Path(__file__).parent / "fixtures"


def _configuration(*commands: str) -> str:
    return "\n".join(
        (
            "version 17.9",
            "platform punt-keepalive disable-kernel-core",
            "hostname SYNTHETIC-DAI",
            *commands,
            "end",
            "",
        )
    )


def _parsed(text: str):  # type: ignore[no-untyped-def]
    return CiscoConfigurationParser().parse(ConfigurationSource("synthetic-dai.txt", text))


def _evaluate(*commands: str):  # type: ignore[no-untyped-def]
    return DynamicArpInspectionRule().evaluate(_parsed(_configuration(*commands)))


def _protected_access_port(*extra_global: str, trust: str = "no ip arp inspection trust"):
    return _evaluate(
        "ip dhcp snooping",
        "ip dhcp snooping vlan 10",
        "ip arp inspection vlan 10",
        *extra_global,
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " no ip dhcp snooping trust",
        f" {trust}",
        "!",
    )


def test_dai_accepts_explicit_vlan_untrusted_access_and_dhcp_prerequisites() -> None:
    result = _protected_access_port()

    assert result.outcome is AssessmentOutcome.SECURE
    assert result.severity is None
    assert any("binding database" in item for item in result.limitations)


def test_dai_explicit_vlan_removal_is_conservative_hardening() -> None:
    result = _evaluate(
        "ip arp inspection vlan 10",
        "no ip arp inspection vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " no ip arp inspection trust",
        "!",
    )

    assert result.outcome is AssessmentOutcome.HARDENING
    assert result.severity is Severity.MEDIUM


def test_dai_vlan_ranges_overlap_and_resolve_in_source_order() -> None:
    enabled_last = _evaluate(
        "ip dhcp snooping",
        "ip dhcp snooping vlan 20",
        "ip arp inspection vlan 10-20",
        "no ip arp inspection vlan 15-25",
        "ip arp inspection vlan 20",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 20",
        " no ip dhcp snooping trust",
        " no ip arp inspection trust",
        "!",
    )
    removed_last = _evaluate(
        "ip arp inspection vlan 10-20",
        "no ip arp inspection vlan 15-25",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 15",
        " no ip arp inspection trust",
        "!",
    )

    assert enabled_last.outcome is AssessmentOutcome.SECURE
    assert removed_last.outcome is AssessmentOutcome.HARDENING


def test_dai_access_trust_is_potential_risk_but_trusted_trunk_is_not() -> None:
    trusted_access = _protected_access_port(trust="ip arp inspection trust")
    trusted_trunk = _evaluate(
        "ip dhcp snooping",
        "ip dhcp snooping vlan 10",
        "ip arp inspection vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " no ip dhcp snooping trust",
        " no ip arp inspection trust",
        "!",
        "interface GigabitEthernet1/0/48",
        " switchport mode trunk",
        " ip arp inspection trust",
        "!",
    )

    assert trusted_access.outcome is AssessmentOutcome.POTENTIAL_RISK
    assert trusted_access.severity is Severity.MEDIUM
    assert trusted_trunk.outcome is AssessmentOutcome.SECURE


def test_dai_interface_trust_negation_resolves_in_source_order() -> None:
    untrusted_last = _evaluate(
        "ip dhcp snooping",
        "ip dhcp snooping vlan 10",
        "ip arp inspection vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " no ip dhcp snooping trust",
        " ip arp inspection trust",
        " no ip arp inspection trust",
        "!",
    )
    trusted_last = _evaluate(
        "ip dhcp snooping",
        "ip dhcp snooping vlan 10",
        "ip arp inspection vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " no ip dhcp snooping trust",
        " no ip arp inspection trust",
        " ip arp inspection trust",
        "!",
    )

    assert untrusted_last.outcome is AssessmentOutcome.SECURE
    assert trusted_last.outcome is AssessmentOutcome.POTENTIAL_RISK


@pytest.mark.parametrize(
    "dhcp_commands",
    (
        (),
        ("no ip dhcp snooping",),
        ("ip dhcp snooping",),
        ("ip dhcp snooping", "ip dhcp snooping vlan 20"),
    ),
)
def test_dai_preserves_uncertainty_without_supported_binding_source(
    dhcp_commands: tuple[str, ...],
) -> None:
    result = _evaluate(
        *dhcp_commands,
        "ip arp inspection vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " no ip arp inspection trust",
        "!",
    )

    assert result.outcome is AssessmentOutcome.UNKNOWN
    assert result.severity is None


def test_dai_static_validation_configuration_remains_unsupported() -> None:
    result = _evaluate(
        "ip arp inspection vlan 10",
        "ip arp inspection filter SYNTHETIC-STATIC vlan 10 static",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " no ip arp inspection trust",
        "!",
    )

    assert result.outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX


def test_dai_missing_vlan_or_trust_evidence_is_unknown_not_a_finding() -> None:
    missing_access_vlan = _evaluate(
        "ip arp inspection vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " no ip arp inspection trust",
        "!",
    )
    missing_trust = _evaluate(
        "ip arp inspection vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        "!",
    )

    assert missing_access_vlan.outcome is AssessmentOutcome.UNKNOWN
    assert missing_trust.outcome is AssessmentOutcome.UNKNOWN


@pytest.mark.parametrize(
    "interface_lines",
    (
        (
            "interface range GigabitEthernet1/0/1-4",
            " switchport mode access",
            " switchport access vlan 10",
            " no ip dhcp snooping trust",
            " no ip arp inspection trust",
            "!",
        ),
        (
            "interface GigabitEthernet1/0/1",
            " switchport mode access",
            " switchport access vlan 10",
            " channel-group 1 mode active",
            " no ip arp inspection trust",
            "!",
        ),
        (
            "interface Port-channel1",
            " switchport mode access",
            " switchport access vlan 10",
            " no ip arp inspection trust",
            "!",
        ),
    ),
)
def test_dai_unresolved_interface_constructs_are_unknown(
    interface_lines: tuple[str, ...],
) -> None:
    result = _evaluate("ip arp inspection vlan 10", *interface_lines)

    assert result.outcome is AssessmentOutcome.UNKNOWN


def test_dai_malformed_relevant_syntax_is_unsupported() -> None:
    result = _evaluate(
        "ip arp inspection vlan SYNTHETIC",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        " no ip arp inspection trust",
        "!",
    )

    assert result.outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX


def test_dai_incomplete_input_is_unknown() -> None:
    text = _configuration(
        "ip arp inspection vlan 10",
        "interface GigabitEthernet1/0/1",
        " switchport mode access",
        " switchport access vlan 10",
        "banner motd ^C",
        "SYNTHETIC-TRUNCATED",
    ).removesuffix("end\n")
    parsed = _parsed(text)

    assert parsed.status is ParseStatus.INCOMPLETE
    assert DynamicArpInspectionRule().evaluate(parsed).outcome is AssessmentOutcome.UNKNOWN


def test_dai_router_without_switch_evidence_is_not_applicable() -> None:
    parsed = _parsed((FIXTURES / "synthetic_ios_router.txt").read_text(encoding="utf-8"))

    assert DynamicArpInspectionRule().evaluate(parsed).outcome is AssessmentOutcome.NOT_APPLICABLE


def test_dai_and_dhcp_rules_are_consistent_but_independent() -> None:
    complete = default_analysis_engine().analyze(
        _parsed(
            _configuration(
                "ip dhcp snooping",
                "ip dhcp snooping vlan 10",
                "ip arp inspection vlan 10",
                "interface GigabitEthernet1/0/1",
                " switchport mode access",
                " switchport access vlan 10",
                " no ip dhcp snooping trust",
                " no ip arp inspection trust",
                "!",
            )
        )
    )
    uncertain = default_analysis_engine().analyze(
        _parsed(
            _configuration(
                "ip arp inspection vlan 10",
                "interface GigabitEthernet1/0/1",
                " switchport mode access",
                " switchport access vlan 10",
                " no ip dhcp snooping trust",
                " no ip arp inspection trust",
                "!",
            )
        )
    )
    trusted_for_dhcp = default_analysis_engine().analyze(
        _parsed(
            _configuration(
                "ip dhcp snooping",
                "ip dhcp snooping vlan 10",
                "ip arp inspection vlan 10",
                "interface GigabitEthernet1/0/1",
                " switchport mode access",
                " switchport access vlan 10",
                " ip dhcp snooping trust",
                " no ip arp inspection trust",
                "!",
            )
        )
    )
    complete_findings = {item.rule_id: item for item in complete.findings}
    uncertain_findings = {item.rule_id: item for item in uncertain.findings}
    trusted_findings = {item.rule_id: item for item in trusted_for_dhcp.findings}

    assert complete_findings["CG-L2-002"].outcome is AssessmentOutcome.SECURE
    assert complete_findings["CG-L2-003"].outcome is AssessmentOutcome.SECURE
    assert uncertain_findings["CG-L2-002"].outcome is AssessmentOutcome.UNKNOWN
    assert uncertain_findings["CG-L2-003"].outcome is AssessmentOutcome.UNKNOWN
    assert trusted_findings["CG-L2-002"].outcome is AssessmentOutcome.POTENTIAL_RISK
    assert trusted_findings["CG-L2-003"].outcome is AssessmentOutcome.UNKNOWN


def test_dai_is_deterministic_and_unrelated_unknown_syntax_does_not_invalidate_it() -> None:
    parsed = _parsed(
        _configuration(
            "ip dhcp snooping",
            "ip dhcp snooping vlan 10",
            "ip arp inspection vlan 10",
            "interface GigabitEthernet1/0/1",
            " switchport mode access",
            " switchport access vlan 10",
            " no ip dhcp snooping trust",
            " no ip arp inspection trust",
            " synthetic-unrelated-option enabled",
            "!",
        )
    )
    first = default_analysis_engine().analyze(parsed)
    second = default_analysis_engine().analyze(parsed)
    findings = {item.rule_id: item for item in first.findings}

    assert parsed.status is ParseStatus.PARTIAL
    assert first == second
    assert findings["CG-L2-003"].outcome is AssessmentOutcome.SECURE


def test_dai_public_outputs_preserve_secret_redaction(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    principal = "SYNTHETIC-DAI-PRIVATE-PRINCIPAL"
    credential = "SYNTHETIC-DAI-PRIVATE-CREDENTIAL"
    fixture = (FIXTURES / "synthetic_ios_xe_layer2_switch.txt").read_text(encoding="utf-8")
    source = tmp_path / "synthetic-dai.txt"
    html_path = tmp_path / "dai-report.html"
    source.write_text(
        fixture.replace(
            "username SYNTHETIC-L2-ADMIN secret 9 SYNTHETIC-L2-HASH",
            f"username {principal} password 0 {credential}",
        ),
        encoding="utf-8",
    )

    assert main(["scan", str(source)]) is ExitCode.COMPLETED
    terminal = capsys.readouterr().out
    assert main(["scan", str(source), "--format", "json"]) is ExitCode.COMPLETED
    json_output = capsys.readouterr().out
    assert main(["scan", str(source), "--report", str(html_path)]) is ExitCode.COMPLETED
    capsys.readouterr()
    html = html_path.read_text(encoding="utf-8")

    assert len(json.loads(json_output)["findings"]) == 17
    for rendered in (terminal, json_output, html):
        assert principal not in rendered
        assert credential not in rendered
        assert "[REDACTED]" in rendered
