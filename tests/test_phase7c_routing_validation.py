"""Phase 7C routing validation and integration-hardening regressions."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from configguard.analysis import default_analysis_engine
from configguard.cli import ExitCode, main
from configguard.domain import AssessmentOutcome
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource
from configguard.reporting import build_assessment_report, render_html, render_json, render_terminal
from configguard.rules import (
    EigrpAuthenticationRule,
    OspfAuthenticationRule,
    RipAuthenticationRule,
)
from configguard.rules.contracts import SecurityRule

FIXTURES = Path(__file__).parent / "fixtures" / "phase7c"


def _text(*commands: str) -> str:
    return "\n".join(
        (
            "version 15.2",
            "hostname SYNTHETIC-PHASE7C",
            *commands,
            "end",
            "",
        )
    )


def _parse(*commands: str):  # type: ignore[no-untyped-def]
    return CiscoConfigurationParser().parse(
        ConfigurationSource("synthetic-phase7c.txt", _text(*commands))
    )


@pytest.mark.parametrize(
    ("fixture_name", "expected"),
    [
        (
            "synthetic_ripv2.txt",
            (
                AssessmentOutcome.NOT_APPLICABLE,
                AssessmentOutcome.NOT_APPLICABLE,
                AssessmentOutcome.SECURE,
            ),
        ),
        (
            "synthetic_ospfv2.txt",
            (
                AssessmentOutcome.SECURE,
                AssessmentOutcome.NOT_APPLICABLE,
                AssessmentOutcome.NOT_APPLICABLE,
            ),
        ),
        (
            "synthetic_eigrp.txt",
            (
                AssessmentOutcome.NOT_APPLICABLE,
                AssessmentOutcome.SECURE,
                AssessmentOutcome.NOT_APPLICABLE,
            ),
        ),
        (
            "synthetic_multi_process.txt",
            (
                AssessmentOutcome.POTENTIAL_RISK,
                AssessmentOutcome.UNKNOWN,
                AssessmentOutcome.SECURE,
            ),
        ),
        (
            "synthetic_interface_range.txt",
            (
                AssessmentOutcome.NOT_APPLICABLE,
                AssessmentOutcome.SECURE,
                AssessmentOutcome.NOT_APPLICABLE,
            ),
        ),
    ],
)
def test_documented_controlled_fixtures_have_exact_expected_outcomes(
    fixture_name: str,
    expected: tuple[AssessmentOutcome, AssessmentOutcome, AssessmentOutcome],
) -> None:
    parsed = CiscoConfigurationParser().parse(
        ConfigurationSource(
            fixture_name,
            (FIXTURES / fixture_name).read_text(encoding="utf-8"),
        )
    )

    actual = (
        OspfAuthenticationRule().evaluate(parsed).outcome,
        EigrpAuthenticationRule().evaluate(parsed).outcome,
        RipAuthenticationRule().evaluate(parsed).outcome,
    )

    assert actual == expected


@pytest.mark.parametrize(
    ("rule", "commands", "expected"),
    [
        (
            OspfAuthenticationRule(),
            (
                "interface GigabitEthernet0/1",
                " ip ospf 10 area 0",
                " ip ospf authentication null",
                "!",
                "router ospf 10",
                "!",
            ),
            AssessmentOutcome.POTENTIAL_RISK,
        ),
        (
            OspfAuthenticationRule(),
            (
                "interface GigabitEthernet0/1",
                " ip ospf 10 area 0",
                " ip ospf authentication message-digest",
                "!",
                "router ospf 10",
                "!",
            ),
            AssessmentOutcome.UNKNOWN,
        ),
        (
            OspfAuthenticationRule(),
            (
                "interface GigabitEthernet0/1",
                " ip ospf 20 area 0",
                "!",
                "router ospf 10",
                "!",
            ),
            AssessmentOutcome.UNKNOWN,
        ),
        (
            OspfAuthenticationRule(),
            (
                "interface GigabitEthernet0/1",
                " ip ospf 10 area 0",
                " ip ospf authentication sha256 SYNTHETIC-UNSUPPORTED-OSPF",
                "!",
                "router ospf 10",
                "!",
            ),
            AssessmentOutcome.UNSUPPORTED_SYNTAX,
        ),
        (
            EigrpAuthenticationRule(),
            (
                "interface GigabitEthernet0/1",
                " ip address 172.16.1.1 255.255.255.0",
                " no ip authentication mode eigrp 100",
                "!",
                "router eigrp 100",
                " network 172.16.0.0 0.0.255.255",
                "!",
            ),
            AssessmentOutcome.UNKNOWN,
        ),
        (
            EigrpAuthenticationRule(),
            (
                "interface GigabitEthernet0/1",
                " ip address 172.16.1.1 255.255.255.0",
                " ip authentication mode eigrp 100 md5",
                " ip authentication key-chain eigrp 100 MISSING-CHAIN",
                "!",
                "router eigrp 100",
                " network 172.16.0.0 0.0.255.255",
                "!",
            ),
            AssessmentOutcome.UNKNOWN,
        ),
        (
            EigrpAuthenticationRule(),
            (
                "interface GigabitEthernet0/1",
                " ip address 172.16.1.1 255.255.255.0",
                " ip authentication mode eigrp 200 md5",
                " ip authentication key-chain eigrp 200 MISSING-CHAIN",
                "!",
                "router eigrp 100",
                " network 172.16.0.0 0.0.255.255",
                "!",
            ),
            AssessmentOutcome.UNKNOWN,
        ),
        (
            EigrpAuthenticationRule(),
            ("router eigrp SYNTHETIC-NAMED", "!"),
            AssessmentOutcome.UNSUPPORTED_SYNTAX,
        ),
        (
            RipAuthenticationRule(),
            (
                "interface GigabitEthernet0/1",
                " ip address 10.1.1.1 255.255.255.0",
                " no ip rip authentication mode",
                "!",
                "router rip",
                " version 2",
                " network 10.0.0.0",
                "!",
            ),
            AssessmentOutcome.UNKNOWN,
        ),
        (
            RipAuthenticationRule(),
            (
                "interface GigabitEthernet0/1",
                " ip address 10.1.1.1 255.255.255.0",
                " ip rip authentication mode md5",
                " ip rip authentication key-chain MISSING-CHAIN",
                "!",
                "router rip",
                " version 2",
                " network 10.0.0.0",
                "!",
            ),
            AssessmentOutcome.UNKNOWN,
        ),
        (
            RipAuthenticationRule(),
            (
                "interface GigabitEthernet0/1",
                " ip address 192.0.2.1 255.255.255.0",
                "!",
                "router rip",
                " version 2",
                " network 10.0.0.0",
                "!",
            ),
            AssessmentOutcome.UNKNOWN,
        ),
        (
            RipAuthenticationRule(),
            (
                "interface GigabitEthernet0/1",
                " ip address 10.1.1.1 255.255.255.0",
                " ip rip authentication mode sha256 SYNTHETIC-UNSUPPORTED-RIP",
                "!",
                "router rip",
                " version 2",
                " network 10.0.0.0",
                "!",
            ),
            AssessmentOutcome.UNSUPPORTED_SYNTAX,
        ),
    ],
)
def test_protocol_outcome_matrix_is_conservative(
    rule: SecurityRule,
    commands: tuple[str, ...],
    expected: AssessmentOutcome,
) -> None:
    assert rule.evaluate(_parse(*commands)).outcome is expected


@pytest.mark.parametrize(
    "rule",
    [OspfAuthenticationRule(), EigrpAuthenticationRule(), RipAuthenticationRule()],
)
def test_incomplete_input_is_unknown_for_every_routing_rule(rule: SecurityRule) -> None:
    parsed = _parse("router ospf 10", "banner motd ^", "SYNTHETIC UNTERMINATED")

    assert rule.evaluate(parsed).outcome is AssessmentOutcome.UNKNOWN


def test_same_interface_passive_in_multiple_eigrp_processes_is_not_applicable() -> None:
    parsed = _parse(
        "interface GigabitEthernet0/1",
        " ip address 10.1.1.1 255.255.255.0",
        "!",
        "router eigrp 100",
        " network 10.0.0.0 0.255.255.255",
        " passive-interface Gi0/1",
        "!",
        "router eigrp 200",
        " network 10.0.0.0 0.255.255.255",
        " passive-interface GigabitEthernet0/1",
        "!",
    )
    evaluation = EigrpAuthenticationRule().evaluate(parsed)

    assert evaluation.outcome is AssessmentOutcome.NOT_APPLICABLE
    assert len(evaluation.evidence) >= 5


@pytest.mark.parametrize(
    ("rule", "commands"),
    [
        (
            EigrpAuthenticationRule(),
            (
                "key chain SYNTHETIC-CHAIN",
                " key 1",
                "  key-string SYNTHETIC-SECRET",
                "!",
                "interface GigabitEthernet0/1",
                " ip address 10.1.1.1 255.255.255.0",
                " ip authentication mode eigrp 100 md5",
                " ip authentication key-chain eigrp 100 SYNTHETIC-CHAIN",
                "!",
                "router eigrp 100",
                " network 10.0.0.0 0.255.255.255",
                " no network 10.0.0.0",
                "!",
            ),
        ),
        (
            OspfAuthenticationRule(),
            (
                "interface GigabitEthernet0/1",
                " ip ospf 10 area 0",
                " no ip ospf 10 area 1",
                " ip ospf authentication message-digest",
                " ip ospf message-digest-key 1 md5 SYNTHETIC-SECRET",
                "!",
                "router ospf 10",
                "!",
            ),
        ),
    ],
)
def test_non_matching_supported_negation_cannot_leave_a_false_secure_result(
    rule: SecurityRule,
    commands: tuple[str, ...],
) -> None:
    evaluation = rule.evaluate(_parse(*commands))

    assert evaluation.outcome is AssessmentOutcome.UNKNOWN
    assert evaluation.evidence


def test_association_mismatch_report_retains_safe_process_and_interface_context() -> None:
    source = ConfigurationSource(
        "synthetic-association-mismatch.txt",
        _text(
            "interface GigabitEthernet0/1",
            " ip address 10.1.1.1 255.255.255.0",
            "!",
            "router eigrp 100",
            " network 172.16.0.0 0.0.255.255",
            "!",
        ),
    )
    parser = CiscoConfigurationParser()
    parsed = parser.parse(source)
    analysis = default_analysis_engine().analyze(parsed)
    report = build_assessment_report(parser.identify(source), parsed, analysis)
    finding = next(item for item in report.findings if item.rule_id == "CG-ROUTE-002")

    assert finding.outcome is AssessmentOutcome.UNKNOWN
    assert {item.location.line_start for item in finding.evidence}.issuperset({4, 6, 7})
    assert "actively exchanging" not in render_terminal(report)
    assert "adjacency" not in finding.description.lower()


def test_cli_json_html_diagnostics_and_repr_hide_all_synthetic_secret_markers(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    markers = (
        "SYNTHETIC-PRIVATE-ROUTING-KEY",
        "SYNTHETIC-PRIVATE-SNMP",
        "SYNTHETIC-PRIVATE-PASSWORD",
        "SYNTHETIC-PRIVATE-UNSUPPORTED-ARGUMENT",
    )
    source_path = tmp_path / "synthetic-phase7c-private.txt"
    html_path = tmp_path / "synthetic-phase7c-private.html"
    source_path.write_text(
        _text(
            f"username SYNTHETIC-USER password 0 {markers[2]}",
            f"snmp-server community {markers[1]} RO",
            "key chain SYNTHETIC-PRIVATE-CHAIN",
            " key 1",
            f"  key-string {markers[0]}",
            "!",
            "interface GigabitEthernet0/1",
            " ip address 172.16.1.1 255.255.255.0",
            f" ip authentication mode eigrp 100 sha256 {markers[3]}",
            "!",
            "router eigrp 100",
            " network 172.16.0.0 0.0.255.255",
            "!",
        ),
        encoding="utf-8",
    )

    assert main(["scan", str(source_path)]) is ExitCode.PARTIAL_ASSESSMENT
    terminal = capsys.readouterr().out
    assert main(["scan", str(source_path), "--format", "json"]) is ExitCode.PARTIAL_ASSESSMENT
    json_output = capsys.readouterr().out
    assert (
        main(["scan", str(source_path), "--report", str(html_path)]) is ExitCode.PARTIAL_ASSESSMENT
    )
    terminal_with_report = capsys.readouterr().out
    html_output = html_path.read_text(encoding="utf-8")
    parsed_repr = repr(
        CiscoConfigurationParser().parse(
            ConfigurationSource(source_path.name, source_path.read_text(encoding="utf-8"))
        )
    )
    public = "\n".join((terminal, terminal_with_report, json_output, html_output, parsed_repr))

    assert len(json.loads(json_output)["findings"]) == 17
    assert "CG-ROUTE-002" in public
    assert "unsupported_syntax" in public
    assert "[REDACTED]" in public
    assert all(marker not in public for marker in markers)


def test_renderers_are_deterministic_for_controlled_routing_fixture() -> None:
    source = ConfigurationSource(
        "synthetic_ospfv2.txt",
        (FIXTURES / "synthetic_ospfv2.txt").read_text(encoding="utf-8"),
    )
    parser = CiscoConfigurationParser()
    parsed = parser.parse(source)
    analysis = default_analysis_engine().analyze(parsed)
    report = build_assessment_report(parser.identify(source), parsed, analysis)

    assert render_terminal(report) == render_terminal(report)
    assert render_json(report) == render_json(report)
    assert render_html(report) == render_html(report)
