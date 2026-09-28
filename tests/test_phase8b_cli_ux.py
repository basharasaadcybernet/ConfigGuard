"""Focused CLI usability and automation-safety tests for Phase 8B."""

from __future__ import annotations

import json
import tomllib
from dataclasses import replace
from pathlib import Path

import pytest

import configguard.cli as cli_module
from configguard.analysis import default_analysis_engine
from configguard.cli import ExitCode, main
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource
from configguard.reporting import build_assessment_report, render_html, render_terminal

ROOT = Path(__file__).parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "SYNTHETIC-PHASE8B-PRIVATE-MARKER"


def _configuration(*commands: str) -> str:
    return "\n".join(("version 15.7", "hostname SYNTHETIC-UX", *commands, "end", ""))


def _report(text: str):  # type: ignore[no-untyped-def]
    parser = CiscoConfigurationParser()
    source = ConfigurationSource("synthetic-cli-ux.txt", text)
    parsed = parser.parse(source)
    return build_assessment_report(
        parser.identify(source),
        parsed,
        default_analysis_engine().analyze(parsed),
    )


def test_rich_is_an_explicit_bounded_runtime_dependency() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert metadata["project"]["dependencies"] == ["rich>=13.9,<15"]


def test_root_help_is_local_static_and_discoverable(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--help"])
    output = capsys.readouterr().out

    assert caught.value.code == ExitCode.COMPLETED
    assert "local, static, read-only" in output
    assert "Cisco IOS and IOS XE-style" in output
    assert "version" in output
    assert "scan" in output
    assert "configguard scan router.txt" in output
    assert "configguard scan switch.txt --report report.html" in output
    assert "configguard scan router.txt --format json" in output
    assert "configguard scan router.txt --details" in output
    assert "web" in output
    assert "configguard web" in output


def test_scan_help_documents_scope_options_examples_and_exit_codes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        main(["scan", "--help"])
    output = capsys.readouterr().out

    assert caught.value.code == ExitCode.COMPLETED
    for expected in (
        "FILE",
        "Cisco IOS or IOS XE-style",
        "--format",
        "--output",
        "--report",
        "--details",
        "--no-color",
        "Exit codes:",
    ):
        assert expected in output
    assert "never connects" not in output
    assert "no device connection" in output


def test_default_hides_only_not_applicable_noise_and_details_shows_all_rules(
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = str(FIXTURES / "synthetic_ios_router.txt")

    assert main(["scan", source, "--no-color"]) == ExitCode.COMPLETED
    default = capsys.readouterr().out
    assert "[CG-SNMP-001]" in default
    assert "[CG-L2-001]" not in default
    assert "NOT_APPLICABLE result(s) hidden" in default
    assert "Evaluated rule identifiers" not in default
    assert "Assessment limitations" not in default

    assert main(["scan", source, "--details", "--no-color"]) == ExitCode.COMPLETED
    detailed = capsys.readouterr().out
    assert all(f"[{rule_id}]" in detailed for rule_id in _rule_ids())
    assert "Evaluated rule identifiers" in detailed
    assert "Assessment limitations" in detailed
    assert "Technical references" in detailed
    assert len(detailed) > len(default)


def test_terminal_color_is_opt_in_and_plain_fallback_is_ascii() -> None:
    report = _report((FIXTURES / "synthetic_ios_router.txt").read_text(encoding="utf-8"))
    plain = render_terminal(report, color=False)
    colored = render_terminal(report, color=True)

    assert "\x1b[" not in plain
    assert "\x1b[" in colored
    assert all(ord(character) < 128 for character in plain)
    assert "Classification:" in plain
    assert "Outcome:" in plain


def test_redirected_default_and_no_color_never_emit_ansi(
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = str(FIXTURES / "synthetic_ios_router.txt")

    assert main(["scan", source]) == ExitCode.COMPLETED
    redirected = capsys.readouterr().out
    assert main(["scan", source, "--no-color"]) == ExitCode.COMPLETED
    explicit = capsys.readouterr().out

    assert "\x1b[" not in redirected
    assert "\x1b[" not in explicit
    assert redirected == explicit


def test_interactive_color_policy_respects_no_color_and_dumb_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InteractiveOutput:
        @staticmethod
        def isatty() -> bool:
            return True

    monkeypatch.setattr(cli_module.sys, "stdout", InteractiveOutput())
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    assert cli_module._terminal_color_enabled(False) is True
    assert cli_module._terminal_color_enabled(True) is False

    monkeypatch.setenv("NO_COLOR", "1")
    assert cli_module._terminal_color_enabled(False) is False
    monkeypatch.delenv("NO_COLOR")
    monkeypatch.setenv("TERM", "dumb")
    assert cli_module._terminal_color_enabled(False) is False


def test_json_is_identical_with_terminal_only_options(
    capsys: pytest.CaptureFixture[str],
) -> None:
    source = str(FIXTURES / "synthetic_ios_router.txt")

    assert main(["scan", source, "--format", "json"]) == ExitCode.COMPLETED
    plain = capsys.readouterr()
    assert (
        main(["scan", source, "--format", "json", "--details", "--no-color"]) == ExitCode.COMPLETED
    )
    decorated = capsys.readouterr()

    assert plain.err == decorated.err == ""
    assert plain.out == decorated.out
    assert json.loads(decorated.out)["report_schema_version"] == "1.0.0"
    assert "\x1b[" not in decorated.out
    assert not decorated.out.startswith("+")


def test_narrow_and_wide_rendering_wraps_without_silent_content_loss() -> None:
    report = _report(
        _configuration(
            "ip http server",
            "line vty 0 4",
            " transport input telnet",
            "!",
        )
    )
    first = report.findings[0]
    long_finding = replace(
        first,
        description=(
            "LONG-SUMMARY-MARKER This deliberately long assessment summary must wrap while "
            "remaining visible to a user reviewing a narrow terminal."
        ),
        recommendation=(
            "LONG-RECOMMENDATION-MARKER Preserve every security-relevant instruction even "
            "when the terminal has limited horizontal space."
        ),
    )
    long_report = replace(report, findings=(long_finding, *report.findings[1:]))

    narrow = render_terminal(long_report, details=True, color=False, width=52)
    wide = render_terminal(long_report, details=True, color=False, width=240)

    assert max(map(len, narrow.splitlines())) <= 52
    assert max(map(len, wide.splitlines())) <= 120
    assert "LONG-SUMMARY-MARKER" in narrow
    assert "LONG-RECOMMENDATION-MARKER" in narrow
    assert "remaining visible" in narrow


def test_outcomes_remain_textually_distinct_and_not_applicable_is_quiet() -> None:
    report = _report(
        _configuration(
            "ip http server",
            "line vty 0 4",
            " login local",
            "!",
        )
    )
    default = render_terminal(report)
    detailed = render_terminal(report, details=True)

    assert "Classification: Confirmed weakness" in default
    assert "Outcome: confirmed_insecure" in default
    assert "Classification: Unknown result" in default
    assert "Outcome: unknown" in default
    assert "NOT_APPLICABLE result(s) hidden" in default
    assert "Classification: Not applicable" not in default
    assert "Classification: Not applicable" in detailed


def test_operational_diagnostics_are_compact_by_default_and_explained_in_details() -> None:
    report = _report(
        _configuration(
            "synthetic-unsupported-command enabled",
            "line vty 0 4",
            " login local",
            "!",
        )
    )
    default = render_terminal(report)
    detailed = render_terminal(report, details=True)

    assert "Operational diagnostics" in default
    assert "CG-PARSE-UNSUPPORTED-COMMAND" in default
    assert "A command was retained but could not be classified safely." not in default
    assert "A command was retained" in detailed
    assert "classified safely." in detailed


def test_terminal_redaction_holds_for_default_details_and_color() -> None:
    report = _report(
        _configuration(
            f"snmp-server community {SECRET} RW",
            "line vty 0 4",
            " transport input ssh",
            "!",
        )
    )

    for output in (
        render_terminal(report),
        render_terminal(report, details=True),
        render_terminal(report, details=True, color=True),
        render_html(report),
    ):
        assert SECRET not in output
        assert "[REDACTED]" in output


def test_version_output_remains_one_script_friendly_line(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["version"]) == ExitCode.COMPLETED

    assert capsys.readouterr().out == "ConfigGuard 0.1.0\n"


def _rule_ids() -> tuple[str, ...]:
    return (
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
        "CG-L2-003",
        "CG-L2-004",
        "CG-ACL-001",
        "CG-ACL-002",
        "CG-ROUTE-001",
        "CG-ROUTE-002",
        "CG-ROUTE-003",
    )
