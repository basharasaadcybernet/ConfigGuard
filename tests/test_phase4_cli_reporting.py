"""CLI and public-reporting tests using synthetic configuration only."""

from __future__ import annotations

import ast
import json
import tomllib
from pathlib import Path

import pytest

from configguard.analysis import AnalysisEngine, RuleRegistry
from configguard.cli import ExitCode, main
from configguard.domain import AssessmentOutcome, ParsedConfiguration
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource
from configguard.reporting import (
    AssessmentStatus,
    OutputWriteError,
    build_assessment_report,
    render_html,
    render_json,
    render_terminal,
    write_new_report,
)
from configguard.rules import RuleCategory, RuleEvaluation, RuleMetadata
from configguard.sanitization import CiscoEvidenceSanitizer

ROOT = Path(__file__).parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "SYNTHETIC-PHASE4-SECRET-MARKER"


def _write_config(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "synthetic-config.txt"
    path.write_text(body, encoding="utf-8")
    return path


def _supported_config(*commands: str) -> str:
    return "\n".join(("version 15.7", "hostname TEST", *commands, "end", ""))


def _report_for(text: str):  # type: ignore[no-untyped-def]
    parser = CiscoConfigurationParser()
    source = ConfigurationSource("synthetic.txt", text)
    parsed = parser.parse(source)
    from configguard.analysis import default_analysis_engine

    return build_assessment_report(
        parser.identify(source),
        parsed,
        default_analysis_engine().analyze(parsed),
    )


def test_console_entry_point_and_help_are_declared(capsys: pytest.CaptureFixture[str]) -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert metadata["project"]["scripts"]["configguard"] == "configguard.cli:main"
    with pytest.raises(SystemExit) as caught:
        main(["--help"])
    assert caught.value.code == 0
    assert "configguard scan" not in capsys.readouterr().err


def test_cli_version_and_argument_validation(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["version"]) == ExitCode.COMPLETED
    assert "ConfigGuard 0.1.0.dev0" in capsys.readouterr().out

    with pytest.raises(SystemExit) as caught:
        main(["scan", "synthetic.txt", "--output", "result.json"])
    assert caught.value.code == ExitCode.INVALID_INPUT
    assert "--output requires --format json" in capsys.readouterr().err


def test_successful_terminal_assessment_has_required_sections(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["scan", str(FIXTURES / "synthetic_ios_router.txt")])
    output = capsys.readouterr()

    assert exit_code == ExitCode.COMPLETED
    assert output.err == ""
    assert "ConfigGuard 0.1.0.dev0" in output.out
    assert "Assessment status" in output.out
    assert "completed" in output.out
    assert "Platform" in output.out
    assert "Cisco IOS" in output.out
    assert "Rules evaluated" in output.out
    assert "17" in output.out
    assert "Assessment summary" in output.out
    assert "Potential risk 1" in output.out
    assert "Sanitized evidence" in output.out
    assert "Recommendation:" in output.out
    assert "NOT_APPLICABLE result(s) hidden" in output.out
    assert "Evaluated rule identifiers" not in output.out
    assert "device or configuration is secure" in output.out
    assert "\x1b[" not in output.out


def test_json_stdout_is_valid_versioned_and_deterministic(
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = ["scan", str(FIXTURES / "synthetic_ios_router.txt"), "--format", "json"]
    assert main(arguments) == ExitCode.COMPLETED
    first = capsys.readouterr()
    assert main(arguments) == ExitCode.COMPLETED
    second = capsys.readouterr()

    payload = json.loads(first.out)
    assert first.err == second.err == ""
    assert first.out == second.out
    assert payload["report_schema_version"] == "1.0.0"
    assert payload["assessment_status"] == "completed"
    assert len(payload["evaluated_rule_ids"]) == 17
    assert payload["parser"]["status"] == "parsed"
    assert payload["platform"]["support"] == "supported"
    assert len(payload["findings"]) == 17
    assert "severity_summary" in payload
    assert "operational_diagnostics" in payload
    assert str(FIXTURES.resolve()) not in first.out


def test_all_renderers_redact_secrets_and_html_escapes_injected_content() -> None:
    report = _report_for(
        _supported_config(
            f"snmp-server community {SECRET} RW",
            "line vty 0 4",
            " transport input telnet <script>alert(1)</script>",
        )
    )
    outputs = (render_terminal(report), render_json(report), render_html(report))

    assert all(SECRET not in output for output in outputs)
    assert all("[REDACTED]" in output for output in outputs)
    assert "<script>alert(1)</script>" not in outputs[2]
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in outputs[2]
    assert "Content-Security-Policy" in outputs[2]
    assert "<script" not in outputs[2].lower()
    assert "http://" not in outputs[2]
    assert "https://cdn" not in outputs[2]


def test_html_has_all_required_offline_report_sections() -> None:
    html = render_html(_report_for((FIXTURES / "synthetic_ios_router.txt").read_text()))

    for section in (
        "Executive Summary",
        "Assessment Scope",
        "Device / Platform Information",
        "Assessment Completeness",
        "Severity Summary",
        "Findings and Evidence",
        "Security Impact",
        "Recommendations",
        "Technical References",
        "Methodology and Limitations",
    ):
        assert section in html
    assert "@media print" in html
    assert "@page" in html
    assert "@media (max-width: 700px)" in html
    assert "not an exploitation test" in html
    assert "finding-adverse" in html
    assert "finding-pass" in html
    assert "Zero counts are not" in html


def test_html_omits_empty_impact_recommendation_and_reference_sections() -> None:
    report = _report_for(
        _supported_config(
            "username SYNTHETIC-USER secret 9 SYNTHETIC-HASH",
            "no ip http server",
            "ip ssh version 2",
            "ip access-list standard MGMT",
            " permit 192.0.2.0 0.0.0.255",
            "line vty 0 4",
            " transport input ssh",
            " access-class MGMT in",
            " login local",
        )
    )
    html = render_html(report)

    assert report.assessment_status is AssessmentStatus.COMPLETED
    assert "finding-pass" in html
    assert "finding-observation" in html
    assert "<h2>Security Impact</h2>" not in html
    assert "<h2>Recommendations</h2>" not in html
    assert "<h2>Technical References</h2>" not in html
    assert "No security impact was asserted" not in html
    assert "No remediation recommendation applies" not in html


def test_html_uncertainty_has_evidence_guidance_and_useful_safe_diagnostics() -> None:
    report = _report_for(
        _supported_config(
            "synthetic-unclassified-command enabled",
            "no ip http server",
            "line vty 0 4",
            " login local",
        )
    )
    html = render_html(report)

    assert report.assessment_status is AssessmentStatus.PARTIAL
    assert "finding-uncertain" in html
    assert "Additional evidence needed" in html
    assert "explicit effective transport input" in html
    assert "does not infer device defaults" in html
    assert "CG-PARSE-UNSUPPORTED-COMMAND" in html
    assert "diagnostic-meta" in html
    assert "Parser · line 3" in html
    assert "unknown or unsupported results are not passes" in html.lower()


def test_json_and_html_files_require_explicit_new_destinations(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    json_path = tmp_path / "result.json"
    html_path = tmp_path / "report.html"
    source = str(FIXTURES / "synthetic_ios_router.txt")

    assert main(["scan", source, "--format", "json", "--output", str(json_path)]) == 0
    assert json.loads(json_path.read_text(encoding="utf-8"))["report_schema_version"] == "1.0.0"
    capsys.readouterr()
    assert main(["scan", source, "--report", str(html_path)]) == 0
    assert html_path.read_text(encoding="utf-8").startswith("<!doctype html>")
    capsys.readouterr()

    original = json_path.read_text(encoding="utf-8")
    assert main(["scan", source, "--format", "json", "--output", str(json_path)]) == 6
    output = capsys.readouterr()
    assert output.out == ""
    assert str(json_path) not in output.err
    assert json_path.read_text(encoding="utf-8") == original


def test_output_rejects_missing_directories_and_cleans_failed_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(OutputWriteError, match="invalid"):
        write_new_report(tmp_path / "missing" / "result.json", "{}")
    assert not (tmp_path / "missing").exists()

    def fail_link(source: object, target: object) -> None:
        del source, target
        raise PermissionError("PRIVATE-OS-DETAIL")

    monkeypatch.setattr("configguard.reporting.output.os.link", fail_link)
    with pytest.raises(OutputWriteError) as caught:
        write_new_report(tmp_path / "failed.json", "sensitive partial content")
    assert "PRIVATE-OS-DETAIL" not in str(caught.value)
    assert not (tmp_path / "failed.json").exists()
    assert not tuple(tmp_path.glob(".configguard-*.tmp"))


def test_unsupported_and_incomplete_inputs_have_distinct_exit_codes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    unsupported = _write_config(tmp_path, "system {\n host-name PRIVATE-PATH-MARKER;\n}\n")
    assert main(["scan", str(unsupported)]) == ExitCode.UNSUPPORTED_CONFIGURATION
    error = capsys.readouterr()
    assert error.out == ""
    assert str(unsupported) not in error.err
    assert "PRIVATE-PATH-MARKER" not in error.err

    incomplete = _write_config(
        tmp_path,
        _supported_config(
            "line vty 0 4",
            " transport input ssh",
            "banner motd ^C",
            SECRET,
        ),
    )
    assert main(["scan", str(incomplete)]) == ExitCode.PARTIAL_ASSESSMENT
    output = capsys.readouterr()
    assert "Assessment status" in output.out
    assert "partial" in output.out
    assert "Parser completeness" in output.out
    assert "incomplete" in output.out
    assert SECRET not in output.out + output.err


class _ExplodingRule:
    metadata = RuleMetadata(
        rule_id="TEST-FAILURE",
        title="Synthetic failure",
        category=RuleCategory.DEVICE_HARDENING,
        description="Exercises report failure isolation.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        del configuration
        raise RuntimeError(SECRET)


def test_rule_failure_remains_partial_and_separate_from_security_findings() -> None:
    parser = CiscoConfigurationParser()
    source = ConfigurationSource(
        "synthetic.txt",
        _supported_config("line vty 0 4", " transport input ssh"),
    )
    parsed = parser.parse(source)
    analysis = AnalysisEngine(
        RuleRegistry((_ExplodingRule(),)),
        CiscoEvidenceSanitizer(),
    ).analyze(parsed)
    report = build_assessment_report(parser.identify(source), parsed, analysis)
    public = render_json(report)

    assert report.assessment_status is AssessmentStatus.PARTIAL
    assert report.findings[0].outcome is AssessmentOutcome.NOT_EVALUATED
    assert len(report.diagnostics) == 1
    assert SECRET not in public
    assert "CG-ENGINE-RULE-FAILURE" in public


def test_unexpected_cli_failure_hides_exception_and_path(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    private_path = f"C:/private/{SECRET}/router.txt"

    def explode(self: object, path: object) -> None:
        del self, path
        raise RuntimeError(f"{SECRET} {private_path}")

    monkeypatch.setattr("configguard.application.ConfigurationIngestor.read", explode)
    assert main(["scan", private_path]) == ExitCode.INTERNAL_FAILURE
    output = capsys.readouterr()

    assert output.out == ""
    assert SECRET not in output.err
    assert private_path not in output.err
    assert "internal_failure" in output.err


def test_report_rendering_failure_uses_output_exit_code_without_leaking(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def explode(report: object) -> str:
        del report
        raise RuntimeError(SECRET)

    monkeypatch.setattr("configguard.cli.render_json", explode)
    exit_code = main(["scan", str(FIXTURES / "synthetic_ios_router.txt"), "--format", "json"])
    output = capsys.readouterr()

    assert exit_code == ExitCode.OUTPUT_FAILURE
    assert output.out == ""
    assert SECRET not in output.err
    assert "output_failure" in output.err


def test_cli_and_reporting_modules_have_no_network_client_imports() -> None:
    forbidden = {"socket", "requests", "httpx", "urllib", "ftplib", "smtplib"}
    paths = [
        ROOT / "src/configguard/cli.py",
        *sorted((ROOT / "src/configguard/reporting").glob("*.py")),
    ]

    for path in paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        assert imported.isdisjoint(forbidden), path
