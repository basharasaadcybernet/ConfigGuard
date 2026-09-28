"""Focused regressions for Phase 8D report and assessment UX polish."""

from __future__ import annotations

import json
from pathlib import Path

from configguard.analysis import default_analysis_engine
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource
from configguard.reporting import (
    REPORT_SCHEMA_VERSION,
    AssessmentStatus,
    build_assessment_report,
    partial_status_explanation,
    render_html,
    render_json,
)
from configguard.web import WebApplication

ROOT = Path(__file__).parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
SECRET = "SYNTHETIC-PHASE8D-SECRET-MARKER"


def _report(label: str, text: str):  # type: ignore[no-untyped-def]
    parser = CiscoConfigurationParser()
    source = ConfigurationSource(label, text)
    configuration = parser.parse(source)
    return build_assessment_report(
        parser.identify(source),
        configuration,
        default_analysis_engine().analyze(configuration),
    )


def _supported_config(*commands: str) -> str:
    return "\n".join(
        (
            "version 15.7",
            "hostname SYNTHETIC",
            *commands,
            "ip ssh version 2",
            "no ip http server",
            "line vty 0 4",
            " transport input ssh",
            " login local",
            "end",
            "",
        )
    )


def test_html_uses_safe_escaped_basename_without_host_path_leakage() -> None:
    private_path = "C:\\Users\\private-user\\Temp\\router<script>.txt"
    report = _report(private_path, _supported_config("no ip http server"))
    html = render_html(report)

    assert report.source_basename == "router<script>.txt"
    assert "router&lt;script&gt;.txt" in html
    assert private_path not in html
    assert "private-user" not in html
    assert "<script>" not in html.lower()
    assert "source_basename" not in render_json(report)


def test_html_omits_empty_noise_but_keeps_useful_uncertainty_guidance() -> None:
    complete = _report(
        "synthetic.txt",
        (FIXTURES / "synthetic_ios_router.txt").read_text(encoding="utf-8"),
    )
    partial = _report(
        "synthetic.txt",
        _supported_config(
            "synthetic-unsupported-command enabled",
            "line vty 0 4",
            " login local",
        ),
    )
    complete_html = render_html(complete)
    partial_html = render_html(partial)

    for meaningless in ("No safe evidence is available", "None stated"):
        assert meaningless not in complete_html
        assert meaningless not in partial_html
    assert "<h2>Operational Diagnostics</h2>" not in complete_html
    assert "<h2>Operational Diagnostics</h2>" in partial_html
    assert "Additional evidence needed" in partial_html


def test_partial_status_explains_distinct_completeness_and_uncertainty_concepts() -> None:
    partial = _report(
        "synthetic.txt",
        _supported_config("synthetic-unsupported-command enabled"),
    )
    explanation = partial_status_explanation(partial)

    assert partial.assessment_status is AssessmentStatus.PARTIAL
    assert explanation is not None
    for concept in (
        "assessment completed",
        "part of the file was read",
        "parser crashed",
        "Parser completeness",
        "platform confidence",
        "rule-level",
        "unsupported syntax",
        "missing configuration evidence",
    ):
        assert concept in explanation
    assert explanation in render_html(partial)

    completed = _report(
        "synthetic.txt",
        (FIXTURES / "synthetic_ios_router.txt").read_text(encoding="utf-8"),
    )
    assert partial_status_explanation(completed) is None


def test_html_scope_leads_with_categories_and_keeps_ids_in_compact_details() -> None:
    report = _report(
        "synthetic.txt",
        (FIXTURES / "synthetic_ios_router.txt").read_text(encoding="utf-8"),
    )
    html = render_html(report)
    scope_start = html.index("<h2>Assessment Scope</h2>")
    details_start = html.index('<details class="scope-details">', scope_start)
    category_summary = html[scope_start:details_start]

    for label in (
        "Management Plane",
        "SNMP",
        "Layer 2",
        "Interface ACL",
        "Routing Authentication",
    ):
        assert label in category_summary
    assert all(rule_id not in category_summary for rule_id in report.evaluated_rule_ids)
    assert "17 rule identifiers" in html
    assert all(rule_id in html[details_start:] for rule_id in report.evaluated_rule_ids)


def test_html_reference_labels_and_print_css_remain_offline_and_readable() -> None:
    report = _report(
        "synthetic.txt",
        (FIXTURES / "synthetic_ios_router.txt").read_text(encoding="utf-8"),
    )
    html = render_html(report)
    rfc_url = "https://www.rfc-editor.org/rfc/rfc3414"

    assert f'href="{rfc_url}"' in html
    assert "RFC 3414 — SNMPv3 User-based Security Model" in html
    assert f">{rfc_url}</a>" not in html
    for print_contract in (
        "@page",
        "@media print",
        "break-inside: avoid-page",
        "print-color-adjust: exact",
        "break-before: page",
    ):
        assert print_contract in html
    assert "https://cdn" not in html
    assert "<script" not in html.lower()


def test_secret_redaction_survives_visual_polish() -> None:
    report = _report(
        "synthetic.txt",
        _supported_config(
            f"username TEST secret 9 {SECRET}",
            f"snmp-server community {SECRET} RW",
            "line vty 0 4",
            " transport input telnet",
        ),
    )
    html = render_html(report)

    assert SECRET not in html
    assert "[REDACTED]" in html


def test_json_schema_and_semantics_are_unchanged_by_presentation_fields() -> None:
    report = _report(
        "C:/private/customer/router.txt",
        (FIXTURES / "synthetic_ios_router.txt").read_text(encoding="utf-8"),
    )
    public = report.to_public_dict()
    rendered = json.loads(render_json(report))

    assert REPORT_SCHEMA_VERSION == "1.0.0"
    assert rendered == public
    assert set(rendered) == {
        "assessment_limitations",
        "assessment_status",
        "configguard_version",
        "evaluated_rule_ids",
        "findings",
        "operational_diagnostics",
        "outcome_summary",
        "parser",
        "platform",
        "report_schema_version",
        "severity_summary",
    }
    assert "router.txt" not in render_json(report)
    assert "C:/private" not in render_json(report)


def test_web_uses_backend_rule_count_and_returns_partial_explanation() -> None:
    template = (ROOT / "src/configguard/web_assets/index.html").read_text(encoding="utf-8")
    application = WebApplication(request_token="synthetic-phase8d-token")
    index = application.index().decode("utf-8")
    response = application.scan(
        "synthetic.txt",
        _supported_config("synthetic-unsupported-command enabled").encode("utf-8"),
    )

    assert "__CONFIGGUARD_RULE_COUNT__" in template
    assert "17 deterministic, explainable security checks" not in template
    assert "__CONFIGGUARD_RULE_COUNT__" not in index
    assert "17 deterministic, explainable security checks" in index
    assert len(response["assessment"]["evaluated_rule_ids"]) == 17  # type: ignore[index]
    partial = response["presentation"]["partial_status"]  # type: ignore[index]
    assert isinstance(partial, str)
    assert "assessment completed" in partial
