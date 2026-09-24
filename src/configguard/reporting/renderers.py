"""Deterministic terminal, JSON, and self-contained HTML rendering."""

from __future__ import annotations

import json
from html import escape

from configguard import __version__
from configguard.analysis import Finding
from configguard.domain import AssessmentOutcome
from configguard.reporting.models import AssessmentReport, OperationalDiagnostic

_OUTCOME_LABELS = {
    AssessmentOutcome.SECURE: "Explicit supported check",
    AssessmentOutcome.CONFIRMED_INSECURE: "Confirmed weakness",
    AssessmentOutcome.POTENTIAL_RISK: "Potential risk",
    AssessmentOutcome.HARDENING: "Hardening recommendation",
    AssessmentOutcome.NOT_APPLICABLE: "Not applicable",
    AssessmentOutcome.UNKNOWN: "Unknown result",
    AssessmentOutcome.NOT_EVALUATED: "Evaluation failure",
    AssessmentOutcome.UNSUPPORTED_SYNTAX: "Unsupported syntax",
}


def render_json(report: AssessmentReport) -> str:
    """Render valid, stable JSON with no progress or terminal decoration."""

    return json.dumps(report.to_public_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def render_terminal(report: AssessmentReport) -> str:
    """Render a readable plain-text assessment for an interactive terminal."""

    lines = [
        f"ConfigGuard {__version__}",
        "Static Configuration Security Assessment",
        "",
        f"Assessment status: {report.assessment_status.value}",
        (
            f"Platform: {_display_platform(report.platform_family)} "
            f"(inferred from configuration syntax; confidence {report.platform_confidence:.2f})"
        ),
        f"Platform support: {report.platform_support}",
        f"Parser completeness: {report.parser_status}",
        f"Implemented rules evaluated: {len(report.evaluated_rule_ids)}",
        "Rule identifiers: " + ", ".join(report.evaluated_rule_ids),
        "",
        "Severity summary",
    ]
    severity = report.severity_summary()
    lines.extend(
        f"  {name.title()}: {severity[name]}"
        for name in ("critical", "high", "medium", "low", "info")
    )
    lines.extend(("", "Findings and rule results"))
    for finding in report.findings:
        lines.extend(_terminal_finding(finding))

    confirmed = report.outcome_summary()[AssessmentOutcome.CONFIRMED_INSECURE.value]
    if confirmed == 0:
        lines.extend(
            (
                "",
                "No confirmed weaknesses were identified by the implemented rules.",
                "This does not establish that the device or configuration is secure.",
            )
        )

    lines.extend(("", "Operational diagnostics"))
    if report.diagnostics:
        for item in report.diagnostics:
            rule = f" [{item.rule_id}]" if item.rule_id else ""
            location = f" (line {item.line_start})" if item.line_start is not None else ""
            lines.append(f"  - {item.code}{rule}{location}: {item.message}")
    else:
        lines.append("  None.")

    lines.extend(("", "Assessment limitations"))
    lines.extend(f"  - {item}" for item in report.limitations)
    return "\n".join(lines) + "\n"


def _terminal_finding(finding: Finding) -> list[str]:
    severity = finding.severity.value if finding.severity is not None else "none"
    lines = [
        "",
        f"[{finding.rule_id}] {finding.title}",
        f"  Classification: {_OUTCOME_LABELS[finding.outcome]}",
        f"  Outcome: {finding.outcome.value}",
        f"  Severity: {severity}",
        f"  Evidence confidence: {finding.confidence.value}",
        f"  Summary: {finding.description}",
    ]
    if finding.evidence:
        lines.append("  Safe technical evidence:")
        for item in finding.evidence:
            location = _line_range(item.location.line_start, item.location.line_end)
            provenance = _evidence_provenance(item.target_interface, item.resolution_origin)
            lines.append(f"    - {location}{provenance}: {item.redacted_excerpt}")
    else:
        lines.append("  Safe technical evidence: none available")
    if finding.impact:
        lines.append(f"  Security impact: {finding.impact}")
    if finding.recommendation:
        lines.append(f"  Recommendation: {finding.recommendation}")
    if finding.technical_references:
        lines.append("  Technical references: " + ", ".join(finding.technical_references))
    guidance = _additional_evidence_guidance(finding)
    if guidance is not None:
        lines.append(f"  Additional evidence needed: {guidance}")
    for limitation in finding.limitations:
        lines.append(f"  Limitation: {limitation}")
    return lines


def render_html(report: AssessmentReport) -> str:
    """Render an escaped, offline, printable report with a restrictive CSP."""

    findings = "".join(_html_finding(item) for item in report.findings)
    references = tuple(
        dict.fromkeys(
            reference for finding in report.findings for reference in finding.technical_references
        )
    )
    diagnostics = "".join(_html_diagnostic(item) for item in report.diagnostics)
    if not diagnostics:
        diagnostics = '<p class="empty-state">No operational diagnostics were produced.</p>'
    severity = report.severity_summary()
    outcome = report.outcome_summary()
    no_confirmed = ""
    if outcome[AssessmentOutcome.CONFIRMED_INSECURE.value] == 0:
        no_confirmed = (
            '<p class="notice">No confirmed weaknesses were identified by the implemented '
            "rules. This does not establish that the device is secure.</p>"
        )

    rule_items = "".join(
        f"<li><code>{escape(rule_id)}</code></li>" for rule_id in report.evaluated_rule_ids
    )
    severity_items = "".join(
        f"<div><strong>{severity[name]}</strong><span>{escape(name.title())}</span></div>"
        for name in ("critical", "high", "medium", "low", "info")
    )
    reference_items = "".join(
        f'<li><a href="{escape(item, quote=True)}">{escape(item)}</a></li>' for item in references
    )
    limitation_items = "".join(f"<li>{escape(item)}</li>" for item in report.limitations)
    unknown_count = outcome["unknown"] + outcome["not_evaluated"] + outcome["unsupported_syntax"]
    impact_items = _html_field_list(report.findings, "impact")
    recommendation_items = _html_field_list(report.findings, "recommendation")
    impact_section = (
        f"<section><h2>7. Security Impact</h2>{impact_items}</section>" if impact_items else ""
    )
    recommendation_section = (
        f"<section><h2>8. Recommendations</h2>{recommendation_items}</section>"
        if recommendation_items
        else ""
    )
    reference_section = (
        f"<section><h2>9. Technical References</h2><ul>{reference_items}</ul></section>"
        if reference_items
        else ""
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;
               base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
<title>ConfigGuard Security Assessment</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<header>
<p class="eyebrow">ConfigGuard {escape(__version__)}</p>
<h1>Static Configuration Security Assessment</h1>
<p class="status">Assessment status:
<strong>{escape(report.assessment_status.value)}</strong></p>
</header>
<section><h2>1. Executive Summary</h2>
<p>ConfigGuard evaluated {len(report.evaluated_rule_ids)} implemented rules.
Confirmed weaknesses: {outcome["confirmed_insecure"]};
potential risks: {outcome["potential_risk"]};
unknown or unevaluated results: {unknown_count}.</p>{no_confirmed}</section>
<section><h2>2. Assessment Scope</h2>
<p>Offline analysis of one explicitly selected Cisco-style configuration using these rules:</p>
<ul>{rule_items}</ul></section>
<section><h2>3. Device / Platform Information</h2><dl>
<dt>Platform family</dt><dd>{escape(_display_platform(report.platform_family))}</dd>
<dt>Identification</dt><dd>Inferred from configuration syntax;
confidence {report.platform_confidence:.2f}</dd>
<dt>Support</dt><dd>{escape(report.platform_support)}</dd>
<dt>Identification detail</dt><dd>{escape(report.platform_identification)}</dd>
</dl></section>
<section><h2>4. Assessment Completeness</h2><dl>
<dt>Parser status</dt><dd>{escape(report.parser_status)}</dd>
<dt>Commands classified</dt>
<dd>{report.classified_command_count} of {report.command_count}</dd>
<dt>Unsupported commands</dt><dd>{report.unsupported_command_count}</dd>
<dt>Structured observations</dt><dd>{report.observation_count}</dd>
</dl></section>
<section><h2>5. Severity Summary</h2>
<div class="summary">{severity_items}</div>
<p class="summary-note">Severity counts apply only to adverse findings. Zero counts are not
proof of security and do not include unknown, unsupported, or unevaluated results.</p></section>
<section class="major-break"><h2>6. Findings and Evidence</h2>
<p class="section-intro">Cards distinguish security findings, passing observations,
uncertainty, and applicability. Unknown or unsupported results are not passes.</p>
{findings}</section>
{impact_section}
{recommendation_section}
{reference_section}
<section><h2>10. Operational Diagnostics</h2>{diagnostics}</section>
<section><h2>11. Methodology and Limitations</h2>
<p>This report was produced through bounded local ingestion, context-aware parsing,
deterministic rule evaluation, and centralized evidence sanitization.</p>
<ul>{limitation_items}</ul></section>
</main>
</body>
</html>
"""


def _html_finding(finding: Finding) -> str:
    severity = finding.severity.value if finding.severity is not None else "none"
    card_class = _finding_card_class(finding.outcome)
    evidence = (
        "".join(
            '<li><span class="line">'
            + escape(_line_range(item.location.line_start, item.location.line_end))
            + escape(_evidence_provenance(item.target_interface, item.resolution_origin))
            + "</span><code>"
            + escape(item.redacted_excerpt)
            + "</code></li>"
            for item in finding.evidence
        )
        or "<li>No safe evidence is available.</li>"
    )
    limitations = "".join(f"<li>{escape(item)}</li>" for item in finding.limitations)
    guidance = _additional_evidence_guidance(finding)
    guidance_block = (
        '<aside class="evidence-needed"><h4>Additional evidence needed</h4>'
        f"<p>{escape(guidance)}</p></aside>"
        if guidance is not None
        else ""
    )
    return (
        f'<article class="finding {card_class}">'
        f"<h3>{escape(finding.rule_id)} — {escape(finding.title)}</h3>"
        f'<p class="classification">{escape(_OUTCOME_LABELS[finding.outcome])}</p>'
        f"<dl><dt>Outcome</dt><dd>{escape(finding.outcome.value)}</dd>"
        f"<dt>Severity</dt><dd>{escape(severity)}</dd>"
        f"<dt>Evidence confidence</dt><dd>{escape(finding.confidence.value)}</dd></dl>"
        f"<p>{escape(finding.description)}</p>{guidance_block}"
        f"<h4>Safe technical evidence</h4><ul>{evidence}</ul>"
        f"<h4>Finding limitations</h4><ul>{limitations or '<li>None stated.</li>'}</ul>"
        "</article>"
    )


def _evidence_provenance(target: str | None, origin: str | None) -> str:
    if target is None:
        return ""
    origin_label = f", {origin}" if origin is not None else ""
    return f" [target: {target}{origin_label}]"


def _html_field_list(
    findings: tuple[Finding, ...],
    attribute: str,
) -> str:
    items = []
    for finding in findings:
        value = getattr(finding, attribute)
        if isinstance(value, str):
            items.append(f"<li><strong>{escape(finding.rule_id)}</strong> — {escape(value)}</li>")
    return "<ul>" + "".join(items) + "</ul>" if items else ""


def _finding_card_class(outcome: AssessmentOutcome) -> str:
    if outcome in {
        AssessmentOutcome.CONFIRMED_INSECURE,
        AssessmentOutcome.POTENTIAL_RISK,
        AssessmentOutcome.HARDENING,
    }:
        return "finding-adverse"
    if outcome is AssessmentOutcome.SECURE:
        return "finding-pass"
    if outcome in {AssessmentOutcome.UNKNOWN, AssessmentOutcome.UNSUPPORTED_SYNTAX}:
        return "finding-uncertain"
    if outcome is AssessmentOutcome.NOT_EVALUATED:
        return "finding-failure"
    return "finding-observation"


def _additional_evidence_guidance(finding: Finding) -> str | None:
    if finding.outcome not in {
        AssessmentOutcome.UNKNOWN,
        AssessmentOutcome.UNSUPPORTED_SYNTAX,
        AssessmentOutcome.NOT_EVALUATED,
    }:
        return None
    if finding.outcome is AssessmentOutcome.NOT_EVALUATED:
        return "Resolve the associated operational diagnostic and rerun the assessment."
    guidance = {
        "CG-MGMT-001": (
            "Provide complete VTY line sections with an explicit effective transport input "
            "setting for every VTY range."
        ),
        "CG-MGMT-006": (
            "Provide an explicit supported plaintext HTTP server enable or disable command."
        ),
        "CG-MGMT-002": (
            "Provide an explicit supported SSH version selection or authoritative platform "
            "runtime evidence; ConfigGuard does not infer device defaults."
        ),
        "CG-SNMP-001": (
            "Provide complete supported SNMP community declarations, including explicit "
            "access modes where configured."
        ),
        "CG-SNMP-002": (
            "Provide complete supported SNMP community declarations and any referenced ACL "
            "definitions."
        ),
        "CG-MGMT-003": (
            "Provide complete VTY line sections, each effective inbound access-class, and all "
            "referenced ACL definitions."
        ),
        "CG-MGMT-005": (
            "Provide complete supported local-user, enable, and management-line credential "
            "commands with explicit storage types where available."
        ),
        "CG-MGMT-004": (
            "Provide complete VTY and console login commands plus referenced local-user or AAA "
            "method-list prerequisites."
        ),
        "CG-L2-001": (
            "Provide explicit supported switchport role, Port Security state, and violation "
            "mode for each applicable access interface."
        ),
        "CG-L2-002": (
            "Provide explicit global and VLAN DHCP Snooping state plus supported access VLAN "
            "and trust settings for each applicable interface."
        ),
        "CG-L2-003": (
            "Provide explicit DAI VLAN selection, access VLAN and trust state, and a supported "
            "binding source including modeled DHCP Snooping VLAN and interface trust state."
        ),
        "CG-L2-004": (
            "Provide supported PortFast or edge-port state and the effective global or "
            "per-interface BPDU Guard setting."
        ),
    }
    return guidance.get(
        finding.rule_id,
        "Provide complete supported configuration evidence for this rule and rerun the assessment.",
    )


def _html_diagnostic(diagnostic: OperationalDiagnostic) -> str:
    metadata = [diagnostic.source.title()]
    if diagnostic.rule_id is not None:
        metadata.append(diagnostic.rule_id)
    if diagnostic.line_start is not None:
        line_end = diagnostic.line_end or diagnostic.line_start
        metadata.append(_line_range(diagnostic.line_start, line_end))
    return (
        '<article class="diagnostic">'
        f"<h3>{escape(diagnostic.code)}</h3>"
        f'<p class="diagnostic-meta">{escape(" · ".join(metadata))}</p>'
        f"<p>{escape(diagnostic.message)}</p>"
        "</article>"
    )


def _line_range(start: int, end: int) -> str:
    return f"line {start}" if start == end else f"lines {start}-{end}"


def _display_platform(value: str) -> str:
    return {
        "cisco_ios": "Cisco IOS",
        "cisco_ios_xe": "Cisco IOS XE",
        "unknown": "Compatible Cisco IOS-style platform (exact family unknown)",
        "unsupported": "Unsupported platform",
    }.get(value, "Unknown platform")


_CSS = """
:root { color-scheme: light; --ink: #172033; --muted: #5b6475; --line: #d7dce5;
  --soft: #f4f6f9; --accent: #234c7a; --pass: #287552; --warn: #a66116;
  --risk: #a63f3f; --failure: #6f4b8b; }
* { box-sizing: border-box; }
body { margin: 0; background: #eef1f5; color: var(--ink);
  font: 15px/1.65 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { width: min(1040px, calc(100% - 32px)); margin: 32px auto; background: #fff;
  padding: 48px; border: 1px solid var(--line); box-shadow: 0 10px 30px #17203312; }
header { border-bottom: 3px solid var(--accent); padding-bottom: 24px; }
.eyebrow { color: var(--accent); font-weight: 700; letter-spacing: .08em;
  text-transform: uppercase; }
h1 { font-size: 2.1rem; line-height: 1.15; margin: .2rem 0; }
h2 { font-size: 1.35rem; margin-top: 2.4rem; border-bottom: 1px solid var(--line);
  padding-bottom: .45rem; }
h3 { font-size: 1.05rem; margin-top: 0; }
h4 { margin-bottom: .3rem; }
p, li, dd { max-width: 78ch; }
.status, .notice { padding: 12px 16px; background: var(--soft);
  border-left: 4px solid var(--accent); }
.section-intro, .summary-note, .empty-state { color: var(--muted); }
dl { display: grid; grid-template-columns: minmax(150px, 220px) 1fr; gap: 7px 18px; }
dt { font-weight: 700; }
dd { margin: 0; }
.summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; }
.summary div { padding: 16px; background: var(--soft); text-align: center; }
.summary strong, .summary span { display: block; }
.summary strong { font-size: 1.5rem; }
.finding { border: 1px solid var(--line); border-radius: 6px; padding: 20px;
  margin: 16px 0; break-inside: avoid-page; border-left-width: 5px; }
.finding-adverse { border-left-color: var(--risk); }
.finding-pass { border-left-color: var(--pass); }
.finding-uncertain { border-left-color: var(--warn); background: #fffbf4; }
.finding-failure { border-left-color: var(--failure); background: #fbf7fd; }
.finding-observation { border-left-color: var(--muted); }
.classification { display: inline-block; background: var(--soft); padding: 4px 9px;
  font-weight: 700; }
.evidence-needed { margin: 14px 0; padding: 12px 16px; background: #fff4df;
  border-left: 3px solid var(--warn); }
.evidence-needed h4 { margin-top: 0; }
.diagnostic { border: 1px solid var(--line); padding: 14px 18px; margin: 12px 0;
  break-inside: avoid-page; }
.diagnostic h3 { margin-bottom: 0; }
.diagnostic-meta { color: var(--muted); margin: 2px 0 8px; font-size: .92rem; }
code { white-space: pre-wrap; overflow-wrap: anywhere; }
.line { color: var(--muted); margin-right: 8px; }
a { color: var(--accent); overflow-wrap: anywhere; }
@page { margin: 16mm 14mm; }
@media (max-width: 700px) {
  main { width: 100%; margin: 0; padding: 22px; }
  dl { grid-template-columns: 1fr; }
  .summary { grid-template-columns: repeat(2, 1fr); }
}
@media print {
  body { background: #fff; }
  main { width: 100%; margin: 0; padding: 0; border: 0; box-shadow: none;
    font-size: 10.5pt; line-height: 1.5; }
  header { break-after: avoid-page; }
  h2, h3, h4 { break-after: avoid-page; }
  .major-break { break-before: page; }
  .finding, .diagnostic, dl, ul { break-inside: avoid-page; page-break-inside: avoid; }
  .summary { break-inside: avoid-page; }
  a { color: inherit; text-decoration: none; }
}
"""
