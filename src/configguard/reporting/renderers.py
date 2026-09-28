"""Deterministic terminal, JSON, and self-contained HTML rendering."""

from __future__ import annotations

import json
from base64 import b64encode
from html import escape
from importlib.resources import files
from io import StringIO

from rich import box
from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from configguard import __version__
from configguard.analysis import Finding
from configguard.domain import AssessmentOutcome
from configguard.reporting.models import AssessmentReport, AssessmentStatus, OperationalDiagnostic

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

_OUTCOME_STYLES = {
    AssessmentOutcome.SECURE: "bold green",
    AssessmentOutcome.CONFIRMED_INSECURE: "bold red",
    AssessmentOutcome.POTENTIAL_RISK: "bold bright_red",
    AssessmentOutcome.HARDENING: "bold yellow",
    AssessmentOutcome.NOT_APPLICABLE: "dim",
    AssessmentOutcome.UNKNOWN: "bold yellow",
    AssessmentOutcome.NOT_EVALUATED: "bold magenta",
    AssessmentOutcome.UNSUPPORTED_SYNTAX: "bold magenta",
}

_OUTCOME_ORDER = (
    AssessmentOutcome.CONFIRMED_INSECURE,
    AssessmentOutcome.POTENTIAL_RISK,
    AssessmentOutcome.HARDENING,
    AssessmentOutcome.UNKNOWN,
    AssessmentOutcome.UNSUPPORTED_SYNTAX,
    AssessmentOutcome.NOT_EVALUATED,
    AssessmentOutcome.SECURE,
    AssessmentOutcome.NOT_APPLICABLE,
)

_REFERENCE_LABELS = {
    "https://www.rfc-editor.org/rfc/rfc854": "RFC 854 — Telnet Protocol Specification",
    "https://www.rfc-editor.org/rfc/rfc9110": "RFC 9110 — HTTP Semantics",
    "https://www.rfc-editor.org/rfc/rfc4253": "RFC 4253 — SSH Transport Layer Protocol",
    "https://www.rfc-editor.org/rfc/rfc3414": ("RFC 3414 — SNMPv3 User-based Security Model"),
    "https://www.rfc-editor.org/rfc/rfc3415": ("RFC 3415 — SNMPv3 View-based Access Control Model"),
    (
        "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/"
        "application-services/b-application-services/m-bba-vrf-aware-access-class-line.html"
    ): "Cisco IOS XE VTY Access-Class Configuration",
    (
        "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/"
        "15-mt/sec-usr-cfg-15-mt-book/sec-cfg-sec-4cli.html"
    ): "Cisco IOS Password Security Configuration Guide",
    (
        "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/security-vpn/security-vpn/"
        "m_sec-cfg-authentifcn-0.html"
    ): "Cisco IOS XE Authentication Configuration Guide",
}

_SCOPE_CATEGORIES = (
    ("CG-MGMT-", "Management Plane"),
    ("CG-SNMP-", "SNMP"),
    ("CG-L2-", "Layer 2"),
    ("CG-ACL-", "Interface ACL"),
    ("CG-ROUTE-", "Routing Authentication"),
)

_BRAND_LOGO_DATA_URI = "data:image/svg+xml;base64," + b64encode(
    files("configguard").joinpath("web_assets", "brand-mark.svg").read_bytes()
).decode("ascii")


def render_json(report: AssessmentReport) -> str:
    """Render valid, stable JSON with no progress or terminal decoration."""

    return json.dumps(report.to_public_dict(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def partial_status_explanation(report: AssessmentReport) -> str | None:
    """Explain a partial assessment without implying truncated input or a parser crash."""

    if report.assessment_status is not AssessmentStatus.PARTIAL:
        return None
    return (
        "Partial means the assessment completed, but one or more rule conclusions remain "
        "uncertain; it does not mean only part of the file was read or that the parser "
        "crashed. Parser completeness describes recognized syntax, platform confidence "
        f"({report.platform_confidence:.2f}) describes device-family identification, and "
        "rule-level Unknown, Unsupported, or Not Evaluated results can reflect unsupported "
        "syntax or missing configuration evidence."
    )


def render_terminal(
    report: AssessmentReport,
    *,
    details: bool = False,
    color: bool = False,
    width: int = 100,
) -> str:
    """Render a sanitized Rich terminal report with deterministic non-color output."""

    output = StringIO()
    console = Console(
        file=output,
        force_terminal=color,
        no_color=not color,
        color_system="standard" if color else None,
        width=max(40, min(width, 120)),
        highlight=False,
        legacy_windows=False,
    )
    panel_box = box.ROUNDED if color else box.ASCII2

    heading = Text("Static Configuration Security Assessment", style="bold")
    subtitle = Text("Local | Static | Read-only", style="dim")
    console.print(
        Panel(
            Group(heading, subtitle),
            title=f"ConfigGuard {__version__}",
            border_style="cyan",
            box=panel_box,
        )
    )

    overview = Table.grid(expand=True, padding=(0, 1))
    overview.add_column(style="bold", no_wrap=True)
    overview.add_column(ratio=1)
    overview.add_row("Assessment status", report.assessment_status.value)
    overview.add_row(
        "Platform",
        (
            f"{_display_platform(report.platform_family)}; support {report.platform_support}; "
            f"inference confidence {report.platform_confidence:.2f}"
        ),
    )
    overview.add_row("Parser completeness", report.parser_status)
    overview.add_row("Rules evaluated", str(len(report.evaluated_rule_ids)))
    overview.add_row("Operational diagnostics", str(len(report.diagnostics)))
    console.print(Panel(overview, title="Overview", box=panel_box, border_style="blue"))

    counts = Group(
        _terminal_count_line("Outcomes", _outcome_count_items(report)),
        _terminal_count_line("Severity", _severity_count_items(report)),
    )
    console.print(Panel(counts, title="Assessment summary", box=panel_box, border_style="blue"))

    rule_character = "─" if color else "-"
    console.rule("Security results", characters=rule_character, style="bold blue")
    visible = tuple(
        finding
        for finding in report.findings
        if details or finding.outcome is not AssessmentOutcome.NOT_APPLICABLE
    )
    for finding in visible:
        _render_terminal_finding(console, finding, details=details, panel_box=panel_box)

    hidden = len(report.findings) - len(visible)
    if hidden:
        console.print(
            Text(
                f"{hidden} NOT_APPLICABLE result(s) hidden in the default view. "
                "Use --details to display all rule results.",
                style="dim",
            )
        )

    confirmed = report.outcome_summary()[AssessmentOutcome.CONFIRMED_INSECURE.value]
    if confirmed == 0:
        console.print(
            Panel(
                "No confirmed weaknesses were identified by the implemented rules. "
                "This does not establish that the device or configuration is secure.",
                title="Assessment notice",
                border_style="yellow",
                box=panel_box,
            )
        )

    if report.diagnostics:
        _render_terminal_diagnostics(console, report, details=details, panel_box=panel_box)

    if details:
        console.rule("Detailed scope", characters=rule_character, style="bold blue")
        console.print(
            Panel(
                Text(", ".join(report.evaluated_rule_ids), overflow="fold"),
                title="Evaluated rule identifiers",
                box=panel_box,
            )
        )
        limitations = Group(*(Text(f"- {item}") for item in report.limitations))
        console.print(Panel(limitations, title="Assessment limitations", box=panel_box))

    return output.getvalue()


def _render_terminal_finding(
    console: Console,
    finding: Finding,
    *,
    details: bool,
    panel_box: box.Box,
) -> None:
    severity = finding.severity.value if finding.severity is not None else "none"
    outcome_style = _OUTCOME_STYLES[finding.outcome]
    content: list[RenderableType] = [
        _terminal_field("Classification", _OUTCOME_LABELS[finding.outcome], outcome_style),
        _terminal_field("Outcome", finding.outcome.value, outcome_style),
        _terminal_field("Severity", severity, _severity_style(severity)),
        _terminal_field("Confidence", finding.confidence.value),
        _terminal_field("Summary", finding.description),
    ]

    if finding.impact:
        content.append(_terminal_field("Security impact", finding.impact))
    if finding.recommendation:
        content.append(_terminal_field("Recommendation", finding.recommendation))
    guidance = additional_evidence_guidance(finding)
    if guidance is not None:
        content.append(_terminal_field("Additional evidence needed", guidance))

    show_default_evidence = finding.outcome in {
        AssessmentOutcome.CONFIRMED_INSECURE,
        AssessmentOutcome.POTENTIAL_RISK,
        AssessmentOutcome.HARDENING,
        AssessmentOutcome.UNKNOWN,
        AssessmentOutcome.NOT_EVALUATED,
        AssessmentOutcome.UNSUPPORTED_SYNTAX,
    }
    evidence = (
        finding.evidence if details else finding.evidence[:2] if show_default_evidence else ()
    )
    if evidence:
        content.append(Text("Sanitized evidence", style="bold dim"))
        for item in evidence:
            location = _line_range(item.location.line_start, item.location.line_end)
            provenance = _evidence_provenance(item.target_interface, item.resolution_origin)
            content.append(
                Text(f"  - {location}{provenance}: {item.redacted_excerpt}", style="dim")
            )
        if not details and len(finding.evidence) > len(evidence):
            content.append(
                Text(
                    f"  {len(finding.evidence) - len(evidence)} more evidence item(s); "
                    "use --details.",
                    style="dim",
                )
            )

    if details and finding.technical_references:
        content.append(
            _terminal_field(
                "Technical references",
                ", ".join(finding.technical_references),
            )
        )
    if details:
        content.extend(_terminal_field("Limitation", item) for item in finding.limitations)

    title = Text()
    title.append(f"[{finding.rule_id}] ", style="bold")
    title.append(finding.title)
    console.print(
        Panel(
            Group(*content),
            title=title,
            border_style=_outcome_border_style(finding.outcome),
            box=panel_box,
        )
    )


def _render_terminal_diagnostics(
    console: Console,
    report: AssessmentReport,
    *,
    details: bool,
    panel_box: box.Box,
) -> None:
    table = Table(
        title=None,
        box=panel_box,
        expand=True,
        show_header=True,
        header_style="bold",
    )
    table.add_column("Code", overflow="fold")
    table.add_column("Context", overflow="fold")
    if details:
        table.add_column("Message", ratio=2, overflow="fold")
    for item in report.diagnostics:
        context = item.source.title()
        if item.rule_id is not None:
            context += f" | {item.rule_id}"
        if item.line_start is not None:
            context += f" | line {item.line_start}"
        row = (item.code, context, item.message) if details else (item.code, context)
        table.add_row(*row)
    console.print(Panel(table, title="Operational diagnostics", box=panel_box))


def _terminal_count_line(title: str, items: tuple[tuple[str, int], ...]) -> Text:
    line = Text()
    line.append(f"{title}: ", style="bold")
    for index, (label, count) in enumerate(items):
        if index:
            line.append(" | ", style="dim")
        line.append(f"{label} {count}")
    return line


def _outcome_count_items(report: AssessmentReport) -> tuple[tuple[str, int], ...]:
    summary = report.outcome_summary()
    return tuple((_OUTCOME_LABELS[outcome], summary[outcome.value]) for outcome in _OUTCOME_ORDER)


def _severity_count_items(report: AssessmentReport) -> tuple[tuple[str, int], ...]:
    summary = report.severity_summary()
    return tuple(
        (name.title(), summary[name]) for name in ("critical", "high", "medium", "low", "info")
    )


def _terminal_field(label: str, value: str, style: str | None = None) -> Text:
    line = Text()
    line.append(f"{label}: ", style="bold")
    line.append(value, style=style)
    return line


def _severity_style(severity: str) -> str | None:
    return {
        "critical": "bold red",
        "high": "bold red",
        "medium": "bold bright_red",
        "low": "bold yellow",
        "info": "cyan",
    }.get(severity)


def _outcome_border_style(outcome: AssessmentOutcome) -> str:
    return {
        AssessmentOutcome.SECURE: "green",
        AssessmentOutcome.CONFIRMED_INSECURE: "red",
        AssessmentOutcome.POTENTIAL_RISK: "bright_red",
        AssessmentOutcome.HARDENING: "yellow",
        AssessmentOutcome.NOT_APPLICABLE: "dim",
        AssessmentOutcome.UNKNOWN: "yellow",
        AssessmentOutcome.NOT_EVALUATED: "magenta",
        AssessmentOutcome.UNSUPPORTED_SYNTAX: "magenta",
    }[outcome]


def render_html(report: AssessmentReport) -> str:
    """Render an escaped, offline, printable report with a restrictive CSP."""

    findings = "".join(_html_finding(item) for item in report.findings)
    references = tuple(
        dict.fromkeys(
            reference for finding in report.findings for reference in finding.technical_references
        )
    )
    diagnostics = "".join(_html_diagnostic(item) for item in report.diagnostics)
    severity = report.severity_summary()
    outcome = report.outcome_summary()
    unknown_count = outcome["unknown"] + outcome["not_evaluated"] + outcome["unsupported_syntax"]
    adverse_count = outcome["confirmed_insecure"] + outcome["potential_risk"] + outcome["hardening"]
    no_confirmed = ""
    if outcome[AssessmentOutcome.CONFIRMED_INSECURE.value] == 0:
        no_confirmed = (
            '<p class="notice">No confirmed weaknesses were identified by the implemented '
            "rules. This does not establish that the device is secure.</p>"
        )
    partial_explanation = partial_status_explanation(report)
    partial_block = (
        '<aside class="partial-explanation"><h2>Why this assessment is Partial</h2>'
        f"<p>{escape(partial_explanation)}</p></aside>"
        if partial_explanation is not None
        else ""
    )
    rule_items = "".join(
        f"<li><code>{escape(rule_id)}</code></li>" for rule_id in report.evaluated_rule_ids
    )
    scope_items = "".join(
        f"<article><strong>{count}</strong><span>{escape(label)}</span></article>"
        for label, count in _scope_category_counts(report.evaluated_rule_ids)
    )
    severity_items = "".join(
        f"<div><strong>{severity[name]}</strong><span>{escape(name.title())}</span></div>"
        for name in ("critical", "high", "medium", "low", "info")
    )
    reference_items = "".join(
        f'<li><a href="{escape(item, quote=True)}">{escape(_reference_label(item))}</a></li>'
        for item in references
    )
    limitation_items = "".join(f"<li>{escape(item)}</li>" for item in report.limitations)
    impact_items = _html_field_list(report.findings, "impact")
    recommendation_items = _html_field_list(report.findings, "recommendation")
    impact_section = (
        f"<section><h2>Security Impact</h2>{impact_items}</section>" if impact_items else ""
    )
    recommendation_section = (
        f"<section><h2>Recommendations</h2>{recommendation_items}</section>"
        if recommendation_items
        else ""
    )
    reference_section = (
        f"<section><h2>Technical References</h2><ul>{reference_items}</ul></section>"
        if reference_items
        else ""
    )
    diagnostic_section = (
        f"<section><h2>Operational Diagnostics</h2>{diagnostics}</section>" if diagnostics else ""
    )
    status_class = "status-partial" if report.assessment_status is AssessmentStatus.PARTIAL else ""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; img-src data:;
               base-uri 'none'; form-action 'none'; frame-ancestors 'none'">
<title>ConfigGuard Security Assessment — {escape(report.source_basename)}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
<header class="report-header">
<div class="brand-row">
<img class="brand-logo" src="{_BRAND_LOGO_DATA_URI}" alt="Bashar Asaad logo">
<div><p class="eyebrow">Cybersecurity | Networking</p>
<p class="product-name">ConfigGuard <span>{escape(__version__)}</span></p>
<p class="publisher">by Bashar Asaad / <bdi lang="ar" dir="rtl">بشار أسعد</bdi></p></div>
</div>
<div class="report-title"><p class="report-label">Security assessment report</p>
<h1>Static Configuration Security Assessment</h1></div>
<div class="header-meta">
<div><span>Assessment status</span><strong class="status-badge {status_class}">
{escape(report.assessment_status.value.title())}</strong></div>
<div><span>Source file</span><strong>{escape(report.source_basename)}</strong></div>
</div>
</header>
<section><h2>Executive Summary</h2>
<div class="executive-grid">
<article><strong>{len(report.evaluated_rule_ids)}</strong><span>Rules evaluated</span></article>
<article><strong>{adverse_count}</strong><span>Security findings</span></article>
<article><strong>{unknown_count}</strong><span>Uncertain results</span></article>
<article><strong>{len(report.diagnostics)}</strong><span>Operational diagnostics</span></article>
</div>{no_confirmed}{partial_block}</section>
<section><h2>Assessment Scope</h2>
<p>Offline analysis of one explicitly selected Cisco IOS / IOS XE-style configuration across
the implemented security areas below.</p>
<div class="scope-grid">{scope_items}</div>
<details class="scope-details"><summary>Technical traceability —
{len(report.evaluated_rule_ids)} rule identifiers</summary><ul class="rule-id-list">
{rule_items}</ul></details></section>
<div class="section-grid">
<section><h2>Device / Platform Information</h2><dl>
<dt>Platform family</dt><dd>{escape(_display_platform(report.platform_family))}</dd>
<dt>Identification</dt><dd>Inferred from configuration syntax;
confidence {report.platform_confidence:.2f}</dd>
<dt>Support</dt><dd>{escape(report.platform_support)}</dd>
<dt>Identification detail</dt><dd>{escape(report.platform_identification)}</dd>
</dl></section>
<section><h2>Assessment Completeness</h2><dl>
<dt>Parser status</dt><dd>{escape(report.parser_status)}</dd>
<dt>Commands classified</dt><dd>{report.classified_command_count} of {report.command_count}</dd>
<dt>Unsupported commands</dt><dd>{report.unsupported_command_count}</dd>
<dt>Structured observations</dt><dd>{report.observation_count}</dd>
</dl></section></div>
<section><h2>Severity Summary</h2>
<div class="summary">{severity_items}</div>
<p class="summary-note">Severity counts apply only to adverse findings. Zero counts are not
proof of security and do not include unknown, unsupported, or unevaluated results.</p></section>
<section class="major-break"><h2>Findings and Evidence</h2>
<p class="section-intro">Cards distinguish security findings, passing observations,
uncertainty, and applicability. Unknown or unsupported results are not passes.</p>
{findings}</section>
{impact_section}
{recommendation_section}
{reference_section}
{diagnostic_section}
<section><h2>Methodology and Limitations</h2>
<p>This report was produced through bounded local ingestion, context-aware parsing,
deterministic rule evaluation, and centralized evidence sanitization.</p>
<ul>{limitation_items}</ul></section>
</main>
</body>
</html>
"""


def _scope_category_counts(rule_ids: tuple[str, ...]) -> tuple[tuple[str, int], ...]:
    return tuple(
        (label, sum(rule_id.startswith(prefix) for rule_id in rule_ids))
        for prefix, label in _SCOPE_CATEGORIES
    )


def _reference_label(reference: str) -> str:
    return _REFERENCE_LABELS.get(reference, reference)


def _html_finding(finding: Finding) -> str:
    severity = finding.severity.value if finding.severity is not None else "none"
    card_class = _finding_card_class(finding.outcome)
    evidence_items = "".join(
        '<li><span class="line">'
        + escape(_line_range(item.location.line_start, item.location.line_end))
        + escape(_evidence_provenance(item.target_interface, item.resolution_origin))
        + "</span><code>"
        + escape(item.redacted_excerpt)
        + "</code></li>"
        for item in finding.evidence
    )
    evidence_block = (
        '<div class="finding-detail"><h4>Safe technical evidence</h4>'
        f"<ul>{evidence_items}</ul></div>"
        if evidence_items
        else ""
    )
    limitations = "".join(f"<li>{escape(item)}</li>" for item in finding.limitations)
    limitation_block = (
        f'<div class="finding-detail"><h4>Finding limitations</h4><ul>{limitations}</ul></div>'
        if limitations
        else ""
    )
    guidance = additional_evidence_guidance(finding)
    guidance_block = (
        '<aside class="evidence-needed"><h4>Additional evidence needed</h4>'
        f"<p>{escape(guidance)}</p></aside>"
        if guidance is not None
        else ""
    )
    return (
        f'<article class="finding {card_class}">'
        '<div class="finding-heading"><div>'
        f"<h3>{escape(finding.rule_id)} — {escape(finding.title)}</h3>"
        f'<span class="classification">{escape(_OUTCOME_LABELS[finding.outcome])}</span>'
        '</div><span class="severity-badge">'
        f"Severity: {escape(severity)}</span></div>"
        f"<dl><dt>Outcome</dt><dd>{escape(finding.outcome.value)}</dd>"
        f"<dt>Severity</dt><dd>{escape(severity)}</dd>"
        f"<dt>Evidence confidence</dt><dd>{escape(finding.confidence.value)}</dd></dl>"
        f"<p>{escape(finding.description)}</p>{guidance_block}"
        f"{evidence_block}{limitation_block}"
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


def additional_evidence_guidance(finding: Finding) -> str | None:
    """Return safe presentation guidance for uncertain public findings."""

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
        "CG-ACL-001": (
            "Provide the complete referenced IPv4 ACL, its supported ordered entries, and "
            "the effective interface attachment and relationship context."
        ),
        "CG-ACL-002": (
            "Provide every referenced IPv4 ACL definition and supported ordered entry plus "
            "complete interface attachment, template, and Port-channel context."
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

/* Phase 8D: restrained Bashar Asaad print-report identity. */
:root { --navy: #020a23; --blue: #2f63e0; --slate: #536171; --emerald: #1fba83;
  --cyan: #22d6e7; --neutral: #e5e5e5; --ink: #13223a; --muted: #536171;
  --line: #dbe2ea; --soft: #f5f7fa; --accent: #2f63e0; --pass: #16845f;
  --warn: #9b6116; --risk: #a93f49; --failure: #67508f; }
body { background: #edf1f5; color: var(--ink); }
main { border: 0; border-radius: 18px; padding: 0 48px 48px; overflow: hidden;
  box-shadow: 0 18px 50px #020a2314; }
.report-header { margin: 0 -48px 36px; padding: 34px 48px 30px; color: #fff;
  border: 0; background: linear-gradient(128deg, var(--navy) 0%, #0c214c 76%, #153b75 100%); }
.brand-row { display: flex; align-items: center; gap: 14px; }
.brand-logo { width: 48px; height: 48px; border-radius: 12px; }
.brand-row p { margin: 0; }
.brand-row .eyebrow { color: var(--cyan); font-size: .68rem; }
.product-name { font-size: 1.15rem; font-weight: 800; }
.product-name span, .publisher { color: #b9c8dc; font-size: .78rem; font-weight: 500; }
.report-title { margin-top: 30px; }
.report-label { margin: 0; color: #9fb3cc; font-size: .72rem; font-weight: 750;
  letter-spacing: .11em; text-transform: uppercase; }
.report-title h1 { max-width: 720px; margin-top: 5px; font-size: 2.35rem; }
.header-meta { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px;
  margin-top: 24px; }
.header-meta > div { padding: 12px 14px; border: 1px solid #ffffff24; border-radius: 10px;
  background: #ffffff0d; }
.header-meta span, .header-meta strong { display: block; }
.header-meta span { color: #aebed2; font-size: .72rem; }
.header-meta strong { margin-top: 2px; overflow-wrap: anywhere; }
.status-badge { width: fit-content; padding: 3px 9px; border-radius: 999px;
  color: #c9fff0; background: #1fba8326; }
.status-badge.status-partial { color: #fff0cb; background: #f2b95026; }
h2 { color: var(--navy); border: 0; margin-bottom: 14px; padding: 0; }
h2::after { content: ""; display: block; width: 42px; height: 3px; margin-top: 8px;
  border-radius: 999px; background: linear-gradient(90deg, var(--blue), var(--cyan)); }
.executive-grid, .scope-grid { display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.executive-grid article, .scope-grid article { padding: 18px; border: 1px solid var(--line);
  border-radius: 12px; background: var(--soft); }
.executive-grid strong, .executive-grid span,
.scope-grid strong, .scope-grid span { display: block; }
.executive-grid strong { color: var(--blue); font-size: 1.7rem; }
.executive-grid span, .scope-grid span { color: var(--muted); font-size: .78rem; }
.scope-grid { grid-template-columns: repeat(5, minmax(0, 1fr)); }
.scope-grid strong { color: var(--navy); font-size: 1.35rem; }
.scope-details { margin-top: 14px; padding: 12px 15px; border: 1px solid var(--line);
  border-radius: 10px; background: #fff; }
.scope-details summary { color: var(--blue); cursor: pointer; font-weight: 700; }
.rule-id-list { columns: 3; margin-bottom: 0; }
.rule-id-list code { color: var(--slate); font-size: .8rem; }
.section-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 18px; }
.section-grid section { padding: 2px 20px 20px; border: 1px solid var(--line);
  border-radius: 12px; background: #fff; }
.notice, .partial-explanation { margin-top: 16px; padding: 14px 17px; border-radius: 10px;
  border-left: 4px solid var(--blue); background: #eef3ff; }
.partial-explanation { border-left-color: var(--warn); background: #fff8e9; }
.partial-explanation h2 { margin: 0 0 5px; font-size: 1rem; }
.partial-explanation h2::after { display: none; }
.partial-explanation p { margin: 0; }
.summary div { border: 1px solid var(--line); border-radius: 10px; background: var(--soft); }
.finding { border-radius: 12px; padding: 22px; box-shadow: 0 5px 18px #020a2308; }
.finding h3 { color: var(--navy); }
.finding-heading { display: flex; align-items: flex-start;
  justify-content: space-between; gap: 14px; }
.finding-heading h3 { margin-bottom: 7px; }
.classification { border-radius: 999px; color: var(--slate); font-size: .72rem;
  letter-spacing: .035em; text-transform: uppercase; }
.severity-badge { flex: 0 0 auto; padding: 4px 9px; border: 1px solid var(--line);
  border-radius: 999px; color: var(--slate); background: var(--soft); font-size: .72rem;
  font-weight: 700; text-transform: uppercase; }
.finding > dl { grid-template-columns: repeat(3, max-content 1fr); gap: 7px 10px;
  padding: 10px 12px; border-radius: 8px; background: var(--soft); font-size: .8rem; }
.finding > dl dd { margin-right: 10px; }
.finding-detail { margin-top: 15px; }
.finding-detail h4 { color: var(--slate); }
.finding-observation { opacity: .78; box-shadow: none; }
.evidence-needed { border-radius: 8px; }
.diagnostic { border-radius: 10px; background: var(--soft); }

@media (max-width: 800px) {
  main { padding: 0 22px 28px; }
  .report-header { margin: 0 -22px 28px; padding: 28px 22px; }
  .executive-grid, .scope-grid, .section-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .finding-heading { flex-direction: column; }
  .finding > dl { grid-template-columns: 1fr; }
  .rule-id-list { columns: 2; }
}

@media print {
  * { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
  main { border-radius: 0; padding: 0; overflow: visible; }
  .report-header { margin: 0 0 9mm; padding: 9mm 10mm; border-radius: 0; }
  .report-title { margin-top: 6mm; }
  .report-title h1 { font-size: 22pt; }
  .header-meta { margin-top: 5mm; }
  section { break-before: auto; }
  .executive-grid article, .scope-grid article, .section-grid section,
  .partial-explanation, .notice, .finding-detail, .scope-details { break-inside: avoid-page; }
  .scope-details[open] summary { margin-bottom: 4px; }
  .scope-details:not([open]) > *:not(summary) { display: block; }
  .scope-details:not([open]) summary::marker { content: ""; }
  .major-break { break-before: page; }
  a::after { content: ""; }
}
"""
