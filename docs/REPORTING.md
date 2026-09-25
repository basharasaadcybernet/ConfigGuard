# Security Assessment Reporting

Phase 4 exposes one sanitized assessment model through terminal, JSON, and HTML renderers.
All formats use the same parser and deterministic analysis result; reporting does not contain
independent security decisions.

## Report contents

Reports include ConfigGuard and schema versions, assessment status, inferred platform and
confidence, parser completeness, the seventeen evaluated rule IDs, qualitative severity and
outcome summaries, findings, evidence confidence, sanitized excerpts, source line numbers,
impact, recommendations, static technical references, limitations, and safe operational
diagnostics. Phase 6 range-derived evidence also includes additive `target_interface` and
`resolution_origin` fields and retains the original range context; non-resolved evidence uses
`null` for those fields.

`unknown`, `not_evaluated`, and `unsupported_syntax` are uncertainty states. They are never
reported as secure. Parser partial/incomplete status or any of those outcomes makes the
overall assessment partial. Operational failures remain separate from security findings.

## Terminal contract

The Rich-powered human report is presentation-only and consumes the same sanitized assessment
model as JSON and HTML. Its compact overview includes assessment/platform/parser state, rule
and diagnostic counts, and outcome/severity counts without listing every rule identifier at
the top. The default view displays all security-relevant and passing results while summarizing
`NOT_APPLICABLE` results; `--details` displays all seventeen rules, complete sanitized evidence,
technical references, full diagnostic messages, rule identifiers, and assessment limitations.

Interactive terminals may receive color and Unicode borders. Redirected output and
`--no-color` use an ANSI-free ASCII fallback. Text labels always communicate classification,
outcome, severity, and confidence, so color is never required. Output width is bounded and
long summaries, impacts, recommendations, evidence, and limitations wrap without silent
truncation.

## JSON contract

The current `report_schema_version` is `1.0.0`. JSON is UTF-8, deterministic for identical
input and software versions, and contains no timestamp or machine-specific source path.
Consumers should tolerate additive fields within the same major schema version and should
reject an unsupported major version.

`configguard scan FILE --format json` writes valid JSON only to standard output. With
`--output`, the same document is also written to the explicitly selected new file. Errors
are sent to standard error and produce no partial JSON on standard output. Terminal-only
`--details` and `--no-color` options do not add markup, ANSI sequences, banners, or decoration
to JSON.

## HTML contract

The HTML report is English-first, responsive, printable, self-contained, and usable offline.
It has inline CSS, no JavaScript, no external resources, escaped dynamic content, and a
restrictive Content Security Policy. It is written only when `--report PATH` is supplied.
Print rules provide predictable margins, keep headings with their content, and avoid splitting
finding and diagnostic cards where practical.

Finding cards visually distinguish adverse findings, passing observations, uncertainty,
evaluation failures, and not-applicable observations. Unknown/unsupported cards include
concise guidance about additional evidence when the rule can identify it. A zero-severity
summary explicitly is not a security pass.

The core sections are Executive Summary, Assessment Scope, Device / Platform Information,
Assessment Completeness, Severity Summary, Findings and Evidence, Operational Diagnostics,
and Methodology and Limitations. Security Impact, Recommendations, and Technical References
appear only when at least one result contains meaningful content for that section.

## Output safety and privacy

Renderers accept the sanitized `AssessmentReport`, never raw configuration commands or source
text. Evidence first crosses the existing central Cisco sanitizer. Unclassified evidence is
fully redacted, known credential forms are replaced with `[REDACTED]`, and supported ACL
evidence masks ACL identifiers and literal addresses while retaining only useful structure.
Exceptions are
mapped to fixed public messages without raw operating-system details.

File output uses a temporary file in the selected destination directory and publishes it only
after a complete UTF-8 write. Existing targets, symbolic-link targets, missing directories,
and unsafe write failures are rejected. Temporary content is removed after failure.

Reports can still contain sensitive operational metadata needed to explain a finding,
including line numbers, command structure, interface context, and technical topology hints.
Store and share reports according to the same policy used for
network-security assessment artifacts.

## Limitations

Reports cover exactly seventeen management-plane, SNMP, narrowly scoped Layer 2, interface
IPv4 ACL, and routing-protocol authentication checks.
The Layer 2 results do not establish physical port role, template/Port-channel inheritance,
live VLAN forwarding, DHCP bindings, STP runtime state, or operational enforcement. There is
no numerical score, PDF, API,
frontend, device connection, or automatic remediation. A static configuration snapshot can
be stale or incomplete, and absence of a finding is not proof of security.

Routing results additionally cannot prove peer key agreement, live adjacency, route exchange,
or secret strength. Named EIGRP, OSPFv3, and unresolved interface inheritance remain outside
the narrow Phase 7B pass criteria.
