# Security Assessment Reporting

Phase 4 exposes one sanitized assessment model through terminal, JSON, and HTML renderers.
All formats use the same parser and deterministic analysis result; reporting does not contain
independent security decisions.

## Report contents

Reports include ConfigGuard and schema versions, assessment status, inferred platform and
confidence, parser completeness, the five evaluated rule IDs, qualitative severity and
outcome summaries, findings, evidence confidence, sanitized excerpts, source line numbers,
impact, recommendations, static technical references, limitations, and safe operational
diagnostics.

`unknown`, `not_evaluated`, and `unsupported_syntax` are uncertainty states. They are never
reported as secure. Parser partial/incomplete status or any of those outcomes makes the
overall assessment partial. Operational failures remain separate from security findings.

## JSON contract

The current `report_schema_version` is `1.0.0`. JSON is UTF-8, deterministic for identical
input and software versions, and contains no timestamp or machine-specific source path.
Consumers should tolerate additive fields within the same major schema version and should
reject an unsupported major version.

`configguard scan FILE --format json` writes valid JSON only to standard output. With
`--output`, the same document is also written to the explicitly selected new file. Errors
are sent to standard error and produce no partial JSON on standard output.

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
fully redacted, and known credential forms are replaced with `[REDACTED]`. Exceptions are
mapped to fixed public messages without raw operating-system details.

File output uses a temporary file in the selected destination directory and publishes it only
after a complete UTF-8 write. Existing targets, symbolic-link targets, missing directories,
and unsafe write failures are rejected. Temporary content is removed after failure.

Reports can still contain sensitive operational metadata needed to explain a finding,
including line numbers, command structure, interface context, ACL names/addresses, and
technical topology hints. Store and share reports according to the same policy used for
network-security assessment artifacts.

## Limitations

Reports cover exactly five management-plane/SNMP checks. There is no numerical score, PDF,
API, frontend, device connection, automatic remediation, or runtime verification. A static
configuration snapshot can be stale or incomplete, and absence of a finding is not proof of
security.
