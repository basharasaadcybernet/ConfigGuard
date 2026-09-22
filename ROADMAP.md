# Roadmap

Each phase is intentionally small and requires its own review before the next begins.

## Phase 1 — foundation and analysis design (complete in this repository milestone)

- Python 3.12 package, typed contracts, and minimal tooling.
- Parser/rule/sanitizer boundaries and explicit assessment outcomes.
- Candidate Cisco IOS/IOS XE check catalog, security design, and synthetic contract tests.
- No working scanner or security-rule implementation.

## Phase 2 — safe ingestion and parser minimum viable product (complete)

- Implement bounded, read-only plain-text input validation with explicit encoding behavior.
- Implement conservative Cisco IOS/IOS XE identification.
- Parse global, interface, `line`, AAA, named/numbered ACL, `router`, and VLAN/switchport
  contexts with exact line ranges and negation awareness.
- Produce versioned structured observations needed by the management-plane and SNMP
  candidates only; preserve unknown/unsupported syntax and parser diagnostics.
- Implement centralized evidence redaction for the secret forms listed in `SECURITY.md`.
- Add only synthetic parser/redaction fixtures and tests, including malformed/ambiguous
  cases. Do not add security rules, a scan CLI, reports, API, frontend, or scoring.

## Phase 3 — first deterministic rules and analysis engine (complete)

- Frozen and implemented five management-plane/SNMP rules from `docs/CHECKS.md`.
- Added deterministic registry execution, isolated failures, applicability/uncertainty, safe
  public findings, and centralized evidence resolution.
- Covered effective command order, negative cases, redaction, and false-positive boundaries
  with synthetic tests.

## Phase 4 — CLI and security reports (complete)

- Added `configguard scan <file>` as a thin adapter over the shared engine.
- Added safe terminal output and an explicitly requested, versioned JSON report.
- Include scope, device information, findings, evidence, impact, remediation, references,
  and limitations while keeping raw configuration out of report models.
- Added escaped, self-contained, offline HTML reporting with atomic no-overwrite output.
- Documented stable exit codes that separate findings, partial assessment, unsupported input,
  internal failure, and output failure.
- Phase 4.1 validated a user-supplied configuration locally, added justified recognition for
  Multilink PPP and serial restart-delay syntax, scoped unsupported syntax to affected rules,
  aligned dependent SNMP applicability, and refined offline/print report usability.

## Phase 5 — broader validated coverage

- Add approved ACL, Layer 2, routing-protocol, and hardening rules only as parser evidence
  becomes reliable.
- Validate cross-platform packaging and publish an explicit Cisco syntax compatibility matrix.

## Phase 6 — optional local web interface

- Add a local-only interface that keeps analysis in the shared engine.
- Require explicit file selection and explicit report saving; add no cloud service, telemetry,
  device connection, or separate security logic.

## Deferred decisions

PDF, additional vendors, persistence, and numerical scoring are not scheduled. Scoring may be
considered only after rule semantics, applicability, evidence confidence, and assessment
completeness have a transparent policy backed by tests.
