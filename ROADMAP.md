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

- Phase 5A adds exactly three management-plane rules: inbound VTY source restriction,
  explicit type 0 credential storage, and explicit VTY/console login authentication.
- Phase 5A also validates a synthetic IOS XE switch containing VLAN/switchport syntax without
  interpreting unrelated Layer 2 commands as management findings.
- Phase 5B adds exactly three conservative Layer 2 checks: access-port Port Security posture,
  DHCP Snooping coverage/trust, and BPDU Guard on explicit PortFast/edge ports.
- Phase 5C adds exactly one Dynamic ARP Inspection rule with explicit VLAN/interface trust
  evaluation and conservative integration with supported DHCP Snooping evidence.
- Add further ACL, Layer 2, routing-protocol, and hardening rules only as parser evidence
  becomes reliable in later, separately approved phases.
- Validate cross-platform packaging and publish an explicit Cisco syntax compatibility matrix.

## Phase 6 — interface configuration resolution (complete)

- Add bounded, deterministic physical-interface range expansion with source-order and
  negation semantics.
- Detect interface-template definitions/applications; leave unsafe precedence, nesting, and
  cycles unresolved rather than fabricating inherited state.
- Represent physical member-to-Port-channel declarations and removals without simulating
  EtherChannel formation or copying logical/physical configuration.
- Integrate resolved facts and provenance into the existing four Layer 2 rules. Keep exactly
  twelve rules and preserve management/SNMP behavior.

## Phase 7A — interface ACL security assessment (complete)

- Add exactly two rules for broad permissions in supported interface IPv4 ACLs and for
  interface ACL reference/evaluation integrity.
- Evaluate only ACLs explicitly attached through supported `ip access-group` commands;
  defined, VTY-only, SNMP-only, and IPv6 ACLs do not become interface filters.
- Preserve ACL order, supported sequence and negation semantics, interface-range provenance,
  and scoped template/Port-channel uncertainty without simulating reachability.
- Keep unsupported advanced ACL constructs uncertain and redact ACL identifiers and literal
  addresses in public evidence. The registry ends at exactly fourteen rules.

## Phase 7B — routing protocol authentication security (complete)

- Add exactly three checks using the existing `CG-ROUTE-001`, `CG-ROUTE-002`, and
  `CG-ROUTE-003` catalog meanings: OSPFv2, classic IPv4 EIGRP, and RIPv2 authentication.
- Correlate supported process/network statements with effective interface IPv4 addresses,
  explicit OSPF bindings, passive-interface state, source order, negation, and key chains.
- Reuse range provenance and keep applied templates, Port-channel inheritance, named EIGRP,
  OSPFv3, incomplete input, and relevant unsupported syntax explicitly uncertain.
- Keep the assessment offline and static: no adjacency, peer-key, topology, reachability,
  secret-strength, or runtime-success claim. The registry ends at exactly seventeen rules.

## Phase 8 — acceptance and user experience (complete)

- Validate acceptance boundaries without changing the frozen seventeen-rule engine.
- Add the Rich CLI presentation and the bundled loopback-only local Web UI.
- Apply the ConfigGuard / Bashar Asaad visual identity and finalize JSON/HTML report usability.

## Phase 9 — release hardening (current)

- Freeze product behavior for v0.1.0 and prepare public documentation, licensing, CI, and
  release verification.
- Do not publish, push, tag, or add product capabilities during local preparation.

## Deferred decisions

Remote APIs, hosted services, PDF, additional vendors, persistence, and numerical scoring are
not scheduled. Scoring may be
considered only after rule semantics, applicability, evidence confidence, and assessment
completeness have a transparent policy backed by tests.
