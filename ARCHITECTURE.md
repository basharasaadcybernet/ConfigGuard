# Architecture

## Design goals

ConfigGuard is offline-first, deterministic, explainable, typed, and conservative. A
single exported configuration cannot establish reachability, topology, runtime defaults,
software patch state, or compensating controls, so uncertainty is part of the model rather
than silently treated as secure.

Phase 1 defined the boundaries and contracts. Phase 2 implemented local ingestion, Cisco
IOS-style parsing, observations, diagnostics/metrics, and redaction. Phase 3 implemented the
shared analysis engine, immutable public findings, typed registry, failure isolation, and
five approved rules. Phase 4 added an installable CLI and terminal, JSON, and HTML reporting.
Phase 5A added three management-plane rules, Phase 5B added three Layer 2 rules, Phase 5C
added one DAI integration rule, Phase 6 added interface configuration resolution, Phase 7A
added two interface IPv4 ACL rules, and Phase 7B adds three routing-authentication rules while
preserving offline, deterministic, and conservative boundaries.

## Data flow

```text
CLI / local web / future API
          |
          v
bounded local input validation (implemented)
          |
          v
syntax identification -> context-aware Cisco parser (implemented)
          |
          v
ParsedConfiguration + StructuredObservation + UnsupportedSyntax
          |
          v
typed interface resolution (direct/range facts; template/channel limitations)
          |
          v
bounded IPv4 interface ACL resolution (explicit attachments and ordered entries)
          |
          v
routing-authentication resolution (process/interface/key correlation)
          |
          v
shared analysis engine / registered SecurityRule objects (implemented: seventeen rules)
          |
          v
RuleEvaluation + EvidenceReference
          |
          v
central EvidenceSanitizer (implemented for supported Cisco syntax)
          |
          v
safe Finding / AnalysisResult model
          |
          v
sanitized AssessmentReport -> terminal / JSON / HTML renderers (implemented)
```

No interface owns analysis logic. CLI, API, and local web adapters will call the same
application service when it exists.

## Package boundaries

- `configguard.domain` defines immutable, interface-neutral values: platform identity,
  configuration context, source locations, commands, structured observations, uncertainty
  outcomes, qualitative severity/confidence, and evidence references.
- `configguard.parsing.ingestion` performs bounded, read-only UTF-8 ingestion of an explicitly
  selected local regular file. It returns only an ephemeral `ConfigurationSource`.
- `configguard.parsing.cisco` identifies and parses supported Cisco IOS-style syntax without
  file, process, device, or network access.
- `configguard.analysis.interface_resolution` applies supported direct and bounded range
  facts in source order, preserves provenance, and represents unresolved template and
  Port-channel relationships without inventing inheritance.
- `configguard.analysis.acl_resolution` resolves only supported IPv4 ACLs explicitly attached
  to interfaces, preserves entry order and deletion semantics, and returns scoped uncertainty
  for missing, empty, advanced, template-dependent, or Port-channel-dependent policies.
- `configguard.rules` defines rule metadata and deterministic evaluation contracts. Rules
  accept `ParsedConfiguration`; they do not receive a path, socket, or HTTP client.
- `configguard.rules.initial` contains the five Phase 3 and three Phase 5A rules, and composes
  four Layer 2 rules plus the two Phase 7A rules. Helpers read only structured observations
  and produce opaque evidence references.
- `configguard.analysis` owns the immutable registry, ordered execution, failure isolation,
  evidence sanitization, public findings, operational diagnostics, and safe public mapping.
- `configguard.sanitization` is the sole boundary that resolves evidence references into
  displayable excerpts. Its Cisco implementation masks supported credential forms and emits
  only `[REDACTED]` for unclassified or sensitive block content.
- `configguard.reporting` builds a sanitized, versioned assessment model from parser and
  engine results. Its renderers accept only that public model; they never receive raw source
  text or `CommandRecord` objects.
- `configguard.cli` composes ingestion, parsing, the shared engine, report construction,
  rendering, safe output, and stable exit codes without duplicating analysis logic.
- Future API and frontend packages must depend inward on these contracts rather than duplicate
  parsing or security decisions.

## Parser architecture

The parser operates on validated text already in memory. It identifies Cisco IOS versus IOS
XE conservatively and can accept an unknown-but-compatible IOS-style candidate without
claiming an exact family. Clearly recognized ASA, NX-OS, IOS XR, Junos, FortiOS, and RouterOS
styles are rejected. Identification does not claim a device model or authoritative software
version.

Parser version 1 builds command records with one-based locations, command names/arguments,
parent context, and explicit global, interface, line, AAA, ACL, router, VLAN, and sensitive
crypto contexts. `!` comments and export preambles are not commands. Indentation, section
openers, `exit`, `end`, and sensitive block terminators control context.

Parsing must be stateful enough to understand section boundaries, indentation, repeated
sections, negated commands, and context-specific meanings. A token seen in an unrelated
section is not evidence for a rule. Unsupported commands are recorded in
`UnsupportedSyntax`; they are never assumed to represent a secure state.

The parser produces two layers:

1. `CommandRecord` preserves in-memory source structure and location. Its text is sensitive.
2. `StructuredObservation` exposes typed scalar facts and references the command IDs that
   support them. Rules consume these observations rather than searching raw text.

Observation IDs and command IDs are deterministic, document-local identifiers. The parser
emits observations for VTY/console transport/authentication/access restrictions, SSH/HTTP,
local/AAA authentication, SNMP communities/groups/users, interface state and ACL references,
named/numbered ACL entries, routing authentication declarations, VLANs, and selected Layer 2
settings. Credential values and ACL remarks are never placed in observation attributes.

Unclassified commands carry only a redacted structural context and a narrow rule scope when
their recognized command family can affect an implemented rule. This prevents unrelated
syntax from invalidating explicit conclusions while ensuring malformed VTY transport or SNMP
community syntax cannot produce a false secure or not-applicable result. Layer 2 analysis
applies the same principle to interface-role, Port Security, DHCP Snooping, DAI, PortFast,
and BPDU Guard families.

`ParseStatus` distinguishes parsed, partial, and incomplete documents. Secret-free
diagnostics identify unknown platform family, unsupported commands, malformed structures,
and unterminated sensitive blocks. `ParseMetrics` records total/classified/unsupported
commands and observation counts for future coverage calculations. These are parser facts,
not security findings.

## Rule execution and classification

Each future rule has stable metadata and evaluates a `ParsedConfiguration` without doing
file or network I/O. It returns one `RuleEvaluation` with:

- an explicit outcome (`secure`, `confirmed_insecure`, `potential_risk`, `hardening`,
  `not_applicable`, `unknown`, `not_evaluated`, or `unsupported_syntax`);
- qualitative severity only for adverse outcomes;
- independent evidence confidence;
- evidence references, limitations, impact, and remediation text.

`UNKNOWN` means relevant evidence is insufficient. `NOT_EVALUATED` means the rule could not
run or its required parser capability is absent. `UNSUPPORTED_SYNTAX` means relevant syntax
was encountered but cannot be interpreted safely. These states must remain distinct from a
secure result and from `NOT_APPLICABLE`.

The engine executes immutable registry order, validates matching rule IDs, isolates each rule,
and sends every evidence reference through the configured sanitizer. A failed rule or failed
evidence resolution becomes `NOT_EVALUATED` plus a separate sanitized
`AnalysisDiagnostic`; it is never converted into a security weakness. Identical parsed input
and registry order produce identical results.

The Phase 3 rules are VTY Telnet (`CG-MGMT-001`), plaintext HTTP management
(`CG-MGMT-006`), SSH version 1 (`CG-MGMT-002`), SNMP community configuration
(`CG-SNMP-001`), and SNMP community ACL references (`CG-SNMP-002`). Command order is used
for supported effective-state semantics. Missing/default-dependent and incomplete states
remain unknown or unsupported rather than passing.

Phase 5A adds inbound VTY source restriction (`CG-MGMT-003`), explicit type 0 credential
storage (`CG-MGMT-005`), and management-line login authentication (`CG-MGMT-004`). These
rules resolve overlapping line ranges and cross-reference ACL, local-user, or AAA state.
They do not infer platform defaults, live reachability, AAA server availability, password
strength, or Layer 2 security conclusions.

Phase 5B adds access-port Port Security posture (`CG-L2-001`), DHCP Snooping coverage and
access trust (`CG-L2-002`), and BPDU Guard on explicit PortFast/edge ports (`CG-L2-004`).
Supported repeated and negated commands are resolved in source order. The rules require
explicit interface roles and relevant global/VLAN state; they do not infer physical topology
or runtime state.

Phase 5C adds Dynamic ARP Inspection coverage (`CG-L2-003`). It correlates explicit DAI VLAN
selection, interface trust, access VLANs, and the existing DHCP Snooping declarations. A
configuration-visible pass does not assert that a live binding database exists. Unsupported
static validation sources and unresolved inheritance remain uncertain rather than being
treated as effective protection.

Phase 6 places one typed resolver between parsed observations and all four Layer 2 rules.
Supported physical-interface ranges are expanded to canonical targets with a maximum of 128;
direct and range facts then resolve by source order, including negation and overlap. Each fact
retains the original observation, context, target, order, origin, and confidence. Applied
interface templates are detected but conservatively unresolved because precedence varies;
unused templates contribute no facts. Effective `channel-group N mode` declarations/removals
form explicit member/logical relationships, but logical and physical settings are never
copied. Missing logical definitions, template inheritance, and operational EtherChannel state
produce rule-scoped uncertainty. Confirmed independent adverse observations retain priority.

Phase 7A reuses that resolver for exact `ip access-group` attachments, including supported
range targets and source ordering. A separate bounded ACL resolver handles named/numbered
standard and extended IPv4 entries, supported sequence order, whole-policy and ACE removal,
address/wildcard expressions, selected protocols, and basic port qualifiers. It never treats
an ACL as applied merely because it is defined or referenced by VTY/SNMP. Unsupported
advanced constructs remain scoped uncertainty. `CG-ACL-001` reports only reachable broad
remaining permits as potential risk or hardening; `CG-ACL-002` reports whether every active
reference is present and fully evaluable. Neither rule asserts interface activity, Internet
exposure, business intent, routing, NAT, or end-to-end packet flow.

## Evidence and reporting boundary

Rules cite observation and command IDs; they do not copy raw command text into findings.
Only the centralized sanitizer may resolve those IDs and produce `SanitizedEvidence`.
The Cisco sanitizer masks usernames/credential values, enable credentials, SNMP communities
and v3 keys, routing/AAA keys, URL credentials, banners, crypto block content, ACL identifiers,
and literal ACL addresses while preserving useful command structure and line context.
Range-derived evidence additionally carries the resolved target
and `range` origin while retaining the range header and applied command line. Unknown commands
fail closed as `[REDACTED]`.

`Finding` contains sanitized evidence, line references, outcome, qualitative severity,
confidence, impact, remediation, verified static references, and limitations.
`AnalysisResult.to_public_dict()` exposes only that public model and sanitized operational
diagnostics. `AssessmentReport` adds platform inference, parser completeness, summaries, and
assessment-wide limitations without retaining a source path or raw configuration. JSON and
HTML renderers do not accept `CommandRecord` or `ParsedConfiguration`. Reports require an
explicit destination, use atomic no-overwrite output, and contain no numerical score.
HTML presentation separates adverse, passing, uncertain, failed, and not-applicable results;
optional impact/remediation/reference sections are omitted when empty.

## Interface integration

- **CLI:** the implemented adapter validates one selected file, invokes the shared engine,
  prints sanitized terminal or JSON output, and optionally exports JSON/HTML reports.
- **Local API/web:** a loopback-only adapter may accept an explicitly selected upload in
  memory and call the same service. It must not introduce cloud or device access.
- **Frontend:** presentation only; no independent parser or security logic.

The API, local web, and frontend adapters remain future work.

## Phase 7B routing-authentication resolution

`routing_resolution.py` reuses the Phase 6 interface resolver for direct/range facts and adds
protocol-specific correlation without reading raw command text. Active process generations,
supported network statements, effective IPv4 interface addresses, explicit OSPF process/area
bindings, passive-interface state, authentication modes, and key-chain completeness resolve
in source order. Process deletion prevents settings from an older generation being reused.

The resolver deliberately does not expand interface templates or copy configuration between
Port-channel members and logical interfaces. Relevant unresolved relationships and scoped
unknown syntax block a pass; unrelated unknown syntax does not. The three rules consume the
same typed resolution and preserve range target/origin evidence. Their Secure state means only
that every supported non-passive target has a complete supported static configuration—not
that peers agree, an adjacency exists, routing traffic flows, or a secret is strong.
