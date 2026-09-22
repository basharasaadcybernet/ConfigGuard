# Architecture

## Design goals

ConfigGuard is offline-first, deterministic, explainable, typed, and conservative. A
single exported configuration cannot establish reachability, topology, runtime defaults,
software patch state, or compensating controls, so uncertainty is part of the model rather
than silently treated as secure.

Phase 1 defines boundaries and contracts only. Components marked *future* are not
implemented.

## Data flow

```text
CLI / local web / future API
          |
          v
input validation (future: size, encoding, text, explicit user action)
          |
          v
syntax identification -> context-aware parser (future implementation)
          |
          v
ParsedConfiguration + StructuredObservation + UnsupportedSyntax
          |
          v
shared analysis engine / registered SecurityRule objects (future)
          |
          v
RuleEvaluation + EvidenceReference
          |
          v
central EvidenceSanitizer (future implementation)
          |
          v
safe finding model -> CLI / JSON / HTML renderers (future)
```

No interface owns analysis logic. CLI, API, and local web adapters will call the same
application service when it exists.

## Package boundaries

- `configguard.domain` defines immutable, interface-neutral values: platform identity,
  configuration context, source locations, commands, structured observations, uncertainty
  outcomes, qualitative severity/confidence, and evidence references.
- `configguard.parsing` defines the no-I/O parser protocol and its ephemeral input contract.
- `configguard.rules` defines rule metadata and deterministic evaluation contracts. Rules
  accept `ParsedConfiguration`; they do not receive a path, socket, or HTTP client.
- `configguard.sanitization` defines the sole boundary that may resolve evidence references
  into displayable, redacted excerpts.
- Future application, reporting, CLI, API, and frontend packages must depend inward on these
  contracts rather than duplicate parsing or security decisions.

## Parser architecture

The future parser will operate on validated text already in memory. It will first identify
Cisco IOS versus IOS XE conservatively, then build command records with one-based source
locations and explicit contexts such as global, interface, line, AAA, ACL, router, and VLAN.

Parsing must be stateful enough to understand section boundaries, indentation, repeated
sections, negated commands, and context-specific meanings. A token seen in an unrelated
section is not evidence for a rule. Unsupported commands are recorded in
`UnsupportedSyntax`; they are never assumed to represent a secure state.

The parser produces two layers:

1. `CommandRecord` preserves in-memory source structure and location. Its text is sensitive.
2. `StructuredObservation` exposes typed scalar facts and references the command IDs that
   support them. Rules consume these observations rather than searching raw text.

Observation IDs and command IDs are document-local opaque identifiers. Observation kinds
will be versioned as the parser is implemented. The generic attribute map is intentionally
small in Phase 1; stable domain-specific observation types should be introduced only when
real parser requirements prove them useful.

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

The future engine will own registry order, prerequisite checks, exception isolation, and
assessment-completeness reporting. Phase 1 contains no engine or rules.

## Evidence and reporting boundary

Rules cite observation and command IDs; they do not copy raw command text into findings.
Only the centralized sanitizer may resolve those IDs and produce `SanitizedEvidence`.
Sanitization must mask passwords, hashes, SNMP communities, authentication keys, private
keys, and similar secrets while preserving useful command shape and line context.

Future report models will consume sanitized evidence only. JSON and HTML renderers must not
accept `CommandRecord` or `ParsedConfiguration`. Reports require an explicit user action to
write and must describe scope and limitations. Numerical scoring is outside Phase 1.

## Interface integration

- **CLI:** a thin adapter will validate a selected file, call the shared application service,
  print sanitized output, and optionally export a report.
- **Local API/web:** a loopback-only adapter may accept an explicitly selected upload in
  memory and call the same service. It must not introduce cloud or device access.
- **Frontend:** presentation only; no independent parser or security logic.

These adapters are future work and are not package entry points in Phase 1.
