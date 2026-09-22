# Security Policy and Design

## Scope of this document

This is the Phase 1 threat model and secure-design baseline. ConfigGuard is pre-alpha and
does not yet perform assessments. Do not use it as proof that a device is secure.

## Assets and trust boundaries

An exported configuration can disclose credentials, hashes, keys, internal addresses,
hostnames, topology, access-control policy, and business-sensitive metadata. Treat the
entire input and unsanitized intermediate representation as confidential.

The main trust boundaries are untrusted input entering validation, raw text entering the
parser, parser facts entering deterministic rules, internal evidence crossing the sanitizer,
and sanitized findings entering an explicitly requested report.

## Threats considered

- accidental disclosure through logs, tracebacks, reports, caches, or source control;
- maliciously large, binary, malformed, or ambiguously encoded input causing resource
  exhaustion or incorrect parsing;
- configuration lines being interpreted or executed as commands, paths, templates, or code;
- path traversal or unsafe output-file replacement in future interfaces;
- secret-bearing evidence escaping without redaction;
- unsupported syntax or missing context being reported as secure;
- misleading claims caused by defaults, topology, reachability, or compensating controls
  that are not visible in one file;
- dependency or rendering vulnerabilities in future report and web components.

## Required controls

### Offline and passive operation

ConfigGuard must not contact devices, resolve device addresses, call cloud services, upload
content, use AI/LLM services, emit telemetry, or execute commands found in configurations.
Security rules receive structured in-memory observations only. Network clients are not part
of the core architecture.

### Input validation

The future input boundary must require an explicit user-selected file; enforce a documented
size limit; reject binary/NUL-containing content; use a conservative encoding policy; avoid
archive expansion; read without modifying the source; and pass text in memory. File names
are untrusted display labels, not output paths. Phase 1 defines the handoff contract but does
not yet implement these controls.

### Evidence redaction

Raw `CommandRecord.text` is sensitive. Rules return opaque `EvidenceReference` values, and
only the central sanitizer may resolve them. The sanitizer must fail closed for unknown
secret-bearing syntax and cover at least password/secret commands, SNMP communities,
routing authentication keys, key chains, RADIUS/TACACS shared secrets, private-key blocks,
and URL-style credentials. Redaction must preserve command shape and source line while
replacing the secret value. Tests must use synthetic secrets only.

Raw configuration text and secret values must never appear in normal logs. Exception
messages must be designed or filtered so they cannot echo input. Debug behavior must not
weaken this rule.

### Persistence and reports

Inputs remain in memory by default. ConfigGuard must not create copies, autosaves, recent-file
indexes, or reports without an explicit user action. Future JSON/HTML renderers accept only
sanitized report models, apply safe output permissions where supported, escape untrusted
text, and clearly warn that reports may still contain sensitive infrastructure metadata.

The repository ignores common raw-configuration, credential, report, environment, and key
artifacts. This is defense in depth, not permission to store sensitive data in the project.

### Conservative conclusions

Missing commands are not automatically vulnerabilities. Rules must distinguish secure,
confirmed insecure, potential risk, hardening advice, not applicable, unknown, not evaluated,
and unsupported syntax. Reports must state that configuration-only review cannot prove live
reachability, effective defaults, software patch state, topology, or compensating controls.

## Known Phase 1 limitations

- No input validator, Cisco parser, sanitizer implementation, rule, engine, CLI, or renderer
  exists yet.
- The contracts alone do not prevent a future implementation from logging raw text; code
  review and regression tests remain required.
- Cisco IOS and IOS XE syntax varies by platform, release, feature set, and generated output.
- Encrypted or obfuscated Cisco credential formats may still be sensitive and must be masked.
- A configuration snapshot can be stale, incomplete, or different from effective runtime
  state.

## Reporting security issues

Until a public security contact is established, report issues privately to the repository
owner. Do not attach real device configurations or credentials; provide a minimal synthetic
reproduction.
