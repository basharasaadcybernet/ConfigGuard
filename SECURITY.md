# Security Policy and Design

## Scope of this document

This is the Phase 2 threat model and secure-design baseline. ConfigGuard is pre-alpha and
parses configurations but does not yet perform assessments. Do not use it as proof that a
device is secure.

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

`ConfigurationIngestor` accepts an explicitly provided local regular file, rejects UNC paths
and symbolic links, reads at most the configured limit plus one byte, defaults to 2 MiB,
accepts UTF-8 with an optional BOM, and rejects empty, invalidly encoded, NUL/control-bearing,
or oversized input. It reads in binary mode and decodes in memory without modifying or
copying the source. File names are sanitized display labels, not output paths. Public errors
contain neither absolute paths nor configuration content.

### Evidence redaction

Raw `CommandRecord.text` and parsed arguments are sensitive and excluded from object
representations. Future rules return opaque `EvidenceReference` values; only the central
sanitizer resolves them. The Phase 2 sanitizer covers supported username/password/secret,
enable, SNMP community/v3, routing authentication, AAA key, banner, crypto-block, and
URL-credential forms. It preserves context and source line while replacing secrets with
`[REDACTED]`. Unclassified commands fail closed instead of exposing their text.

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

## Known Phase 2 limitations

- No security rule, analysis engine, CLI scanner, renderer, API, or frontend exists yet.
- Raw commands remain accessible inside the in-memory parser representation by design and
  must never be logged or passed directly to a future serializer.
- Redaction recognizes the credential forms currently supported by parser version 1. Unknown
  commands are fully redacted because their sensitivity cannot be established.
- Cisco IOS and IOS XE syntax varies by platform, release, feature set, and generated output.
- Encrypted or obfuscated Cisco credential formats may still be sensitive and must be masked.
- A configuration snapshot can be stale, incomplete, or different from effective runtime
  state.

## Reporting security issues

Until a public security contact is established, report issues privately to the repository
owner. Do not attach real device configurations or credentials; provide a minimal synthetic
reproduction.
