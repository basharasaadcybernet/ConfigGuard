# Security Policy and Design

## Scope of this document

This is the Phase 5C threat model and secure-design baseline. ConfigGuard is pre-alpha and
performs twelve limited configuration checks through a local CLI and sanitized reports. It is
not a complete audit and must not be used as proof that a device is secure or exploitable.

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
Security rules receive structured in-memory observations only. Static regression tests reject
file/process/network-client imports in rule and engine modules. Network clients are not part
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

### Findings and failure isolation

The engine converts a rule's opaque evidence references through `EvidenceSanitizer` before
constructing a public `Finding`. Public representations contain only sanitized excerpts and
line/context metadata. Synthetic markers verify that SNMP communities and exception details
do not enter finding reprs or `to_public_dict()` output.

Rule and evidence-sanitization exceptions are caught per rule. Public diagnostics use static
messages and never include exception text. The corresponding result is `NOT_EVALUATED`, not
a security finding. Registry construction rejects duplicate rule IDs.

### Persistence and reports

Inputs remain in memory. ConfigGuard does not create copies, autosaves, recent-file indexes,
or reports without an explicit user action. JSON/HTML renderers accept only the sanitized
report model. HTML escapes dynamic content and uses a restrictive Content Security Policy,
inline CSS, no JavaScript, and no external resources.

Report output uses a temporary file in the explicitly selected existing directory, completes
and flushes the UTF-8 write, then creates the requested destination without overwriting. A
failed write removes temporary content. Public errors omit source/output paths, configuration
content, raw exceptions, and operating-system details. Reports still warn that minimized
evidence can contain sensitive infrastructure metadata.

The repository ignores common raw-configuration, credential, report, environment, and key
artifacts. This is defense in depth, not permission to store sensitive data in the project.

### Conservative conclusions

Missing commands are not automatically vulnerabilities. Rules must distinguish secure,
confirmed insecure, potential risk, hardening advice, not applicable, unknown, not evaluated,
and unsupported syntax. Reports must state that configuration-only review cannot prove live
reachability, effective defaults, software patch state, topology, or compensating controls.
Unsupported syntax is scoped to the implemented rule family it can affect. An unrelated
unknown command must not erase an otherwise explicit conclusion, while malformed VTY
transport or SNMP community syntax must never create a false secure or not-applicable result.

## Known Phase 5C limitations

- Only twelve documented rules exist. There is no API, frontend, PDF, numerical score, grade,
  device connectivity, or automatic remediation.
- Raw commands remain accessible inside the in-memory parser representation by design and
  must never be logged or passed directly to a future serializer.
- Redaction recognizes the credential forms currently supported by parser version 1. Unknown
  commands are fully redacted because their sensitivity cannot be established.
- Cisco IOS and IOS XE syntax varies by platform, release, feature set, and generated output.
- Encrypted or obfuscated Cisco credential formats may still be sensitive and must be masked.
- A configuration snapshot can be stale, incomplete, or different from effective runtime
  state.
- VTY, HTTP, and SSH rules evaluate supported explicit configuration, not device
  reachability. SNMP ACL checks confirm only a recognizable reference and parsed definition;
  they do not evaluate ACL reachability, topology, upstream controls, or runtime exposure.
- Type 0 detection identifies explicit plaintext storage only. Encoded or secret forms are
  still redacted and are not certified as strong. AAA checks do not simulate server health,
  authentication exchanges, or platform defaults.
- Layer 2 checks require explicit supported access/trunk, VLAN, trust, Port Security, and
  PortFast/BPDU Guard evidence. They do not infer endpoint role, expand interface ranges or
  templates, resolve port-channel inheritance, inspect DHCP bindings, or verify live STP/DAI
  enforcement. DAI declarations do not prove a valid binding database; unsupported static
  validation arrangements remain uncertain.

## Reporting security issues

Until a public security contact is established, report issues privately to the repository
owner. Do not attach real device configurations or credentials; provide a minimal synthetic
reproduction.
