# Security Policy

## Security model

ConfigGuard 0.1.0 is an offline, static analyzer for a documented subset of Cisco IOS and
IOS XE-style configuration syntax. It does not connect to devices, execute configuration
commands, test exploitation, verify runtime state, upload content, use cloud/AI services, or
perform automatic remediation.

The CLI reads one explicitly selected local file. The local Web UI binds only to
`127.0.0.1`, accepts bounded in-memory uploads from its same-origin frontend, and does not
provide a public host option. ConfigGuard has no telemetry, analytics, user accounts, scan
history, database, or intentional configuration persistence.

## Treat configurations as sensitive

Device configurations can disclose credentials, hashes, key material, addresses, hostnames,
topology, access-control policy, and business-sensitive metadata. Only assess files you are
authorized to handle. Do not commit real customer or production configurations to this
repository, including in issues, pull requests, tests, screenshots, or release assets.

Generated JSON and HTML reports contain minimized, sanitized evidence, but can still disclose
line numbers, interface relationships, command structure, and other operational context.
Protect reports according to the same policy used for network-security assessment artifacts.

## Input and processing controls

ConfigGuard applies these boundaries:

- local regular-file ingestion for the CLI; UNC paths and symbolic links are rejected;
- UTF-8 text with an optional BOM, a default 2 MiB limit, and rejection of empty, binary,
  control-bearing, invalidly encoded, or oversized input;
- in-memory parsing with raw command text excluded from public object representations;
- no execution of configuration content and no device/network client in the analysis engine;
- fixed public error messages that omit raw input, private paths, and exception details;
- explicitly requested report writes only, using new destinations without overwriting.

## Evidence redaction

Rules consume structured observations and return opaque evidence references. A centralized
sanitizer is the only boundary that resolves those references for terminal, JSON, HTML, or
Web UI presentation.

Supported credential, enable secret, SNMP, AAA, routing key, banner, crypto-block, and
URL-credential forms are masked. Supported ACL evidence minimizes policy identifiers and
literal addresses. Unknown commands fail closed rather than exposing their raw text. Key-chain
names and routing authentication material are treated as sensitive operational metadata.

Redaction reduces accidental disclosure; it is not a promise that reports are anonymous or
safe to publish without review.

## Conservative assessment behavior

Missing configuration is not automatically a vulnerability or a pass. Results distinguish
secure observations, confirmed weaknesses, potential risks, hardening advice, not applicable,
unknown, unsupported syntax, and evaluation failures. Unsupported or incomplete evidence is
not silently interpreted as secure.

A static snapshot cannot prove live reachability, topology, effective runtime defaults,
software patch state, adjacency/session behavior, peer-key agreement, enforcement, or
compensating controls. See [docs/CHECKS.md](docs/CHECKS.md) for rule-specific limitations.

## Local Web UI threat model

The bundled web server is intended for one local user on loopback. Release security controls
include:

- IPv4 loopback-only binding and no configurable host mode;
- Host-header validation for `127.0.0.1` and `localhost` on the active port;
- a per-process request token required by scan requests;
- same-origin assets and restrictive response security headers;
- no permissive CORS response;
- bounded content length and accepted content types;
- in-memory filenames reduced to safe display/export names;
- no arbitrary server-side path reads from browser input;
- no browser local/session storage, IndexedDB, external frontend resources, or telemetry;
- safe errors without tracebacks, configuration text, or private path disclosure.

Loopback is a boundary, not authentication for a multi-user host. Stop the process after use,
protect the workstation, and do not expose the port through tunneling, port forwarding, or a
reverse proxy.

## Supported versions

Security fixes are prepared for the current release line. Before a public release exists,
only the latest commit on the rewritten `main` branch is considered supported.

## Reporting a vulnerability

Use GitHub Private Vulnerability Reporting through the repository's **Security** tab when it
is enabled. Include the affected version, impact, and a minimal synthetic reproduction.

Do not attach real device configurations, credentials, private reports, or exploit details to
a public issue. If Private Vulnerability Reporting is not available, open a public issue that
contains no sensitive technical details and asks the maintainer to establish a private
reporting channel. No private email address is designated by this project.

## Disclosure expectations

Please allow reasonable time to reproduce and address a report before public disclosure.
Good-faith research against synthetic or owned data is welcome; this policy does not authorize
access to third-party devices, data, or infrastructure.
