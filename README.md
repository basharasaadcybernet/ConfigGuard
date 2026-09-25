# ConfigGuard

ConfigGuard is an offline **Network Configuration Security Auditor** by Bashar Asaad.
It is intended to help network and security engineers review exported device
configurations with deterministic, explainable checks while preserving the distinction
between confirmed misconfiguration, potential risk, hardening advice, and missing evidence.

The initial v0.1 scope is plain-text `running-config` exports from Cisco IOS and Cisco IOS
XE routers and switches. NX-OS, ASA, IOS XR, Junos, RouterOS, FortiOS, and other syntaxes
are explicitly outside that scope.

## Why it exists

Manual reviews are slow and inconsistent, while simple keyword searches lose command
context. ConfigGuard is designed around a context-aware parser, a structured intermediate
representation, deterministic rules, line-linked evidence, and centralized redaction. It
does not connect to devices, execute configuration content, upload data, or use cloud/AI
services.

Intended users include network security assessors, network engineers, defensive security
teams, consultants, educators, and lab users who are authorized to review a configuration.

## Phase 8B status

Phase 1 established the package and typed contracts. Phase 2 provides:

- bounded, read-only ingestion of explicitly selected local UTF-8 files (optional BOM), with
  a configurable 2 MiB default limit;
- conservative Cisco IOS, IOS XE, compatible IOS-style, and unsupported-format detection;
- deterministic, context-aware parsing with line-numbered commands and observations;
- parser completeness metrics and secret-free diagnostics for partial/incomplete input;
- centralized Cisco credential redaction and fail-closed rendering for unknown commands.

Supported contexts are global, interface, VTY/console line, AAA, named and numbered ACL,
router protocol, VLAN, and sensitive crypto/certificate blocks. The parser extracts facts
for management settings, authentication/AAA, SNMP, interfaces, ACL ordering, routing
authentication, VLANs, and selected Layer 2 controls. Unsupported commands remain visible
as redacted, unclassified observations.

Phase 3 added a shared deterministic analysis engine and five checks:

- `CG-MGMT-001`: explicit Telnet/all inbound transport on VTY ranges;
- `CG-MGMT-006`: effective explicit plaintext HTTP management enablement;
- `CG-MGMT-002`: effective explicit SSH protocol version 1 selection;
- `CG-SNMP-001`: effective SNMP community-based management declarations;
- `CG-SNMP-002`: supported SNMP community source-ACL references.

Phase 5A adds exactly three management-plane checks, bringing the deterministic registry to
eight rules:

- `CG-MGMT-003`: effective inbound VTY source restrictions and referenced ACL breadth;
- `CG-MGMT-005`: explicit type 0 plaintext storage for local, enable, and line passwords;
- `CG-MGMT-004`: explicit VTY/console login authentication and resolvable local/AAA
  prerequisites.

Phase 5B adds exactly three conservative Layer 2 switch checks, bringing the registry to
eleven rules:

- `CG-L2-001`: explicit Port Security state and supported violation mode on explicit access
  ports;
- `CG-L2-002`: explicit global/VLAN DHCP Snooping coverage and access-port trust state;
- `CG-L2-004`: effective BPDU Guard state on explicitly configured PortFast/edge ports.

Phase 5C adds exactly one rule, bringing the registry to twelve:

- `CG-L2-003`: explicit Dynamic ARP Inspection VLAN coverage, access/trunk trust context,
  and supported DHCP Snooping prerequisite evidence.

Each rule consumes structured observations, not raw configuration searches. Results include
explicit secure, confirmed-insecure, potential-risk, not-applicable, unknown, not-evaluated,
and unsupported-syntax states. Findings carry qualitative severity and independent evidence
confidence; there is no numerical score.

This is a deliberately limited configuration assessment, not a complete router or switch
security audit. It does not demonstrate live reachability or exploitability. Phase 4 adds an
installable local CLI with terminal output and versioned JSON/self-contained HTML reports.
Phase 4.1 adds real-configuration regression validation, rule-scoped unsupported-syntax
handling, consistent dependent SNMP applicability, and clearer printable reports.
Phase 6 keeps the registry at exactly twelve rules and adds a typed interface-resolution
layer. It expands only bounded, unambiguous `GigabitEthernet`/`Gi`, `FastEthernet`/`Fa`, and
`TenGigabitEthernet`/`Te` ranges whose last numeric component is contiguous, including
comma-separated members. Direct and range commands share source ordering, so a later
supported command or negation determines the resolved fact.

Interface-template declarations and exact `source template NAME` applications are detected.
Unused templates have no effect; applied, missing, nested, or cyclic inheritance remains
Unknown because cross-release precedence is not inferred. Supported `channel-group N mode`
relationships are recorded, including removal, but logical Port-channel configuration is not
copied to physical members (or vice versa); inheritance and operational formation remain
Unknown. Range-derived evidence reports both its concrete target and original range context.
The resolver does not prove physical roles, runtime VLAN forwarding, DHCP bindings, DAI/STP
enforcement, or EtherChannel formation, and adds no rule, score, or device connectivity.

Phase 7A adds exactly two interface IPv4 ACL rules, bringing the registry to fourteen:

- `CG-ACL-001`: reachable broad permits in supported ACLs explicitly attached with
  `ip access-group`, classified conservatively by direction and breadth;
- `CG-ACL-002`: integrity and evaluability of effective interface ACL references.

The evaluator supports a bounded named/numbered standard and extended IPv4 subset, ordered
entries and supported sequence numbers, `any`/`host`/IPv4 wildcard expressions, selected
protocol and port qualifiers, attachment replacement/removal, and range provenance. Merely
defined, VTY-only, SNMP-only, and IPv6 ACLs are not interface IPv4 attachments. Missing or
empty policies, advanced constructs, unresolved templates, relevant Port-channel relations,
and conflicting attachment removals remain explicit uncertainty. This is not comprehensive
firewall analysis, topology inference, or packet-flow simulation.

Phase 7B adds exactly three routing-protocol authentication rules, bringing the registry to
seventeen:

- `CG-ROUTE-001`: supported OSPFv2 area/interface authentication and matching keys;
- `CG-ROUTE-002`: classic IPv4 EIGRP MD5 authentication and usable key chains;
- `CG-ROUTE-003`: explicit RIPv2 version, interface authentication mode, and usable key
  chains.

Supported process/network statements are correlated with effective interface IPv4 addresses,
explicit OSPF process/area bindings, passive-interface state, source ordering, negation, and
bounded interface-range provenance. Named EIGRP, OSPFv3, unresolved templates/Port-channels,
and relevant unknown syntax are never reinterpreted as a pass. A Secure result is limited to
complete supported static configuration; it does not prove peer key agreement, adjacency,
runtime traffic, reachability, or secret strength.

Phase 7C keeps exactly seventeen rules and validates the routing integration with controlled
RIP, OSPF, EIGRP, multi-process, and interface-range scenarios. A supported negation that
does not match the active network or OSPF area association now preserves `UNKNOWN` rather
than leaving a false pass. Passive-only applicability is counted per process/interface pair,
and uncertain/not-applicable routing results retain safe process, interface, network, and
source-line evidence without exposing routing secrets.

Phase 8B changes presentation only. The Rich-powered terminal report adds a compact overview,
outcome and severity counts, wrapped result panels, interactive color, an ASCII redirected
fallback, and a quieter default view that summarizes `NOT_APPLICABLE` results. `--details`
shows every rule plus complete sanitized evidence, references, diagnostics, and limitations.
The parser, resolvers, seventeen rules, JSON schema, HTML semantics, and exit codes are
unchanged.

## Command-line use

```powershell
configguard --help
configguard version
configguard scan router-config.txt
configguard scan router-config.txt --details
configguard scan router-config.txt --no-color
configguard scan router-config.txt --format json
configguard scan router-config.txt --format json --output result.json
configguard scan router-config.txt --report report.html
configguard scan --help
```

Reports are created only at explicitly selected new destinations. ConfigGuard will not create
missing output directories or overwrite existing files. See [docs/CLI.md](docs/CLI.md) for
exit codes and usage, and [docs/REPORTING.md](docs/REPORTING.md) for the reporting contract.

## Library ingestion and parsing

```python
from configguard.analysis import default_analysis_engine
from configguard.parsing import CiscoConfigurationParser, ConfigurationIngestor

source = ConfigurationIngestor().read("explicitly-selected-running-config.txt")
parsed = CiscoConfigurationParser().parse(source)
result = default_analysis_engine().analyze(parsed)
print(result.to_public_dict())
```

The input remains in memory. No copy or report is written. Raw command text is internal
sensitive data; public evidence must be produced through `CiscoEvidenceSanitizer`.

## Development environment

Python 3.12 is required. Rich is the bounded runtime dependency used for human-readable
terminal output. The optional `dev` extra contains the build and verification tools.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the project checks:

```powershell
python -m pytest
python -m ruff check .
python -m mypy
python -m build
python -c "import configguard; print(configguard.__version__)"
```

Do not use real customer or production configurations as test fixtures. See
[SECURITY.md](SECURITY.md) before handling sensitive configuration data.

## Planned capabilities

See [ROADMAP.md](ROADMAP.md). Additional rules, numerical scoring, APIs, and user interfaces
remain outside this phase.
