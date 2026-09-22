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

## Phase 4.1 status

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

Phase 3 adds a shared deterministic analysis engine and exactly five checks:

- `CG-MGMT-001`: explicit Telnet/all inbound transport on VTY ranges;
- `CG-MGMT-006`: effective explicit plaintext HTTP management enablement;
- `CG-MGMT-002`: effective explicit SSH protocol version 1 selection;
- `CG-SNMP-001`: effective SNMP community-based management declarations;
- `CG-SNMP-002`: supported SNMP community source-ACL references.

Each rule consumes structured observations, not raw configuration searches. Results include
explicit secure, confirmed-insecure, potential-risk, not-applicable, unknown, not-evaluated,
and unsupported-syntax states. Findings carry qualitative severity and independent evidence
confidence; there is no numerical score.

This is a deliberately limited configuration assessment, not a complete router or switch
security audit. It does not demonstrate live reachability or exploitability. Phase 4 adds an
installable local CLI with terminal output and versioned JSON/self-contained HTML reports.
Phase 4.1 adds real-configuration regression validation, rule-scoped unsupported-syntax
handling, consistent dependent SNMP applicability, and clearer printable reports.

## Command-line use

```powershell
configguard --help
configguard version
configguard scan router-config.txt
configguard scan router-config.txt --format json
configguard scan router-config.txt --format json --output result.json
configguard scan router-config.txt --report report.html
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

Python 3.12 is required. Runtime dependencies are currently empty. The optional `dev`
extra contains only the build and verification tools used by this repository.

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
