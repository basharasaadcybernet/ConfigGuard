# ConfigGuard

<p align="center">
  <img src="src/configguard/web_assets/brand-mark.svg" alt="Bashar Asaad logo" width="84">
</p>

**Offline, deterministic security review for supported Cisco IOS and IOS XE-style configuration files.**

ConfigGuard helps network and security engineers examine exported configurations with
explainable checks, sanitized evidence, stable outcomes, a command-line interface, and a
local Web UI. It performs static analysis only: it does not connect to devices, verify live
runtime state, provide runtime verification, exploit vulnerabilities, or modify
configurations.

ConfigGuard 0.1.0 is maintained by **Bashar Asaad / بشار أسعد** — Cybersecurity | Networking.

## Key features

- 17 deterministic checks across management plane, SNMP, Layer 2, interface IPv4 ACL, and
  routing-protocol authentication controls.
- Conservative outcomes that distinguish confirmed weaknesses, potential risks, hardening,
  secure observations, uncertainty, unsupported syntax, evaluation failures, and
  not-applicable checks.
- Context-aware Cisco IOS / IOS XE-style parsing with source ordering and line-linked,
  sanitized evidence.
- Rich terminal reports, stable JSON schema `1.0.0`, and self-contained printable HTML.
- A bundled local Web UI on loopback with no CDN, telemetry, cloud upload, or scan history.
- Bounded UTF-8 ingestion, centralized secret redaction, safe errors, and no-overwrite report
  output.

## Privacy and local processing

Configuration files can contain credentials, hashes, addresses, topology, and access-control
policy. Treat both source files and generated reports as sensitive security artifacts.

ConfigGuard processes selected files locally and in memory. It does not intentionally upload
configuration content, contact a network device, use cloud or AI services, emit telemetry, or
store browser history. Known credential forms are redacted and unsupported evidence fails
closed, but reports can still contain operational metadata such as line numbers, interface
context, and policy structure.

## Supported scope

Version 0.1.0 targets a documented subset of plain-text Cisco IOS and IOS XE-style
configuration syntax. Implemented areas are:

- management-plane transport, services, source restriction, credential storage, and login;
- SNMP community use and source restriction;
- access-port Port Security, DHCP Snooping, Dynamic ARP Inspection, and BPDU Guard;
- explicitly attached interface IPv4 ACL breadth and reference integrity;
- RIPv2, OSPFv2, and classic IPv4 EIGRP authentication.

The exact supported syntax and outcome boundaries for every rule are documented in
[docs/CHECKS.md](docs/CHECKS.md).

Major unsupported or incomplete areas include Cisco ASA, Cisco NX-OS, Cisco IOS XR, Juniper
Junos, MikroTik RouterOS, Huawei VRP, full IPv6 assessment, OSPFv3, named EIGRP, advanced ACL
constructs, complete interface-template or Port-channel inheritance, runtime topology and
forwarding state, live adjacency/session verification, and software vulnerability/CVE
assessment.

## Requirements

- Python 3.12 or newer.
- A local configuration export that you are authorized to review.

Rich is the only third-party runtime dependency. The local web server uses Python's standard
library.

## Installation from source

ConfigGuard is not published to PyPI in this release-preparation phase. After cloning or
downloading this repository:

```text
cd ConfigGuard
python -m venv .venv
```

Activate the environment on Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

Or on Linux/macOS:

```bash
source .venv/bin/activate
```

Install the package:

```text
python -m pip install .
```

If a wheel is attached to a future GitHub Release, download that wheel and install the local
file explicitly:

```text
python -m pip install ./configguard-0.1.0-py3-none-any.whl
```

## Quick start

```text
configguard --help
configguard version

configguard scan router.txt
configguard scan router.txt --details
configguard scan router.txt --format json
configguard scan router.txt --report report.html

configguard web
configguard web --no-open
configguard web --port 9000
```

`configguard version` returns `ConfigGuard 0.1.0`.

## Command-line usage

The default scan produces a human-readable terminal assessment:

```text
configguard scan router.txt
```

Use `--details` to include all 17 results, including not-applicable observations and complete
sanitized supporting detail. Use `--no-color` for an explicit ASCII/non-color presentation.
Exit codes distinguish completed, partial, unsupported, invalid-input, internal-failure, and
output-failure states; security findings themselves do not turn a completed run into an
application error. See [docs/CLI.md](docs/CLI.md) for the complete contract.

## Local Web UI

```text
configguard web
```

The server binds only to `127.0.0.1` and defaults to `http://127.0.0.1:8765`. It opens the
default browser after binding unless `--no-open` is supplied. `--port 9000` selects another
non-privileged loopback port. Stop it with Ctrl+C.

The browser sends the selected file only to the loopback process. Uploads use the same 2 MiB,
UTF-8, binary, and empty-input validation as the CLI. There is intentionally no public host
option, remote API, persistent browser storage, or cloud service.

## Report formats

JSON is intended for automation and keeps `report_schema_version` at `1.0.0`:

```text
configguard scan router.txt --format json
configguard scan router.txt --format json --output assessment.json
```

HTML is self-contained, offline, escaped, branded, and printable:

```text
configguard scan router.txt --report report.html
```

Output files are created only at explicitly selected new destinations. ConfigGuard does not
create missing output directories or overwrite existing reports. See
[docs/REPORTING.md](docs/REPORTING.md).

## Security-check categories

| Category | Rules | Coverage summary |
| --- | ---: | --- |
| Management Plane | 6 | VTY transport/restriction/login, HTTP, SSH version, plaintext credentials |
| SNMP | 2 | Community-based management and source restrictions |
| Layer 2 | 4 | Port Security, DHCP Snooping, DAI, BPDU Guard |
| Interface IPv4 ACLs | 2 | Broad reachable permits and reference/evaluation integrity |
| Routing Authentication | 3 | OSPFv2, classic IPv4 EIGRP, and RIPv2 |
| **Total** | **17** | Deterministic checks in v0.1.0 |

## Interpreting results

- A `SECURE` result is narrow: it confirms only the implemented configuration-visible check.
- `UNKNOWN`, `UNSUPPORTED_SYNTAX`, and `NOT_EVALUATED` are not passes.
- `NOT_APPLICABLE` requires sufficient positive evidence; absence alone is not proof.
- `PARTIAL` means the assessment completed with unresolved conclusions. It does not imply a
  truncated read or parser crash.
- Zero findings or zero severity does not prove that a device is secure.
- ConfigGuard does not verify reachability, software patch state, live enforcement, peer-key
  agreement, topology, compensating controls, or exploitability.
- No numerical score or automatic remediation is provided.

## Project structure

```text
src/configguard/       package, parser, rules, reporting, CLI, and local Web UI
tests/                 synthetic fixtures and regression tests
docs/CHECKS.md         exact 17-rule catalog
docs/CLI.md            command and exit-code contract
docs/REPORTING.md      JSON/HTML reporting and privacy contract
docs/RELEASING.md      maintainer-only manual release procedure
SECURITY.md             security model and vulnerability reporting guidance
```

## Development and testing

Install development dependencies from a source checkout:

```text
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy
python -m build
```

Tests must use synthetic configurations only. Never commit real customer/device exports,
credentials, reports, or private infrastructure details. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Security policy

Review [SECURITY.md](SECURITY.md) before handling configurations or reporting a vulnerability.
Use GitHub Private Vulnerability Reporting when it is enabled for the public repository; do
not place credentials, real configurations, or exploit details in a public issue.

## License

ConfigGuard source code is available under the [MIT License](LICENSE).

## Author and maintainer

**Bashar Asaad / بشار أسعد**<br>
Cybersecurity | Networking
