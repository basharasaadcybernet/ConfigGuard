# ConfigGuard CLI

ConfigGuard requires Python 3.12 or newer. It is an offline tool: it reads one explicitly
selected local configuration and does not connect to a network device or upload content.

## Installation

From this repository, create a virtual environment and install the package:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install .
```

Confirm the installed command:

```powershell
configguard --help
configguard version
```

## Local Web UI

```powershell
configguard web
configguard web --port 9000
configguard web --no-open
```

`configguard web` binds only to `127.0.0.1` on port `8765`, prints the local URL, then opens
the default browser after binding succeeds. `--port` accepts a value from 1024 through 65535;
`--no-open` fully disables automatic browser opening. There is intentionally no `--host`
option. An occupied port produces a concise error without a traceback, and Ctrl+C stops the
server without leaving a child process.

The browser interface accepts a selected or dropped configuration, applies the same 2 MiB,
UTF-8, binary, and empty-input validation as `scan`, and invokes the same seventeen-rule
assessment service. Processing occurs locally and in memory: no cloud upload, telemetry,
scan-history database, browser storage, or intentional upload persistence is used. The
supported scope is Cisco IOS / IOS XE-style syntax within ConfigGuard's documented subset,
not arbitrary Cisco products or live devices.

## First assessment

```powershell
configguard scan router-config.txt
```

The default terminal report starts with platform/parser status, rule and diagnostic counts,
and outcome/severity summaries. It shows every confirmed weakness, potential risk, hardening
result, unknown/unsupported evaluation, and supported pass. `NOT_APPLICABLE` results are
counted but visually suppressed to reduce noise.

Show all seventeen rule results, complete sanitized evidence, technical references, full
diagnostic messages, and limitations:

```powershell
configguard scan router-config.txt --details
```

Color is enabled only for an interactive terminal. Redirected output uses an ASCII, non-color
fallback, and color can be disabled explicitly:

```powershell
configguard scan router-config.txt --no-color
```

Every result retains textual classification, outcome, severity, and confidence labels; color
is never the only distinction. A completed assessment may still contain security findings,
and no confirmed weaknesses does not prove that a device is secure.

Generate JSON on standard output:

```powershell
configguard scan router-config.txt --format json
```

Write JSON to a new, explicitly selected file:

```powershell
configguard scan router-config.txt --format json --output result.json
```

Generate a self-contained HTML report while retaining terminal output:

```powershell
configguard scan router-config.txt --report report.html
```

ConfigGuard does not create missing output directories and does not overwrite an existing
report. JSON mode emits only valid JSON to standard output; operational errors use standard
error. `--details` and `--no-color` affect terminal presentation only and never alter JSON.

## Command discovery

```powershell
configguard --help
configguard scan --help
configguard web --help
configguard version
```

The top-level help describes the local, static, read-only workflow and available commands.
Scan help documents the required file, supported high-level IOS/IOS XE-style scope, output
options, examples, and exit codes. Web help documents its local-only privacy boundary, port,
browser behavior, examples, and process lifetime. The version command remains one
undecorated line suitable for scripts.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Assessment completed, whether or not security weaknesses were found. |
| `2` | Invalid CLI arguments/input, or failure to bind the requested local web port. |
| `3` | Configuration platform or syntax is unsupported. |
| `4` | Partial assessment due to parser or rule uncertainty. |
| `5` | Internal application failure. |
| `6` | JSON or HTML report generation/write failure. |

Security findings intentionally do not change the completed-assessment exit code. This keeps
an insecure configuration distinct from an application crash. Automation should inspect the
JSON finding outcomes and severities after exit code `0`.

## Implemented rules

- `CG-MGMT-001` — VTY Telnet transport.
- `CG-MGMT-006` — plaintext HTTP management.
- `CG-MGMT-002` — SSH version 1.
- `CG-SNMP-001` — SNMP community configuration.
- `CG-SNMP-002` — SNMP community access restriction.
- `CG-MGMT-003` — inbound VTY source restriction and ACL resolution.
- `CG-MGMT-005` — explicit type 0 plaintext credential storage.
- `CG-MGMT-004` — explicit VTY/console login authentication.
- `CG-L2-001` — explicit access-port Port Security posture.
- `CG-L2-002` — DHCP Snooping VLAN coverage and access-port trust.
- `CG-L2-003` — Dynamic ARP Inspection VLAN coverage and interface trust.
- `CG-L2-004` — BPDU Guard on explicit PortFast/edge ports.
- `CG-ACL-001` — broad permissions in explicitly attached interface IPv4 ACLs.
- `CG-ACL-002` — interface IPv4 ACL reference and evaluation integrity.

- `CG-ROUTE-001`: OSPFv2 neighbor authentication.
- `CG-ROUTE-002`: classic IPv4 EIGRP authentication.
- `CG-ROUTE-003`: RIPv2 authentication.

These seventeen are the only implemented security rules. `docs/CHECKS.md` documents their
exact supported syntax, outcomes, uncertainty boundaries, limitations, and remediation.

## Privacy and troubleshooting

Treat source configurations and generated reports as confidential. Reports omit raw input,
source paths, and known credential values, but minimized evidence can still expose operational
metadata such as interface identity and line relationships. ACL identifiers and literal
addresses in supported evidence are minimized or redacted.

- If input is rejected, confirm it is a non-empty, UTF-8, local regular file no larger than
  2 MiB. Symbolic links and UNC paths are not accepted.
- If the platform is unsupported, provide Cisco IOS or IOS XE-style text. ConfigGuard does
  not attempt a best-effort scan of an incompatible platform.
- If exit code `4` is returned, review parser status, unknown results, unsupported syntax, and
  operational diagnostics. Do not treat the partial result as a pass.
- If report writing fails, select a new filename in an existing writable directory. The tool
  will not replace an existing file.
- If `configguard web` reports an unavailable port, stop the local process using that port or
  choose another with `--port`. ConfigGuard never falls back to a public interface.

ConfigGuard performs static configuration assessment only. It does not test exploitation,
reachability, effective runtime state, software vulnerabilities, or compensating controls.
