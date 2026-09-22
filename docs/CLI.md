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

## First assessment

```powershell
configguard scan router-config.txt
```

The terminal report shows platform inference and uncertainty, parser completeness, the five
evaluated rule identifiers, qualitative severity, every rule outcome, sanitized evidence,
line numbers, recommendations, diagnostics, and limitations. A completed assessment may
still contain security findings. Conversely, no confirmed weaknesses does not prove that a
device is secure.

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
error.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Assessment completed, whether or not security weaknesses were found. |
| `2` | Invalid CLI arguments, input path, encoding, size, or configuration content. |
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

These are the only implemented security rules. The broader catalog in `docs/CHECKS.md`
contains candidates, not supported checks.

## Privacy and troubleshooting

Treat source configurations and generated reports as confidential. Reports omit raw input,
source paths, and known credential values, but minimized evidence can still expose operational
metadata such as interface, ACL, or address information.

- If input is rejected, confirm it is a non-empty, UTF-8, local regular file no larger than
  2 MiB. Symbolic links and UNC paths are not accepted.
- If the platform is unsupported, provide Cisco IOS or IOS XE-style text. ConfigGuard does
  not attempt a best-effort scan of an incompatible platform.
- If exit code `4` is returned, review parser status, unknown results, unsupported syntax, and
  operational diagnostics. Do not treat the partial result as a pass.
- If report writing fails, select a new filename in an existing writable directory. The tool
  will not replace an existing file.

ConfigGuard performs static configuration assessment only. It does not test exploitation,
reachability, effective runtime state, software vulnerabilities, or compensating controls.
