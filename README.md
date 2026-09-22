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

## Phase 1 status

Phase 1 establishes:

- a Python 3.12 package and typed domain contracts;
- parser, rule, and evidence-sanitizer interfaces;
- explicit severity, confidence, applicability, and uncertainty states;
- architecture regression tests using synthetic data;
- a candidate check catalog and security/architecture documentation.

Phase 1 deliberately does **not** contain a Cisco parser, security-rule implementations,
an analysis engine, scoring, a scanner CLI, report rendering, an API, or a frontend.
Installing this package does not yet provide a usable configuration scan command.

## Development environment

Python 3.12 is required. Runtime dependencies are currently empty. The optional `dev`
extra contains only the build and verification tools used by this repository.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Run the Phase 1 checks:

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

Later phases may add validated in-memory input, Cisco IOS/IOS XE context parsing,
deterministic rules, sanitized findings, a shared analysis engine, a CLI, and explicit
JSON/HTML export. See [ROADMAP.md](ROADMAP.md). Numerical scoring remains deferred until
a transparent and tested policy exists.
