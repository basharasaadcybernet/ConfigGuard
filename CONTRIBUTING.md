# Contributing to ConfigGuard

Thank you for helping improve ConfigGuard. Contributions must preserve its offline,
deterministic, privacy-conscious design and the documented uncertainty boundaries.

## Development setup

Python 3.12 or newer is required.

```text
python -m venv .venv
python -m pip install -e ".[dev]"
```

Activate the environment with `.\.venv\Scripts\Activate.ps1` on Windows PowerShell or
`source .venv/bin/activate` on Linux/macOS.

## Required checks

Run these before submitting a change:

```text
python -m pytest
python -m ruff check src tests
python -m ruff format --check src tests
python -m mypy
python -m build
```

Add focused regression tests for behavior changes. Keep rule outcomes, applicability,
severity, confidence, and evidence boundaries explicit.

## Configuration privacy

- Use only synthetic fixtures with obvious synthetic identities and values.
- Do not commit customer, employer, lab-production, or personal device configurations.
- Do not include real credentials, SNMP communities, keys, private reports, local paths, or
  identifying topology in tests, issues, screenshots, commits, or pull requests.
- Reproduce security problems with the smallest synthetic input possible.
- Treat generated reports as potentially sensitive even after redaction.

## Change scope and commits

Keep changes narrowly scoped and avoid unrelated formatting or generated artifacts. Use clear,
imperative commit subjects. New rules, parser syntax, vendors, scoring, live-device behavior,
or report-schema changes require a separately reviewed scope and tests; they are not routine
release-hardening changes.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) and never publish sensitive details in
a public issue.
