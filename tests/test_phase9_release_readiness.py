"""Release metadata, documentation, catalog, and CI regressions for v0.1.0."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from configguard import __version__
from configguard.analysis import default_rule_registry
from configguard.cli import ExitCode, main

ROOT = Path(__file__).parents[1]


def test_release_version_has_one_package_source_and_exact_cli_output(
    capsys,  # type: ignore[no-untyped-def]
) -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert __version__ == "0.1.0"
    assert metadata["project"]["dynamic"] == ["version"]
    assert "version" not in metadata["project"]
    assert metadata["tool"]["hatch"]["version"]["path"] == "src/configguard/__init__.py"
    assert main(["version"]) == ExitCode.COMPLETED
    assert capsys.readouterr().out == "ConfigGuard 0.1.0\n"


def test_release_metadata_and_mit_license_are_public_ready() -> None:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")

    assert metadata["name"] == "configguard"
    assert metadata["authors"] == [{"name": "Bashar Asaad"}]
    assert metadata["maintainers"] == [{"name": "Bashar Asaad"}]
    assert metadata["license"] == {"file": "LICENSE"}
    assert "supported Cisco IOS and IOS XE-style" in metadata["description"]
    assert "MIT License" in license_text
    assert "Copyright (c) 2026 Bashar Asaad" in license_text


def test_public_readme_documents_real_install_and_required_commands() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")

    for command in (
        "configguard --help",
        "configguard version",
        "configguard scan router.txt",
        "configguard scan router.txt --details",
        "configguard scan router.txt --format json",
        "configguard scan router.txt --report report.html",
        "configguard web",
        "configguard web --no-open",
        "configguard web --port 9000",
    ):
        assert command in readme
    assert "python -m pip install ." in readme
    assert "pip install configguard" not in readme
    for boundary in (
        "static analysis only",
        "does not connect to devices",
        "runtime verification",
        "cloud upload",
        "automatic remediation",
    ):
        assert boundary.lower() in readme.lower()


def test_rule_catalog_matches_the_exact_seventeen_rule_registry() -> None:
    catalog = (ROOT / "docs/CHECKS.md").read_text(encoding="utf-8")
    headings = dict(re.findall(r"^### (CG-[A-Z0-9]+-\d{3}) — (.+)$", catalog, re.MULTILINE))
    expected = {rule.metadata.rule_id: rule.metadata.title for rule in default_rule_registry()}

    assert len(default_rule_registry()) == 17
    assert headings == expected
    assert "Candidate only" not in catalog
    for section in re.split(r"^### ", catalog, flags=re.MULTILINE)[1:]:
        assert "**Supported syntax:**" in section
        assert any(
            marker in section
            for marker in (
                "**Detection conditions:**",
                "**Detection/applicability:**",
                "**Implemented severity policy:**",
            )
        )
        assert any(
            marker in section
            for marker in (
                "**Potential false positives:**",
                "**False-positive limitations:**",
                "**Limitations:**",
                "**UNKNOWN /",
                "**Uncertainty/applicability states:**",
            )
        )
        assert "**Remediation:**" in section


def test_security_contribution_changelog_and_release_docs_exist_without_contact_email() -> None:
    paths = (
        ROOT / "README.md",
        ROOT / "SECURITY.md",
        ROOT / "CONTRIBUTING.md",
        ROOT / "CHANGELOG.md",
        ROOT / "docs/RELEASING.md",
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in paths)

    assert "GitHub Private Vulnerability Reporting" in combined
    assert "## 0.1.0 - 2026-09-28" in combined
    assert "backup/pre-noreply-history" in combined
    assert "git push --all" in combined
    assert "git push --mirror" in combined
    assert re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", combined, re.I) is None


def test_ci_runs_all_release_quality_gates_without_publication_or_secrets() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    for required in (
        "push:",
        "pull_request:",
        'python-version: "3.12"',
        "python -m pytest",
        "python -m ruff check src tests",
        "python -m ruff format --check src tests",
        "python -m mypy",
        "python -m build",
    ):
        assert required in workflow
    for forbidden in ("pypi", "twine", "secrets.", "release-action"):
        assert forbidden not in workflow.lower()
