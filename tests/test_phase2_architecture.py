"""Regression tests for the parser's offline and non-executing architecture."""

from __future__ import annotations

import ast
import os
import subprocess
from pathlib import Path

import pytest

from configguard.parsing import CiscoConfigurationParser, ConfigurationSource

SOURCE_ROOT = Path(__file__).parents[1] / "src" / "configguard"
PROHIBITED_IMPORT_ROOTS = {
    "aiohttp",
    "ftplib",
    "http",
    "httpx",
    "netmiko",
    "paramiko",
    "requests",
    "socket",
    "subprocess",
    "telnetlib",
    "urllib",
}


def test_parser_and_sanitizer_do_not_import_network_or_process_clients() -> None:
    inspected = [
        *sorted((SOURCE_ROOT / "parsing").glob("*.py")),
        *sorted((SOURCE_ROOT / "sanitization").glob("*.py")),
    ]

    for path in inspected:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imports: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imports.add(node.module.split(".", maxsplit=1)[0])
        assert imports.isdisjoint(PROHIBITED_IMPORT_ROOTS), path.name


def test_arbitrary_configuration_lines_are_never_executed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        del args, kwargs
        calls.append("called")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    source = ConfigurationSource(
        "hostile.txt",
        "version 15.7\nhostname TEST\ninterface Loopback0\n $(SYNTHETIC-COMMAND)\nend\n",
    )

    parsed = CiscoConfigurationParser().parse(source)

    assert calls == []
    assert parsed.unsupported_syntax
