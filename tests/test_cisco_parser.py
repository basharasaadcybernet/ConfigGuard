"""Context, observation, uncertainty, and determinism tests for the Cisco parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from configguard.domain import ContextKind, ParseStatus, PlatformFamily
from configguard.parsing import (
    CiscoConfigurationParser,
    ConfigurationSource,
    MalformedConfigurationError,
    UnsupportedPlatformError,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _fixture(name: str) -> ConfigurationSource:
    return ConfigurationSource(name, (FIXTURES / name).read_text(encoding="utf-8"))


def _kinds(source_name: str) -> set[str]:
    parsed = CiscoConfigurationParser().parse(_fixture(source_name))
    return {observation.kind for observation in parsed.observations}


def test_identifies_ios_and_ios_xe_conservatively() -> None:
    parser = CiscoConfigurationParser()

    ios = parser.identify(_fixture("synthetic_ios_router.txt"))
    ios_xe = parser.identify(_fixture("synthetic_ios_xe_switch.txt"))
    candidate = parser.identify(
        ConfigurationSource(
            "candidate.txt",
            "hostname TEST\ninterface GigabitEthernet0/0\n description TEST\n",
        )
    )

    assert ios.platform is PlatformFamily.CISCO_IOS and ios.compatible
    assert ios_xe.platform is PlatformFamily.CISCO_IOS_XE and ios_xe.compatible
    assert candidate.platform is PlatformFamily.UNKNOWN and candidate.compatible

    candidate_result = parser.parse(
        ConfigurationSource(
            "candidate.txt",
            "hostname TEST\ninterface GigabitEthernet0/0\n description TEST\n",
        )
    )
    assert candidate_result.status is ParseStatus.PARTIAL
    assert any(item.code == "CG-PARSE-UNKNOWN-PLATFORM" for item in candidate_result.diagnostics)


def test_rejects_clearly_unsupported_and_unstructured_input() -> None:
    parser = CiscoConfigurationParser()

    with pytest.raises(UnsupportedPlatformError, match="unsupported"):
        parser.parse(ConfigurationSource("synthetic-junos.txt", "system {\n host-name TEST;\n}"))
    with pytest.raises(UnsupportedPlatformError, match="unsupported"):
        parser.parse(ConfigurationSource("notes.txt", "this is not a configuration"))
    with pytest.raises(MalformedConfigurationError, match="empty"):
        parser.parse(ConfigurationSource("empty.txt", "   \n"))


def test_router_fixture_preserves_contexts_lines_and_required_observations() -> None:
    parsed = CiscoConfigurationParser().parse(_fixture("synthetic_ios_router.txt"))
    contexts = {command.context.kind for command in parsed.commands}
    kinds = {observation.kind for observation in parsed.observations}

    assert parsed.status is ParseStatus.PARSED
    assert parsed.platform is PlatformFamily.CISCO_IOS
    assert parsed.metrics.unsupported_command_count == 0
    assert {ContextKind.GLOBAL, ContextKind.INTERFACE, ContextKind.LINE} <= contexts
    assert {ContextKind.AAA, ContextKind.ACL, ContextKind.ROUTER, ContextKind.VLAN} <= contexts
    assert {
        "line.transport",
        "line.authentication",
        "line.access_class",
        "management.ssh_setting",
        "management.http_setting",
        "authentication.local_user",
        "authentication.aaa_method_list",
        "snmp.community",
        "snmp.group",
        "snmp.user",
        "interface.declaration",
        "interface.shutdown",
        "interface.access_group",
        "acl.definition",
        "acl.entry",
        "routing.process",
        "routing.authentication",
        "vlan.declaration",
    } <= kinds
    assert all(command.location.line_start >= 1 for command in parsed.commands)
    assert all(
        command.parent_context is not None
        for command in parsed.commands
        if command.context.kind is not ContextKind.GLOBAL
    )
    assert not any(command.text.lstrip().startswith("!") for command in parsed.commands)


def test_switch_fixture_extracts_layer2_and_repeated_interface_facts() -> None:
    parsed = CiscoConfigurationParser().parse(_fixture("synthetic_ios_xe_switch.txt"))
    kinds = {observation.kind for observation in parsed.observations}

    assert parsed.status is ParseStatus.PARSED
    assert parsed.platform is PlatformFamily.CISCO_IOS_XE
    assert {
        "interface.switchport_mode",
        "interface.access_vlan",
        "interface.port_security",
        "interface.dhcp_snooping_trust",
        "interface.arp_inspection_trust",
        "interface.spanning_tree_portfast",
        "interface.bpdu_guard",
        "layer2.dhcp_snooping_vlan",
        "layer2.arp_inspection_vlan",
        "layer2.bpdu_guard_default",
    } <= kinds
    interface_declarations = [
        observation
        for observation in parsed.observations
        if observation.kind == "interface.declaration"
    ]
    assert len(interface_declarations) == 2


def test_unknown_commands_are_retained_redacted_and_mark_parse_partial() -> None:
    secret = "SYNTHETIC-UNKNOWN-SECRET"
    source = ConfigurationSource(
        "unknown.txt",
        f"version 15.7\nhostname TEST\ninterface Loopback0\n mystery-command {secret}\nend\n",
    )

    parsed = CiscoConfigurationParser().parse(source)

    assert parsed.status is ParseStatus.PARTIAL
    assert parsed.metrics.unsupported_command_count == 1
    assert len(parsed.unsupported_syntax) == 1
    assert any(item.kind == "command.unclassified" for item in parsed.observations)
    assert secret not in repr(parsed)
    assert secret not in " ".join(item.message for item in parsed.diagnostics)


def test_unsupported_section_lines_remain_visible_for_coverage() -> None:
    source = ConfigurationSource(
        "unsupported-section.txt",
        "version 17.9\n"
        "hostname TEST\n"
        "interface Loopback0\n"
        " description TEST\n"
        "!\n"
        "telemetry ietf subscription 101\n"
        " encoding encode-kvgpb\n"
        " filter xpath /synthetic/path\n"
        "end\n",
    )

    parsed = CiscoConfigurationParser().parse(source)

    assert parsed.status is ParseStatus.PARTIAL
    assert parsed.metrics.unsupported_command_count == 3
    assert len(parsed.unsupported_syntax) == 3


def test_truncated_sensitive_block_is_incomplete_without_leaking_content() -> None:
    secret = "SYNTHETIC-BANNER-CONTENT"
    source = ConfigurationSource(
        "truncated.txt",
        "version 15.7\n"
        "hostname TEST\n"
        "line vty 0 4\n"
        " transport input ssh\n"
        "!\n"
        "banner motd ^C\n"
        f"{secret}\n",
    )

    parsed = CiscoConfigurationParser().parse(source)

    assert parsed.status is ParseStatus.INCOMPLETE
    assert any(item.code == "CG-PARSE-INCOMPLETE-BLOCK" for item in parsed.diagnostics)
    assert secret not in repr(parsed)


def test_missing_and_repeated_commands_are_data_not_security_judgments() -> None:
    source = ConfigurationSource(
        "repeated.txt",
        "version 15.7\n"
        "hostname TEST\n"
        "line vty 0 4\n"
        " transport input ssh\n"
        " transport input ssh\n"
        "end\n",
    )

    parsed = CiscoConfigurationParser().parse(source)
    transports = [item for item in parsed.observations if item.kind == "line.transport"]

    assert len(transports) == 2
    assert not any(item.kind.startswith("finding.") for item in parsed.observations)


def test_identical_input_produces_identical_structured_output() -> None:
    parser = CiscoConfigurationParser()
    source = _fixture("synthetic_ios_router.txt")

    assert parser.parse(source) == parser.parse(source)


def test_required_context_families_have_observations() -> None:
    router_kinds = _kinds("synthetic_ios_router.txt")
    switch_kinds = _kinds("synthetic_ios_xe_switch.txt")

    assert "acl.entry" in router_kinds
    assert "routing.process" in router_kinds
    assert "vlan.declaration" in router_kinds | switch_kinds


def test_classifies_valid_irrelevant_multilink_and_serial_commands() -> None:
    source = ConfigurationSource(
        "synthetic-legacy-router.txt",
        "version 15.7\n"
        "hostname TEST\n"
        "multilink bundle-name authenticated\n"
        "interface Serial0/0\n"
        " serial restart-delay 0\n"
        "!\n"
        "line vty 0 4\n"
        " transport input ssh\n"
        "end\n",
    )

    parsed = CiscoConfigurationParser().parse(source)

    assert parsed.status is ParseStatus.PARSED
    assert parsed.metrics.command_count == parsed.metrics.classified_command_count
    assert parsed.metrics.unsupported_command_count == 0
    assert not parsed.unsupported_syntax
    assert any(command.name == "multilink" for command in parsed.commands)
    assert any(command.name == "serial" for command in parsed.commands)
