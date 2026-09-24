"""Focused synthetic regressions for Phase 7B routing authentication checks."""

from __future__ import annotations

import json

import pytest

from configguard.analysis import default_analysis_engine, resolve_routing_authentication
from configguard.domain import AssessmentOutcome, ParseStatus, Severity
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource
from configguard.reporting import build_assessment_report, render_html, render_json, render_terminal
from configguard.rules import (
    EigrpAuthenticationRule,
    OspfAuthenticationRule,
    RipAuthenticationRule,
)


def _text(*commands: str) -> str:
    return "\n".join(
        (
            "version 17.9",
            "platform punt-keepalive disable-kernel-core",
            "hostname SYNTHETIC-PHASE7B",
            *commands,
            "end",
            "",
        )
    )


def _parse(*commands: str):  # type: ignore[no-untyped-def]
    return CiscoConfigurationParser().parse(
        ConfigurationSource("synthetic-phase7b.txt", _text(*commands))
    )


def test_ospfv2_message_digest_and_area_inheritance_are_narrowly_secure() -> None:
    direct = _parse(
        "interface GigabitEthernet0/1",
        " ip address 192.0.2.1 255.255.255.0",
        " ip ospf authentication message-digest",
        " ip ospf message-digest-key 1 md5 SYNTHETIC-OSPF-SECRET",
        "!",
        "router ospf 10",
        " network 192.0.2.0 0.0.0.255 area 0",
        "!",
    )
    inherited = _parse(
        "interface GigabitEthernet0/1",
        " ip address 192.0.2.1 255.255.255.0",
        " ip ospf message-digest-key 1 md5 SYNTHETIC-OSPF-SECRET",
        "!",
        "router ospf 10",
        " area 0 authentication message-digest",
        " network 192.0.2.0 0.0.0.255 area 0",
        "!",
    )

    assert OspfAuthenticationRule().evaluate(direct).outcome is AssessmentOutcome.SECURE
    assert OspfAuthenticationRule().evaluate(inherited).outcome is AssessmentOutcome.SECURE


def test_ospf_simple_password_is_hardening_and_null_is_potential_risk() -> None:
    simple = _parse(
        "interface GigabitEthernet0/1",
        " ip address 192.0.2.1 255.255.255.0",
        " ip ospf authentication",
        " ip ospf authentication-key SYNTHETIC-SIMPLE-SECRET",
        "!",
        "router ospf 10",
        " network 192.0.2.0 0.0.0.255 area 0",
        "!",
    )
    disabled = _parse(
        "interface GigabitEthernet0/1",
        " ip ospf 10 area 0",
        " ip ospf authentication null",
        "!",
        "router ospf 10",
        "!",
    )

    weak = OspfAuthenticationRule().evaluate(simple)
    adverse = OspfAuthenticationRule().evaluate(disabled)
    assert weak.outcome is AssessmentOutcome.HARDENING
    assert weak.severity is Severity.LOW
    assert adverse.outcome is AssessmentOutcome.POTENTIAL_RISK
    assert adverse.severity is Severity.MEDIUM


def test_ospf_missing_key_and_interface_override_removal_remain_unknown() -> None:
    parsed = _parse(
        "interface GigabitEthernet0/1",
        " ip ospf 10 area 0",
        " ip ospf authentication message-digest",
        " no ip ospf authentication",
        "!",
        "router ospf 10",
        "!",
    )

    assert OspfAuthenticationRule().evaluate(parsed).outcome is AssessmentOutcome.UNKNOWN


def test_ripv2_md5_and_classful_network_matching_are_narrowly_secure() -> None:
    parsed = _parse(
        "key chain SYNTHETIC-RIP-CHAIN",
        " key 1",
        "  key-string SYNTHETIC-RIP-SECRET",
        "!",
        "interface GigabitEthernet0/1",
        " ip address 10.1.2.3 255.255.255.0",
        " ip rip authentication mode md5",
        " ip rip authentication key-chain SYNTHETIC-RIP-CHAIN",
        "!",
        "router rip",
        " version 2",
        " network 10.0.0.0",
        "!",
    )

    assert RipAuthenticationRule().evaluate(parsed).outcome is AssessmentOutcome.SECURE


def test_rip_text_is_hardening_and_missing_version_is_unknown() -> None:
    commands = (
        "key chain SYNTHETIC-RIP-CHAIN",
        " key 1",
        "  key-string SYNTHETIC-RIP-SECRET",
        "!",
        "interface GigabitEthernet0/1",
        " ip address 10.1.2.3 255.255.255.0",
        " ip rip authentication mode text",
        " ip rip authentication key-chain SYNTHETIC-RIP-CHAIN",
        "!",
        "router rip",
    )
    weak = RipAuthenticationRule().evaluate(
        _parse(*commands, " version 2", " network 10.0.0.0", "!")
    )
    unknown = RipAuthenticationRule().evaluate(_parse(*commands, " network 10.0.0.0", "!"))

    assert weak.outcome is AssessmentOutcome.HARDENING
    assert unknown.outcome is AssessmentOutcome.UNKNOWN


def test_classic_eigrp_md5_requires_matching_as_and_usable_key_chain() -> None:
    secure = _parse(
        "key chain SYNTHETIC-EIGRP-CHAIN",
        " key 7",
        "  key-string SYNTHETIC-EIGRP-SECRET",
        "!",
        "interface GigabitEthernet0/1",
        " ip address 172.16.1.1 255.255.255.0",
        " ip authentication mode eigrp 100 md5",
        " ip authentication key-chain eigrp 100 SYNTHETIC-EIGRP-CHAIN",
        "!",
        "router eigrp 100",
        " network 172.16.0.0 0.0.255.255",
        "!",
    )
    mismatch = secure.observations
    parsed_mismatch = _parse(
        "key chain SYNTHETIC-EIGRP-CHAIN",
        " key 7",
        "  key-string SYNTHETIC-EIGRP-SECRET",
        "!",
        "interface GigabitEthernet0/1",
        " ip address 172.16.1.1 255.255.255.0",
        " ip authentication mode eigrp 200 md5",
        " ip authentication key-chain eigrp 200 SYNTHETIC-EIGRP-CHAIN",
        "!",
        "router eigrp 100",
        " network 172.16.0.0 0.0.255.255",
        "!",
    )

    assert mismatch
    assert EigrpAuthenticationRule().evaluate(secure).outcome is AssessmentOutcome.SECURE
    assert EigrpAuthenticationRule().evaluate(parsed_mismatch).outcome is AssessmentOutcome.UNKNOWN


def test_named_eigrp_is_unsupported_and_ospfv3_is_not_reinterpreted() -> None:
    named = _parse("router eigrp CAMPUS", " address-family ipv4 autonomous-system 100", "!")
    ospfv3 = _parse("router ospfv3 10", " address-family ipv6 unicast", "!")

    assert EigrpAuthenticationRule().evaluate(named).outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX
    assert OspfAuthenticationRule().evaluate(ospfv3).outcome is AssessmentOutcome.NOT_APPLICABLE


def test_process_removal_and_recreation_do_not_reuse_old_process_settings() -> None:
    parsed = _parse(
        "interface GigabitEthernet0/1",
        " ip address 10.0.0.1 255.255.255.0",
        "!",
        "router rip",
        " version 2",
        " network 10.0.0.0",
        "!",
        "no router rip",
        "router rip",
        " network 10.0.0.0",
        "!",
    )

    assert RipAuthenticationRule().evaluate(parsed).outcome is AssessmentOutcome.UNKNOWN


def test_passive_only_process_is_not_applicable_without_adjacency_claims() -> None:
    parsed = _parse(
        "interface GigabitEthernet0/1",
        " ip address 10.0.0.1 255.255.255.0",
        "!",
        "router rip",
        " version 2",
        " network 10.0.0.0",
        " passive-interface default",
        "!",
    )

    assert RipAuthenticationRule().evaluate(parsed).outcome is AssessmentOutcome.NOT_APPLICABLE


def test_interface_range_authentication_preserves_target_provenance() -> None:
    parsed = _parse(
        "key chain SYNTHETIC-RANGE-CHAIN",
        " key 1",
        "  key-string SYNTHETIC-RANGE-SECRET",
        "!",
        "interface GigabitEthernet1/0/1",
        " ip address 10.0.1.1 255.255.255.0",
        "!",
        "interface GigabitEthernet1/0/2",
        " ip address 10.0.2.1 255.255.255.0",
        "!",
        "interface range GigabitEthernet1/0/1 - 2",
        " ip authentication mode eigrp 100 md5",
        " ip authentication key-chain eigrp 100 SYNTHETIC-RANGE-CHAIN",
        "!",
        "router eigrp 100",
        " network 10.0.0.0 0.255.255.255",
        "!",
    )
    evaluation = EigrpAuthenticationRule().evaluate(parsed)

    assert evaluation.outcome is AssessmentOutcome.SECURE
    assert {item.target_interface for item in evaluation.evidence if item.target_interface} == {
        "GigabitEthernet1/0/1",
        "GigabitEthernet1/0/2",
    }
    assert any(item.resolution_origin == "range" for item in evaluation.evidence)


def test_relevant_template_and_port_channel_inheritance_prevent_false_secure() -> None:
    template = _parse(
        "template ROUTING-AUTH",
        " ip ospf authentication message-digest",
        "!",
        "interface GigabitEthernet0/1",
        " ip ospf 10 area 0",
        " source template ROUTING-AUTH",
        "!",
        "router ospf 10",
        "!",
    )
    port_channel = _parse(
        "interface GigabitEthernet0/1",
        " ip address 10.0.0.1 255.255.255.0",
        " channel-group 1 mode active",
        "!",
        "interface Port-channel1",
        " ip authentication mode eigrp 100 md5",
        "!",
        "router eigrp 100",
        " network 10.0.0.0 0.0.0.255",
        "!",
    )

    assert (
        OspfAuthenticationRule().evaluate(template).outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX
    )
    assert (
        EigrpAuthenticationRule().evaluate(port_channel).outcome
        is AssessmentOutcome.UNSUPPORTED_SYNTAX
    )


@pytest.mark.parametrize(
    ("scope_command", "rule"),
    [
        (" ip rip authentication mode sha256", RipAuthenticationRule()),
        (" ip ospf authentication sha256", OspfAuthenticationRule()),
        (" ip authentication mode eigrp 100 sha256", EigrpAuthenticationRule()),
    ],
)
def test_relevant_unsupported_syntax_never_becomes_secure_or_vulnerable(
    scope_command: str,
    rule: object,
) -> None:
    protocol_header = {
        "CG-ROUTE-001": "router ospf 10",
        "CG-ROUTE-002": "router eigrp 100",
        "CG-ROUTE-003": "router rip",
    }[rule.metadata.rule_id]  # type: ignore[attr-defined]
    parsed = _parse(
        "interface GigabitEthernet0/1",
        " ip address 10.0.0.1 255.255.255.0",
        scope_command,
        "!",
        protocol_header,
        " network 10.0.0.0 0.0.0.255" if "rip" not in protocol_header else " network 10.0.0.0",
        "!",
    )
    evaluation = rule.evaluate(parsed)  # type: ignore[attr-defined]

    assert parsed.status is ParseStatus.PARTIAL
    assert evaluation.outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX


def test_unrelated_unsupported_syntax_does_not_invalidate_routing_result() -> None:
    parsed = _parse(
        "key chain SYNTHETIC-RIP-CHAIN",
        " key 1",
        "  key-string SYNTHETIC-RIP-SECRET",
        "!",
        "interface GigabitEthernet0/1",
        " ip address 10.0.0.1 255.255.255.0",
        " ip rip authentication mode md5",
        " ip rip authentication key-chain SYNTHETIC-RIP-CHAIN",
        "!",
        "router rip",
        " version 2",
        " network 10.0.0.0",
        "!",
        "mystery unrelated syntax",
    )

    assert parsed.status is ParseStatus.PARTIAL
    assert RipAuthenticationRule().evaluate(parsed).outcome is AssessmentOutcome.SECURE


def test_incomplete_input_is_unknown_and_results_are_deterministic() -> None:
    parsed = _parse(
        "router ospf 10",
        " network 10.0.0.0 0.0.0.255 area 0",
        "banner motd ^",
        "unterminated synthetic banner",
    )
    first = OspfAuthenticationRule().evaluate(parsed)
    second = OspfAuthenticationRule().evaluate(parsed)

    assert parsed.status is ParseStatus.INCOMPLETE
    assert first == second
    assert first.outcome is AssessmentOutcome.UNKNOWN


def test_public_outputs_and_object_representations_redact_routing_secrets() -> None:
    chain = "SYNTHETIC-PRIVATE-CHAIN"
    secret = "SYNTHETIC-PRIVATE-ROUTING-SECRET"
    source = ConfigurationSource(
        "synthetic-private-routing.txt",
        _text(
            f"key chain {chain}",
            " key 1",
            f"  key-string {secret}",
            "!",
            "interface GigabitEthernet0/1",
            " ip address 10.0.0.1 255.255.255.0",
            " ip rip authentication mode md5",
            f" ip rip authentication key-chain {chain}",
            "!",
            "router rip",
            " version 2",
            " network 10.0.0.0",
            "!",
        ),
    )
    parser = CiscoConfigurationParser()
    parsed = parser.parse(source)
    analysis = default_analysis_engine().analyze(parsed)
    report = build_assessment_report(parser.identify(source), parsed, analysis)
    public = "\n".join(
        (render_terminal(report), render_json(report), render_html(report), repr(parsed))
    )

    assert len(analysis.findings) == 17
    assert chain not in public
    assert secret not in public
    assert "[REDACTED]" in public
    assert json.loads(render_json(report))["findings"][-1]["rule_id"] == "CG-ROUTE-003"


def test_resolver_reports_only_supported_process_targets() -> None:
    parsed = _parse("router ospfv3 10", "!", "router ospf 20", "!")
    resolution = resolve_routing_authentication(parsed, "ospf")

    assert len(resolution.processes) == 1
    assert not resolution.targets


def test_invalid_process_identifiers_and_ambiguous_ospf_areas_do_not_pass() -> None:
    invalid = _parse("router ospf NOT-A-NUMBER", "!")
    ambiguous = _parse(
        "interface GigabitEthernet0/1",
        " ip address 10.0.0.1 255.255.255.0",
        " ip ospf message-digest-key 1 md5 SYNTHETIC-OSPF-SECRET",
        "!",
        "router ospf 10",
        " area 0 authentication message-digest",
        " network 10.0.0.0 0.0.0.255 area 0",
        " network 10.0.0.0 0.0.0.255 area 1",
        "!",
    )

    assert (
        OspfAuthenticationRule().evaluate(invalid).outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX
    )
    assert OspfAuthenticationRule().evaluate(ambiguous).outcome is AssessmentOutcome.UNKNOWN


def test_referenced_key_lifetime_syntax_blocks_false_secure() -> None:
    parsed = _parse(
        "key chain SYNTHETIC-LIFETIME-CHAIN",
        " key 1",
        "  key-string SYNTHETIC-LIFETIME-SECRET",
        "  send-lifetime 00:00:00 Jan 1 2030 infinite",
        "!",
        "interface GigabitEthernet0/1",
        " ip address 10.0.0.1 255.255.255.0",
        " ip rip authentication mode md5",
        " ip rip authentication key-chain SYNTHETIC-LIFETIME-CHAIN",
        "!",
        "router rip",
        " version 2",
        " network 10.0.0.0",
        "!",
    )

    assert RipAuthenticationRule().evaluate(parsed).outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX


def test_abbreviated_passive_interface_matches_canonical_target() -> None:
    parsed = _parse(
        "interface GigabitEthernet0/1",
        " ip address 10.0.0.1 255.255.255.0",
        "!",
        "router rip",
        " version 2",
        " network 10.0.0.0",
        " passive-interface Gi0/1",
        "!",
    )

    assert RipAuthenticationRule().evaluate(parsed).outcome is AssessmentOutcome.NOT_APPLICABLE
