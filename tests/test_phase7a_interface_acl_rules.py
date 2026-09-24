"""Focused synthetic regressions for Phase 7A interface IPv4 ACL checks."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from configguard.analysis import default_analysis_engine
from configguard.cli import ExitCode, main
from configguard.domain import AssessmentOutcome, EvidenceReference, ParseStatus, Severity
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource
from configguard.reporting import build_assessment_report, render_html, render_json, render_terminal
from configguard.rules import (
    BroadInterfaceAclPermissionRule,
    InterfaceAclReferenceIntegrityRule,
)
from configguard.sanitization import CiscoEvidenceSanitizer


def _text(*commands: str) -> str:
    return "\n".join(
        (
            "version 17.9",
            "platform punt-keepalive disable-kernel-core",
            "hostname SYNTHETIC-PHASE7A",
            *commands,
            "end",
            "",
        )
    )


def _parse(*commands: str):  # type: ignore[no-untyped-def]
    return CiscoConfigurationParser().parse(
        ConfigurationSource("synthetic-phase7a.txt", _text(*commands))
    )


def _evaluate(*commands: str):  # type: ignore[no-untyped-def]
    parsed = _parse(*commands)
    return (
        BroadInterfaceAclPermissionRule().evaluate(parsed),
        InterfaceAclReferenceIntegrityRule().evaluate(parsed),
    )


def test_named_standard_acl_honors_order_and_reports_only_reachable_broad_permit() -> None:
    broad, integrity = _evaluate(
        "ip access-list standard EDGE-IN",
        " deny host 192.0.2.10",
        " permit any",
        "!",
        "interface GigabitEthernet0/1",
        " ip access-group EDGE-IN in",
        "!",
    )
    blocked, _ = _evaluate(
        "ip access-list standard EDGE-IN",
        " deny any",
        " permit any",
        "!",
        "interface GigabitEthernet0/1",
        " ip access-group EDGE-IN in",
        "!",
    )

    assert broad.outcome is AssessmentOutcome.POTENTIAL_RISK
    assert broad.severity is Severity.MEDIUM
    assert integrity.outcome is AssessmentOutcome.SECURE
    assert blocked.outcome is AssessmentOutcome.SECURE


def test_named_extended_sequence_order_and_protocol_breadth_are_conservative() -> None:
    blocked, integrity = _evaluate(
        "ip access-list extended EDGE-IN",
        " 20 permit tcp any any eq 443",
        " 10 deny tcp any any",
        "!",
        "interface GigabitEthernet0/1",
        " ip access-group EDGE-IN in",
        "!",
    )
    protocol_wide, _ = _evaluate(
        "ip access-list extended EDGE-OUT",
        " permit udp any any eq domain",
        "!",
        "interface GigabitEthernet0/1",
        " ip access-group EDGE-OUT out",
        "!",
    )

    assert blocked.outcome is AssessmentOutcome.SECURE
    assert integrity.outcome is AssessmentOutcome.SECURE
    assert protocol_wide.outcome is AssessmentOutcome.HARDENING
    assert protocol_wide.severity is Severity.LOW


@pytest.mark.parametrize(
    ("entries", "name", "direction", "expected"),
    [
        (("access-list 10 permit 192.0.2.0 0.0.0.255",), "10", "in", AssessmentOutcome.SECURE),
        (("access-list 110 permit ip any any",), "110", "in", AssessmentOutcome.POTENTIAL_RISK),
        (("access-list 110 permit tcp any any eq 22",), "110", "out", AssessmentOutcome.HARDENING),
    ],
)
def test_numbered_standard_and_extended_acl_subset(
    entries: tuple[str, ...],
    name: str,
    direction: str,
    expected: AssessmentOutcome,
) -> None:
    broad, integrity = _evaluate(
        *entries,
        "interface GigabitEthernet0/1",
        f" ip access-group {name} {direction}",
        "!",
    )

    assert broad.outcome is expected
    assert integrity.outcome is AssessmentOutcome.SECURE


def test_acl_entry_and_policy_deletions_follow_source_order() -> None:
    after_entry_removal, integrity = _evaluate(
        "ip access-list standard EDGE-IN",
        " 10 deny any",
        " 20 permit any",
        " no 10",
        "!",
        "interface GigabitEthernet0/1",
        " ip access-group EDGE-IN in",
        "!",
    )
    after_policy_removal, removed_integrity = _evaluate(
        "access-list 10 permit any",
        "no access-list 10",
        "interface GigabitEthernet0/1",
        " ip access-group 10 in",
        "!",
    )

    assert after_entry_removal.outcome is AssessmentOutcome.POTENTIAL_RISK
    assert integrity.outcome is AssessmentOutcome.SECURE
    assert after_policy_removal.outcome is AssessmentOutcome.UNKNOWN
    assert removed_integrity.outcome is AssessmentOutcome.UNKNOWN


def test_unused_management_only_and_ipv6_acls_do_not_create_interface_findings() -> None:
    configurations = (
        (
            "ip access-list standard UNUSED",
            " permit any",
            "!",
        ),
        (
            "ip access-list standard MANAGEMENT",
            " permit any",
            "!",
            "line vty 0 4",
            " access-class MANAGEMENT in",
            "!",
            "snmp-server community SYNTHETIC-COMMUNITY RO MANAGEMENT",
        ),
        (
            "ipv6 access-list IPV6-ONLY",
            " permit ipv6 any any",
            "!",
            "interface GigabitEthernet0/1",
            " ipv6 traffic-filter IPV6-ONLY in",
            "!",
        ),
    )

    for commands in configurations:
        broad, integrity = _evaluate(*commands)
        assert broad.outcome is AssessmentOutcome.NOT_APPLICABLE
        assert integrity.outcome is AssessmentOutcome.NOT_APPLICABLE


@pytest.mark.parametrize(
    ("policy", "expected"),
    [
        ((), AssessmentOutcome.UNKNOWN),
        (("ip access-list extended EDGE", "!"), AssessmentOutcome.UNKNOWN),
        (
            ("ip access-list extended EDGE", " permit tcp object-group SOURCES any", "!"),
            AssessmentOutcome.UNSUPPORTED_SYNTAX,
        ),
        (("access-list EDGE",), AssessmentOutcome.UNSUPPORTED_SYNTAX),
        (("ip access-list extended EDGE extra",), AssessmentOutcome.UNSUPPORTED_SYNTAX),
    ],
)
def test_missing_empty_and_advanced_referenced_acls_preserve_uncertainty(
    policy: tuple[str, ...],
    expected: AssessmentOutcome,
) -> None:
    broad, integrity = _evaluate(
        *policy,
        "interface GigabitEthernet0/1",
        " ip access-group EDGE in",
        "!",
    )

    assert broad.outcome is expected
    assert integrity.outcome is expected
    assert broad.severity is None
    assert integrity.severity is None


def test_unrelated_unsupported_acl_does_not_invalidate_supported_attachment() -> None:
    broad, integrity = _evaluate(
        "ip access-list standard ATTACHED",
        " permit host 192.0.2.10",
        "!",
        "ip access-list extended UNUSED",
        " permit tcp object-group PRIVATE any time-range PRIVATE",
        "!",
        "interface GigabitEthernet0/1",
        " ip access-group ATTACHED in",
        "!",
    )

    assert broad.outcome is AssessmentOutcome.SECURE
    assert integrity.outcome is AssessmentOutcome.SECURE


def test_repeated_and_negated_attachments_resolve_by_interface_and_direction() -> None:
    replaced, replaced_integrity = _evaluate(
        "ip access-list standard BROAD",
        " permit any",
        "!",
        "ip access-list standard NARROW",
        " permit host 192.0.2.10",
        "!",
        "interface GigabitEthernet0/1",
        " ip access-group BROAD in",
        " no ip access-group BROAD in",
        " ip access-group NARROW in",
        "!",
    )
    conflicting, conflicting_integrity = _evaluate(
        "ip access-list standard NARROW",
        " permit host 192.0.2.10",
        "!",
        "interface GigabitEthernet0/1",
        " ip access-group NARROW in",
        " no ip access-group OTHER in",
        "!",
    )

    assert replaced.outcome is AssessmentOutcome.SECURE
    assert replaced_integrity.outcome is AssessmentOutcome.SECURE
    assert conflicting.outcome is AssessmentOutcome.UNKNOWN
    assert conflicting_integrity.outcome is AssessmentOutcome.UNKNOWN


def test_interface_range_preserves_concrete_targets_and_source_provenance() -> None:
    parsed = _parse(
        "ip access-list extended EDGE-IN",
        " permit ip any any",
        "!",
        "interface range GigabitEthernet0/1 - 2",
        " ip access-group EDGE-IN in",
        "!",
    )
    finding = {item.rule_id: item for item in default_analysis_engine().analyze(parsed).findings}[
        "CG-ACL-001"
    ]

    assert finding.outcome is AssessmentOutcome.POTENTIAL_RISK
    assert {item.target_interface for item in finding.evidence if item.target_interface} == {
        "GigabitEthernet0/1",
        "GigabitEthernet0/2",
    }
    assert {item.resolution_origin for item in finding.evidence if item.resolution_origin} == {
        "range"
    }
    assert {item.line_start for item in finding.source_locations} == {5, 7, 8}


def test_unexpandable_range_with_acl_attachment_is_not_treated_as_absent() -> None:
    parsed = _parse(
        "access-list 10 permit any",
        "interface range GigabitEthernet0/1 - FastEthernet0/2",
        " ip access-group 10 in",
        "!",
    )

    assert parsed.status is ParseStatus.PARTIAL
    assert (
        BroadInterfaceAclPermissionRule().evaluate(parsed).outcome
        is AssessmentOutcome.UNSUPPORTED_SYNTAX
    )
    assert (
        InterfaceAclReferenceIntegrityRule().evaluate(parsed).outcome
        is AssessmentOutcome.UNSUPPORTED_SYNTAX
    )


def test_templates_and_port_channels_create_only_relevant_scoped_uncertainty() -> None:
    present_irrelevant = _evaluate(
        "template NO-ACL",
        " switchport mode access",
        "!",
        "interface GigabitEthernet0/1",
        " source template NO-ACL",
        "!",
    )
    applied_acl = _evaluate(
        "template EDGE",
        " ip access-group EDGE-IN in",
        "!",
        "interface GigabitEthernet0/1",
        " source template EDGE",
        "!",
    )
    missing_template = _evaluate(
        "interface GigabitEthernet0/1",
        " source template MISSING",
        "!",
    )
    relevant_channel = _evaluate(
        "ip access-list standard EDGE-IN",
        " permit host 192.0.2.10",
        "!",
        "interface GigabitEthernet0/1",
        " channel-group 1 mode active",
        " ip access-group EDGE-IN in",
        "!",
        "interface Port-channel1",
        "!",
    )

    assert all(item.outcome is AssessmentOutcome.NOT_APPLICABLE for item in present_irrelevant)
    assert all(item.outcome is AssessmentOutcome.UNKNOWN for item in applied_acl)
    assert all(item.outcome is AssessmentOutcome.UNKNOWN for item in missing_template)
    assert all(item.outcome is AssessmentOutcome.UNKNOWN for item in relevant_channel)


def test_malformed_attachment_is_scoped_unsupported_and_incomplete_input_is_unknown() -> None:
    malformed = _evaluate(
        "interface GigabitEthernet0/1",
        " ip access-group EDGE sideways",
        "!",
    )
    incomplete_text = _text(
        "access-list 10 permit any",
        "interface GigabitEthernet0/1",
        " ip access-group 10 in",
        "!",
        "banner motd ^C",
        "SYNTHETIC-UNTERMINATED",
    ).removesuffix("end\n")
    incomplete = CiscoConfigurationParser().parse(
        ConfigurationSource("synthetic-incomplete.txt", incomplete_text)
    )

    assert all(item.outcome is AssessmentOutcome.UNSUPPORTED_SYNTAX for item in malformed)
    assert incomplete.status is ParseStatus.INCOMPLETE
    assert (
        BroadInterfaceAclPermissionRule().evaluate(incomplete).outcome is AssessmentOutcome.UNKNOWN
    )
    assert (
        InterfaceAclReferenceIntegrityRule().evaluate(incomplete).outcome
        is AssessmentOutcome.UNKNOWN
    )


def test_reports_are_deterministic_and_redact_acl_identifiers_addresses_and_credentials() -> None:
    acl_name = "SYNTHETIC-PRIVATE-ACL"
    address = "198.51.100.77"
    credential = "SYNTHETIC-PRIVATE-CREDENTIAL"
    parser = CiscoConfigurationParser()
    source = ConfigurationSource(
        "synthetic-phase7a.txt",
        _text(
            f"username SYNTHETIC-USER secret 9 {credential}",
            f"ip access-list extended {acl_name}",
            f" deny ip host {address} any",
            " permit ip any any",
            "!",
            "interface GigabitEthernet0/1",
            f" ip access-group {acl_name} in",
            "!",
        ),
    )
    parsed = parser.parse(source)
    analysis = default_analysis_engine().analyze(parsed)
    report = build_assessment_report(parser.identify(source), parsed, analysis)
    outputs = (render_terminal(report), render_json(report), render_html(report))
    all_references = (
        EvidenceReference(
            "synthetic-all",
            tuple(command.command_id for command in parsed.commands),
        ),
    )
    direct_evidence = "\n".join(
        item.redacted_excerpt for item in CiscoEvidenceSanitizer().sanitize(parsed, all_references)
    )

    assert len(analysis.findings) == 14
    assert json.loads(outputs[1])["evaluated_rule_ids"][-2:] == ["CG-ACL-001", "CG-ACL-002"]
    assert outputs[1] == render_json(report)
    for rendered in (*outputs, direct_evidence, repr(parsed)):
        assert acl_name not in rendered
        assert address not in rendered
        assert credential not in rendered
    assert "[REDACTED]" in direct_evidence


def test_cli_json_and_html_include_both_acl_rules_without_sensitive_policy_data(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    acl_name = "SYNTHETIC-CLI-PRIVATE-ACL"
    address = "203.0.113.88"
    source_path = tmp_path / "synthetic-phase7a.txt"
    html_path = tmp_path / "synthetic-phase7a.html"
    source_path.write_text(
        _text(
            f"ip access-list standard {acl_name}",
            f" permit host {address}",
            "!",
            "interface GigabitEthernet0/1",
            f" ip access-group {acl_name} in",
            "!",
        ),
        encoding="utf-8",
    )

    assert main(["scan", str(source_path), "--format", "json"]) is ExitCode.PARTIAL_ASSESSMENT
    json_output = capsys.readouterr().out
    assert (
        main(["scan", str(source_path), "--report", str(html_path)]) is ExitCode.PARTIAL_ASSESSMENT
    )
    terminal_output = capsys.readouterr().out
    html_output = html_path.read_text(encoding="utf-8")
    payload = json.loads(json_output)

    assert len(payload["findings"]) == 14
    assert payload["evaluated_rule_ids"][-2:] == ["CG-ACL-001", "CG-ACL-002"]
    for rendered in (json_output, terminal_output, html_output):
        assert "CG-ACL-001" in rendered
        assert "CG-ACL-002" in rendered
        assert acl_name not in rendered
        assert address not in rendered
