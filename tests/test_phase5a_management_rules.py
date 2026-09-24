"""Focused regression tests for the Phase 5A management-plane rules."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from configguard.analysis import default_analysis_engine
from configguard.cli import ExitCode, main
from configguard.domain import AssessmentOutcome, ParseStatus, Severity
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource
from configguard.rules import (
    ManagementLineLoginAuthenticationRule,
    PlaintextCredentialStorageRule,
    VtySourceRestrictionRule,
)
from configguard.sanitization import CiscoEvidenceSanitizer

FIXTURES = Path(__file__).parent / "fixtures"


def _configuration(*commands: str) -> str:
    return "\n".join(
        (
            "version 17.9",
            "hostname SYNTHETIC",
            "interface Loopback0",
            " description SYNTHETIC",
            "!",
            *commands,
            "end",
            "",
        )
    )


def _parsed(text: str):  # type: ignore[no-untyped-def]
    return CiscoConfigurationParser().parse(ConfigurationSource("synthetic.txt", text))


def _evaluate(rule, text: str):  # type: ignore[no-untyped-def]
    return rule.evaluate(_parsed(text))


@pytest.mark.parametrize(
    "acl",
    (
        ("ip access-list standard MGMT", " permit 192.0.2.0 0.0.0.255"),
        ("access-list 10 permit 192.0.2.0 0.0.0.255",),
    ),
)
def test_vty_source_restriction_accepts_resolved_named_and_numbered_acls(
    acl: tuple[str, ...],
) -> None:
    result = _evaluate(
        VtySourceRestrictionRule(),
        _configuration(
            *acl,
            "line vty 0 15",
            " access-class MGMT in vrf-also" if len(acl) == 2 else " access-class 10 in",
        ),
    )

    assert result.outcome is AssessmentOutcome.SECURE


def test_vty_source_restriction_honors_overlap_order_and_broad_permit() -> None:
    text = _configuration(
        "ip access-list standard RESTRICTED",
        " permit 192.0.2.0 0.0.0.255",
        "ip access-list standard BROAD",
        " permit any",
        "line vty 0 15",
        " access-class RESTRICTED in",
        "line vty 5 10",
        " access-class BROAD in",
    )

    result = _evaluate(VtySourceRestrictionRule(), text)

    assert result.outcome is AssessmentOutcome.POTENTIAL_RISK
    assert result.severity is Severity.MEDIUM


def test_vty_source_acl_sequence_order_ignores_unreachable_broad_permit() -> None:
    text = _configuration(
        "ip access-list standard ORDERED",
        " 20 permit any",
        " 10 deny any log",
        "line vty 0 4",
        " access-class ORDERED in",
    )

    result = _evaluate(VtySourceRestrictionRule(), text)

    assert result.outcome is AssessmentOutcome.SECURE


def test_vty_source_restriction_preserves_absence_and_unresolved_as_unknown() -> None:
    outbound_only = _configuration("line vty 0 4", " access-class OUTBOUND out")
    unresolved = _configuration("line vty 0 4", " access-class MISSING in")

    assert _evaluate(VtySourceRestrictionRule(), outbound_only).outcome is AssessmentOutcome.UNKNOWN
    assert _evaluate(VtySourceRestrictionRule(), unresolved).outcome is AssessmentOutcome.UNKNOWN


def test_vty_source_restriction_handles_negation_and_referenced_unsupported_acl() -> None:
    removed = _configuration(
        "access-list 10 permit 192.0.2.0 0.0.0.255",
        "line vty 0 4",
        " access-class 10 in",
        " no access-class 10 in",
    )
    unsupported = _configuration(
        "ip access-list standard MGMT",
        " object-group SYNTHETIC",
        "line vty 0 4",
        " access-class MGMT in",
    )

    assert (
        _evaluate(VtySourceRestrictionRule(), removed).outcome is AssessmentOutcome.POTENTIAL_RISK
    )
    assert (
        _evaluate(VtySourceRestrictionRule(), unsupported).outcome
        is AssessmentOutcome.UNSUPPORTED_SYNTAX
    )


@pytest.mark.parametrize(
    "credential",
    (
        "username SYNTHETIC-USER password 0 SYNTHETIC-PLAINTEXT",
        "username SYNTHETIC-USER secret 0 SYNTHETIC-PLAINTEXT",
        "enable password 0 SYNTHETIC-PLAINTEXT",
        "enable secret 0 SYNTHETIC-PLAINTEXT",
        "line console 0\n password 0 SYNTHETIC-PLAINTEXT",
        "line aux 0\n password 0 SYNTHETIC-PLAINTEXT",
    ),
)
def test_plaintext_storage_detects_each_supported_explicit_type_zero(
    credential: str,
) -> None:
    result = _evaluate(PlaintextCredentialStorageRule(), _configuration(credential))

    assert result.outcome is AssessmentOutcome.CONFIRMED_INSECURE
    assert result.severity is Severity.HIGH


def test_plaintext_storage_distinguishes_hashes_untyped_and_negated_values() -> None:
    protected = _configuration(
        "username SYNTHETIC-USER secret 9 SYNTHETIC-HASH",
        "enable password 7 SYNTHETIC-ENCODED",
        "line console 0",
        " password 7 SYNTHETIC-ENCODED",
    )
    untyped = _configuration("enable password SYNTHETIC-UNTYPED")
    removed = _configuration(
        "enable password 0 SYNTHETIC-REMOVED",
        "no enable password",
    )

    assert (
        _evaluate(PlaintextCredentialStorageRule(), protected).outcome
        is AssessmentOutcome.NOT_APPLICABLE
    )
    assert _evaluate(PlaintextCredentialStorageRule(), untyped).outcome is AssessmentOutcome.UNKNOWN
    assert (
        _evaluate(PlaintextCredentialStorageRule(), removed).outcome
        is AssessmentOutcome.NOT_APPLICABLE
    )


def test_relevant_unsupported_credential_and_login_syntax_never_passes() -> None:
    unsupported_password = _configuration("line console 0", " password")
    unsupported_login = _configuration("line vty 0 4", " login authentication")
    supported_then_malformed = _configuration(
        "line console 0",
        " password 7 SYNTHETIC-ENCODED",
        " password",
        " login",
    )

    assert (
        _evaluate(PlaintextCredentialStorageRule(), unsupported_password).outcome
        is AssessmentOutcome.UNSUPPORTED_SYNTAX
    )
    assert (
        _evaluate(ManagementLineLoginAuthenticationRule(), unsupported_login).outcome
        is AssessmentOutcome.UNSUPPORTED_SYNTAX
    )
    assert (
        _evaluate(ManagementLineLoginAuthenticationRule(), supported_then_malformed).outcome
        is AssessmentOutcome.UNSUPPORTED_SYNTAX
    )


def test_plaintext_evidence_redacts_principal_and_value_everywhere() -> None:
    principal = "SYNTHETIC-PRIVATE-PRINCIPAL"
    credential = "SYNTHETIC-PRIVATE-CREDENTIAL"
    parsed = _parsed(_configuration(f"username {principal} password 0 {credential}"))
    evaluation = PlaintextCredentialStorageRule().evaluate(parsed)
    evidence = CiscoEvidenceSanitizer().sanitize(parsed, evaluation.evidence)
    public = json.dumps(default_analysis_engine().analyze(parsed).to_public_dict())

    assert principal not in repr(parsed)
    assert credential not in repr(parsed)
    assert principal not in repr(evidence)
    assert credential not in repr(evidence)
    assert principal not in public
    assert credential not in public


def test_plaintext_finding_is_redacted_in_cli_json_and_html(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    principal = "SYNTHETIC-CLI-PRIVATE-PRINCIPAL"
    credential = "SYNTHETIC-CLI-PRIVATE-CREDENTIAL"
    source = tmp_path / "synthetic.txt"
    report_path = tmp_path / "report.html"
    source.write_text(
        _configuration(
            f"username {principal} password 0 {credential}",
            "no ip http server",
            "ip ssh version 2",
            "access-list 10 permit 192.0.2.0 0.0.0.255",
            "line vty 0 4",
            " transport input ssh",
            " access-class 10 in",
            " login local",
        ),
        encoding="utf-8",
    )

    assert main(["scan", str(source)]) is ExitCode.COMPLETED
    terminal = capsys.readouterr().out
    assert main(["scan", str(source), "--format", "json"]) is ExitCode.COMPLETED
    json_output = capsys.readouterr().out
    assert main(["scan", str(source), "--report", str(report_path)]) is ExitCode.COMPLETED
    capsys.readouterr()
    html = report_path.read_text(encoding="utf-8")

    for rendered in (terminal, json_output, html):
        assert principal not in rendered
        assert credential not in rendered
        assert "[REDACTED]" in rendered


def test_management_login_resolves_local_vty_and_console_independently() -> None:
    text = _configuration(
        "username SYNTHETIC-USER secret 9 SYNTHETIC-HASH",
        "line console 0",
        " login local",
        "line vty 0 4",
        " login local",
    )

    result = _evaluate(ManagementLineLoginAuthenticationRule(), text)

    assert result.outcome is AssessmentOutcome.SECURE


def test_management_login_resolves_explicit_line_password_without_aaa() -> None:
    text = _configuration(
        "line console 0",
        " password 7 SYNTHETIC-ENCODED",
        " login",
    )

    result = _evaluate(ManagementLineLoginAuthenticationRule(), text)

    assert result.outcome is AssessmentOutcome.SECURE


def test_management_login_detects_disabled_vty_after_overlapping_override() -> None:
    text = _configuration(
        "username SYNTHETIC-USER secret 9 SYNTHETIC-HASH",
        "line vty 0 15",
        " login local",
        "line vty 5 10",
        " no login",
    )

    result = _evaluate(ManagementLineLoginAuthenticationRule(), text)

    assert result.outcome is AssessmentOutcome.CONFIRMED_INSECURE
    assert result.severity is Severity.HIGH


def test_management_login_keeps_unresolved_aaa_and_missing_local_user_unknown() -> None:
    missing_list = _configuration(
        "aaa new-model",
        "line vty 0 4",
        " login authentication MISSING",
    )
    missing_local = _configuration("line console 0", " login local")

    assert (
        _evaluate(ManagementLineLoginAuthenticationRule(), missing_list).outcome
        is AssessmentOutcome.UNKNOWN
    )
    assert (
        _evaluate(ManagementLineLoginAuthenticationRule(), missing_local).outcome
        is AssessmentOutcome.UNKNOWN
    )


def test_management_login_classifies_aaa_none_and_fallback_conservatively() -> None:
    only_none = _configuration(
        "aaa new-model",
        "aaa authentication login OPEN none",
        "line console 0",
        " login authentication OPEN",
    )
    fallback = _configuration(
        "aaa new-model",
        "aaa authentication login FALLBACK local none",
        "username SYNTHETIC-USER secret 9 SYNTHETIC-HASH",
        "line vty 0 4",
        " login authentication FALLBACK",
    )

    assert (
        _evaluate(ManagementLineLoginAuthenticationRule(), only_none).outcome
        is AssessmentOutcome.CONFIRMED_INSECURE
    )
    assert (
        _evaluate(ManagementLineLoginAuthenticationRule(), fallback).outcome
        is AssessmentOutcome.POTENTIAL_RISK
    )


def test_incomplete_input_keeps_all_phase5a_rules_unknown() -> None:
    text = _configuration(
        "line vty 0 4",
        " access-class MISSING in",
        " login local",
        "banner motd ^C",
        "SYNTHETIC-TRUNCATED",
    ).removesuffix("end\n")
    parsed = _parsed(text)

    assert parsed.status is ParseStatus.INCOMPLETE
    for rule in (
        VtySourceRestrictionRule(),
        PlaintextCredentialStorageRule(),
        ManagementLineLoginAuthenticationRule(),
    ):
        assert rule.evaluate(parsed).outcome is AssessmentOutcome.UNKNOWN


def test_switch_fixture_keeps_unrelated_layer_two_syntax_out_of_management_rules() -> None:
    text = (FIXTURES / "synthetic_ios_xe_management_switch.txt").read_text(encoding="utf-8")
    parsed = _parsed(text)
    result = default_analysis_engine().analyze(parsed)
    findings = {item.rule_id: item for item in result.findings}
    public = json.dumps(result.to_public_dict())

    assert parsed.status is ParseStatus.PARTIAL
    assert any(item.kind == "vlan.declaration" for item in parsed.observations)
    assert any(item.kind == "interface.switchport_mode" for item in parsed.observations)
    assert len(result.findings) == 14
    assert findings["CG-MGMT-001"].outcome is AssessmentOutcome.SECURE
    assert findings["CG-MGMT-006"].outcome is AssessmentOutcome.SECURE
    assert findings["CG-MGMT-002"].outcome is AssessmentOutcome.SECURE
    assert findings["CG-SNMP-001"].outcome is AssessmentOutcome.POTENTIAL_RISK
    assert findings["CG-SNMP-002"].outcome is AssessmentOutcome.SECURE
    assert findings["CG-MGMT-003"].outcome is AssessmentOutcome.SECURE
    assert findings["CG-MGMT-004"].outcome is AssessmentOutcome.SECURE
    assert findings["CG-MGMT-005"].outcome is AssessmentOutcome.NOT_APPLICABLE
    assert all(item.severity is not Severity.CRITICAL for item in result.findings)
    assert "SYNTHETIC-COMMUNITY" not in public
    assert "SYNTHETIC-ADMIN" not in public
    assert "SYNTHETIC-HASH" not in public
