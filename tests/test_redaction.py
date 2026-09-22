"""Centralized evidence-redaction tests with synthetic credentials."""

from __future__ import annotations

from configguard.domain import EvidenceReference
from configguard.parsing import CiscoConfigurationParser, ConfigurationSource
from configguard.sanitization import (
    REDACTED,
    CiscoEvidenceSanitizer,
    EvidenceSanitizationError,
)


def test_supported_credential_commands_are_redacted_with_context() -> None:
    secrets = (
        "SYNTHETIC-LOCAL-HASH",
        "SYNTHETIC-COMMUNITY",
        "SYNTHETIC-AUTH-KEY",
        "SYNTHETIC-PRIV-KEY",
        "SYNTHETIC-OSPF-KEY",
    )
    source = ConfigurationSource(
        "secrets.txt",
        "\n".join(
            (
                "version 15.7",
                "hostname TEST",
                "username synthetic-user secret 9 SYNTHETIC-LOCAL-HASH",
                "snmp-server community SYNTHETIC-COMMUNITY RO 10",
                "snmp-server user synthetic-user GROUP v3 auth sha "
                "SYNTHETIC-AUTH-KEY priv aes 128 SYNTHETIC-PRIV-KEY access 10",
                "interface GigabitEthernet0/0",
                " ip ospf message-digest-key 1 md5 SYNTHETIC-OSPF-KEY",
                "end",
            )
        ),
    )
    parsed = CiscoConfigurationParser().parse(source)
    references = (
        EvidenceReference(
            observation_id="synthetic",
            source_command_ids=tuple(command.command_id for command in parsed.commands),
        ),
    )

    evidence = CiscoEvidenceSanitizer().sanitize(parsed, references)
    rendered = "\n".join(item.redacted_excerpt for item in evidence)

    assert REDACTED in rendered
    assert "priv aes 128 [REDACTED]" in rendered
    assert all(secret not in rendered for secret in secrets)
    assert all(item.location.line_start >= 1 for item in evidence)


def test_unclassified_commands_and_banner_content_fail_closed() -> None:
    secret = "SYNTHETIC-UNCLASSIFIED-SECRET"
    source = ConfigurationSource(
        "unknown.txt",
        "version 15.7\n"
        "hostname TEST\n"
        "interface Loopback0\n"
        f" unknown-vendor-key {secret}\n"
        "!\n"
        "banner motd ^C\n"
        f"{secret}\n"
        "^C\n"
        "end\n",
    )
    parsed = CiscoConfigurationParser().parse(source)
    hidden_ids = tuple(
        command.command_id
        for command in parsed.commands
        if not command.classified or command.name == "banner-content"
    )

    evidence = CiscoEvidenceSanitizer().sanitize(
        parsed,
        (EvidenceReference("synthetic", hidden_ids),),
    )

    assert evidence
    assert all(item.redacted_excerpt == REDACTED for item in evidence)
    assert secret not in repr(parsed)


def test_missing_evidence_reference_raises_secret_free_error() -> None:
    parsed = CiscoConfigurationParser().parse(
        ConfigurationSource("minimal.txt", "version 15.7\nhostname TEST\nline vty 0 4\nend\n")
    )

    try:
        CiscoEvidenceSanitizer().sanitize(
            parsed,
            (EvidenceReference("synthetic", ("missing-command",)),),
        )
    except EvidenceSanitizationError as error:
        assert str(error) == "Evidence could not be resolved safely."
    else:
        raise AssertionError("Expected safe evidence resolution failure")
