"""Context-aware redaction for Cisco IOS-style configuration evidence."""

from __future__ import annotations

import re
from collections.abc import Sequence

from configguard.domain import (
    CommandRecord,
    ConfigurationContext,
    ContextKind,
    EvidenceReference,
    ParsedConfiguration,
    SanitizedEvidence,
)

REDACTED = "[REDACTED]"
_URL_CREDENTIALS = re.compile(
    r"(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<credentials>[^/@\s:]+:[^/@\s]+)@",
    flags=re.IGNORECASE,
)
_GENERIC_SECRET = re.compile(
    r"\b(password|secret|key-string|authentication-key|pre-shared-key)\b",
    flags=re.IGNORECASE,
)


class EvidenceSanitizationError(ValueError):
    """Safe failure raised when an evidence reference cannot be resolved."""


class CiscoEvidenceSanitizer:
    """Resolve command references and redact every excerpt centrally."""

    def sanitize(
        self,
        configuration: ParsedConfiguration,
        references: Sequence[EvidenceReference],
    ) -> tuple[SanitizedEvidence, ...]:
        command_index = {command.command_id: command for command in configuration.commands}
        ordered: list[tuple[str, str | None, str | None]] = []
        for reference in references:
            for command_id in reference.source_command_ids:
                item = (
                    command_id,
                    reference.target_interface,
                    reference.resolution_origin,
                )
                if item not in ordered:
                    ordered.append(item)

        evidence: list[SanitizedEvidence] = []
        for command_id, target_interface, resolution_origin in ordered:
            command = command_index.get(command_id)
            if command is None:
                raise EvidenceSanitizationError(
                    "Evidence could not be resolved safely.",
                )
            evidence.append(
                SanitizedEvidence(
                    location=command.location,
                    context=_public_context(command.context),
                    redacted_excerpt=redact_command(command),
                    target_interface=target_interface,
                    resolution_origin=resolution_origin,
                )
            )
        return tuple(evidence)


def redact_command(command: CommandRecord) -> str:
    """Return a public excerpt or fail closed for an unclassified command."""

    if not command.classified or command.name in {"banner-content", "crypto-content"}:
        return REDACTED

    text = command.text.strip()
    if not text:
        return REDACTED

    text = _URL_CREDENTIALS.sub(
        lambda match: f"{match.group('scheme')}{REDACTED}:{REDACTED}@",
        text,
    )
    tokens = text.split()
    lowered = [token.lower() for token in tokens]

    if not tokens:
        return REDACTED
    if lowered[0] == "username":
        return _redact_username(tokens, lowered)
    if lowered[:2] == ["no", "username"]:
        return f"{tokens[0]} {tokens[1]} {REDACTED}"
    if lowered[:2] in (["enable", "password"], ["enable", "secret"]):
        return f"{tokens[0]} {tokens[1]} {REDACTED}"
    if lowered[:2] == ["snmp-server", "community"]:
        suffix = tokens[3:] if len(tokens) > 3 else []
        return " ".join([tokens[0], tokens[1], REDACTED, *suffix])
    if lowered[:3] == ["no", "snmp-server", "community"]:
        suffix = tokens[4:] if len(tokens) > 4 else []
        return " ".join([tokens[0], tokens[1], tokens[2], REDACTED, *suffix])
    if lowered[:2] == ["key", "chain"]:
        return f"{tokens[0]} {tokens[1]} {REDACTED}"
    if lowered[:3] == ["no", "key", "chain"]:
        return f"{tokens[0]} {tokens[1]} {tokens[2]} {REDACTED}"
    if lowered[:4] == ["ip", "rip", "authentication", "key-chain"]:
        return " ".join([*tokens[:4], REDACTED])
    if lowered[:4] == ["ip", "authentication", "key-chain", "eigrp"]:
        return " ".join([*tokens[:5], REDACTED])
    if lowered[:5] == ["no", "ip", "authentication", "key-chain", "eigrp"]:
        return " ".join(tokens[:6])
    if lowered[:2] == ["ip", "access-group"] and len(tokens) >= 4:
        return " ".join([tokens[0], tokens[1], REDACTED, tokens[-1]])
    if lowered[:3] == ["no", "ip", "access-group"] and len(tokens) >= 5:
        return " ".join([tokens[0], tokens[1], tokens[2], REDACTED, tokens[-1]])
    if lowered[:2] == ["ip", "access-list"] and len(tokens) >= 4:
        return " ".join([tokens[0], tokens[1], tokens[2], REDACTED])
    if lowered[:3] == ["no", "ip", "access-list"] and len(tokens) >= 5:
        return " ".join([tokens[0], tokens[1], tokens[2], tokens[3], REDACTED])
    if lowered[:2] == ["no", "access-list"] and len(tokens) >= 3:
        return " ".join([tokens[0], tokens[1], REDACTED])
    if lowered[:2] == ["ipv6", "access-list"] and len(tokens) >= 3:
        return " ".join([tokens[0], tokens[1], REDACTED])
    if lowered[0] == "access-list" and len(tokens) >= 3:
        return " ".join([tokens[0], REDACTED, *_redact_acl_tokens(tokens[2:])])
    if command.context.kind is ContextKind.ACL:
        return " ".join(_redact_acl_tokens(tokens))
    if lowered[:2] == ["snmp-server", "user"]:
        return _redact_snmp_user(tokens, lowered)
    if lowered[:2] == ["snmp-server", "host"]:
        return _redact_snmp_host(tokens, lowered)
    if lowered[0] == "banner":
        banner_type = tokens[1] if len(tokens) > 1 else ""
        return " ".join(part for part in (tokens[0], banner_type, REDACTED) if part)
    if lowered[0] in {"password", "secret", "key", "key-string"}:
        return f"{tokens[0]} {REDACTED}"
    if lowered[:2] in (["radius-server", "key"], ["tacacs-server", "key"]):
        return f"{tokens[0]} {tokens[1]} {REDACTED}"
    if lowered[:3] == ["ip", "ospf", "authentication-key"]:
        return f"{tokens[0]} {tokens[1]} {tokens[2]} {REDACTED}"
    if lowered[:3] == ["ip", "ospf", "message-digest-key"]:
        command_prefix = tokens[:5] if len(tokens) >= 5 else tokens[:3]
        return " ".join([*command_prefix, REDACTED])
    if lowered[:2] == ["crypto", "isakmp"] and "key" in lowered:
        return _redact_after_keyword(tokens, lowered, "key")
    if lowered[0] == "neighbor" and "password" in lowered:
        return _redact_after_keyword(tokens, lowered, "password")
    if "private-key" in lowered or ("certificate" in lowered and len(tokens) == 1):
        return REDACTED

    match = _GENERIC_SECRET.search(text)
    if match is not None:
        public_prefix = text[: match.end()].rstrip()
        return f"{public_prefix} {REDACTED}"
    return text


def _redact_username(tokens: list[str], lowered: list[str]) -> str:
    output = [tokens[0], REDACTED]
    if len(tokens) <= 2:
        return " ".join(output)

    credential_indexes = [
        lowered.index(keyword) for keyword in ("password", "secret") if keyword in lowered
    ]
    if not credential_indexes:
        return " ".join([*output, *tokens[2:]])

    credential_index = min(credential_indexes)
    output.extend(tokens[2 : credential_index + 1])
    if credential_index + 1 < len(tokens) and tokens[credential_index + 1].isdigit():
        output.append(tokens[credential_index + 1])
    output.append(REDACTED)
    return " ".join(output)


def _redact_snmp_user(tokens: list[str], lowered: list[str]) -> str:
    output = list(tokens)
    if len(output) > 2:
        output[2] = REDACTED
    for keyword in ("auth", "priv"):
        if keyword not in lowered:
            continue
        index = lowered.index(keyword)
        key_index = index + 2
        if keyword == "priv" and key_index < len(output) and output[key_index].isdigit():
            key_index += 1
        if key_index < len(output):
            output[key_index] = REDACTED
    return " ".join(output)


def _redact_snmp_host(tokens: list[str], lowered: list[str]) -> str:
    output = list(tokens)
    if "version" not in lowered:
        return f"{tokens[0]} {tokens[1]} {REDACTED}"
    version_index = lowered.index("version")
    credential_index = version_index + 2
    if credential_index < len(output):
        output[credential_index] = REDACTED
    return " ".join(output)


def _redact_after_keyword(
    tokens: list[str],
    lowered: list[str],
    keyword: str,
) -> str:
    index = lowered.index(keyword)
    return " ".join([*tokens[: index + 1], REDACTED])


def _public_context(context: ConfigurationContext) -> ConfigurationContext:
    if context.kind is ContextKind.ACL and context.identifier is not None:
        return ConfigurationContext(context.kind, REDACTED)
    if (
        context.kind is ContextKind.AAA
        and context.identifier is not None
        and context.identifier.lower().startswith("key chain ")
    ):
        return ConfigurationContext(context.kind, f"key chain {REDACTED}")
    return context


def _redact_acl_tokens(tokens: list[str]) -> list[str]:
    safe_keywords = {
        "any",
        "deny",
        "eq",
        "gt",
        "host",
        "icmp",
        "ip",
        "lt",
        "neq",
        "permit",
        "range",
        "tcp",
        "udp",
    }
    rendered: list[str] = []
    for index, token in enumerate(tokens):
        lowered = token.lower()
        if (token.isdigit() and index == 0 and len(tokens) > 1) or lowered in safe_keywords:
            rendered.append(token)
        else:
            rendered.append(REDACTED)
    return rendered
