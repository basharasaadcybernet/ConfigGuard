"""Deterministic, context-aware Cisco IOS / IOS XE configuration parser."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from configguard.domain import (
    CommandRecord,
    ConfigurationContext,
    ContextKind,
    DiagnosticKind,
    ObservationValue,
    ParsedConfiguration,
    ParseMetrics,
    ParserDiagnostic,
    ParseStatus,
    PlatformFamily,
    SourceLocation,
    StructuredObservation,
    UnsupportedSyntax,
)
from configguard.parsing.contracts import ConfigurationSource, ParserSupport
from configguard.parsing.errors import (
    MalformedConfigurationError,
    UnsupportedPlatformError,
)
from configguard.parsing.ingestion import DEFAULT_MAX_BYTES

_GLOBAL_CONTEXT = ConfigurationContext(ContextKind.GLOBAL)
_VERSION_PATTERN = re.compile(r"^version\s+(?P<major>\d+)(?:\.(?P<minor>\d+))?", re.I)
_IOS_STYLE_MARKERS = (
    "hostname ",
    "interface ",
    "line vty",
    "line console",
    "ip access-list ",
    "access-list ",
    "router ",
    "snmp-server ",
    "aaa new-model",
)
_IOS_XE_MARKERS = (
    "platform punt-keepalive",
    "platform software ",
    "license boot level network-",
    "switch 1 provision c9",
)
_UNSUPPORTED_SIGNATURES = (
    ("junos", ("set system ", "set interfaces ", "system {", "interfaces {")),
    ("fortios", ("config system global", "config system interface")),
    ("routeros", ("/interface ", "/ip address ", "/system identity")),
    ("cisco asa", ("asa version ", "names\n", "same-security-traffic ")),
    ("cisco ios xr", ("!! ios xr configuration", "router static\n address-family")),
    ("cisco nx-os", ("boot nxos", "feature nxapi", "feature vpc")),
)

type ObservationSpec = tuple[str, dict[str, ObservationValue]]


@dataclass(slots=True)
class _SpecialBlock:
    kind: str
    context: ConfigurationContext
    opener_line: int
    delimiter: str | None = None


@dataclass(slots=True)
class _ParseState:
    commands: list[CommandRecord] = field(default_factory=list)
    observations: list[StructuredObservation] = field(default_factory=list)
    unsupported: list[UnsupportedSyntax] = field(default_factory=list)
    diagnostics: list[ParserDiagnostic] = field(default_factory=list)
    acl_entry_counts: dict[str, int] = field(default_factory=dict)
    snmp_community_ids: dict[str, str] = field(default_factory=dict, repr=False)
    local_user_ids: dict[str, str] = field(default_factory=dict, repr=False)

    def add_observation(
        self,
        kind: str,
        attributes: dict[str, ObservationValue],
        command_id: str,
    ) -> None:
        self.observations.append(
            StructuredObservation.create(
                observation_id=f"obs-{len(self.observations) + 1:06d}",
                kind=kind,
                attributes=attributes,
                source_command_ids=(command_id,),
            )
        )


class CiscoConfigurationParser:
    """Parse supported Cisco IOS-style text without file or network I/O."""

    name = "cisco-ios-style"
    version = "1"

    def __init__(self, max_source_bytes: int = DEFAULT_MAX_BYTES) -> None:
        if max_source_bytes < 1:
            raise ValueError("max_source_bytes must be positive")
        self._max_source_bytes = max_source_bytes

    def identify(self, source: ConfigurationSource) -> ParserSupport:
        """Conservatively identify supported, candidate, and unsupported syntax."""

        lowered = source.text.lower().replace("\r\n", "\n")
        stripped_lines = tuple(
            line.strip() for line in lowered.splitlines() if line.strip() and line.strip() != "!"
        )
        joined = "\n".join(stripped_lines)

        for family, signatures in _UNSUPPORTED_SIGNATURES:
            if any(signature in joined for signature in signatures):
                return ParserSupport(
                    platform=PlatformFamily.UNSUPPORTED,
                    confidence=0.99,
                    reason=f"Detected a clearly unsupported {family} configuration style.",
                    compatible=False,
                )

        marker_count = sum(
            any(line.startswith(marker) for line in stripped_lines) for marker in _IOS_STYLE_MARKERS
        )
        xe_specific = any(marker in joined for marker in _IOS_XE_MARKERS)
        version_major = _declared_version_major(stripped_lines)

        if marker_count >= 2 and (xe_specific or version_major in {16, 17}):
            return ParserSupport(
                platform=PlatformFamily.CISCO_IOS_XE,
                confidence=0.9 if xe_specific else 0.75,
                reason="The source has compatible IOS XE-style syntax and version markers.",
                compatible=True,
            )
        if marker_count >= 2 and version_major is not None and version_major <= 15:
            return ParserSupport(
                platform=PlatformFamily.CISCO_IOS,
                confidence=0.8,
                reason="The source has compatible classic IOS-style syntax and version markers.",
                compatible=True,
            )
        if marker_count >= 2:
            return ParserSupport(
                platform=PlatformFamily.UNKNOWN,
                confidence=0.6,
                reason=(
                    "The source is compatible with supported Cisco IOS-style syntax, "
                    "but the exact IOS family is unknown."
                ),
                compatible=True,
            )
        return ParserSupport(
            platform=PlatformFamily.UNKNOWN,
            confidence=0.0,
            reason="The source does not contain enough supported Cisco IOS-style structure.",
            compatible=False,
        )

    def parse(self, source: ConfigurationSource) -> ParsedConfiguration:
        """Build a parser-neutral representation with safe diagnostics."""

        self._validate_source(source)
        support = self.identify(source)
        if support.platform is PlatformFamily.UNSUPPORTED or not support.compatible:
            raise UnsupportedPlatformError(
                "The configuration syntax is unsupported or could not be identified safely."
            )

        lines = source.text.splitlines()
        state = _ParseState()
        current_context = _GLOBAL_CONTEXT
        current_parent: ConfigurationContext | None = None
        special_block: _SpecialBlock | None = None
        incomplete = False

        if support.platform is PlatformFamily.UNKNOWN:
            state.diagnostics.append(
                ParserDiagnostic(
                    kind=DiagnosticKind.UNKNOWN_PLATFORM,
                    code="CG-PARSE-UNKNOWN-PLATFORM",
                    message=(
                        "Compatible Cisco IOS-style syntax was parsed, but the exact platform "
                        "family could not be established."
                    ),
                )
            )

        for line_number, raw_line in enumerate(lines, start=1):
            stripped = raw_line.strip()
            if special_block is not None:
                closed = self._record_special_block_line(
                    state,
                    special_block,
                    raw_line,
                    stripped,
                    line_number,
                )
                if closed:
                    special_block = None
                    current_context = _GLOBAL_CONTEXT
                    current_parent = None
                continue

            if not stripped or stripped.startswith("!"):
                if stripped.startswith("!"):
                    current_context = _GLOBAL_CONTEXT
                    current_parent = None
                continue
            if _is_export_preamble(stripped):
                continue

            indentation = len(raw_line) - len(raw_line.lstrip())
            header = _section_header(stripped) if indentation == 0 else None
            if header is not None:
                context, name, arguments, observation = header
                command_id = _command_id(line_number)
                state.commands.append(
                    CommandRecord(
                        command_id=command_id,
                        text=raw_line,
                        location=SourceLocation(line_number, line_number),
                        context=context,
                        name=name,
                        arguments=arguments,
                        parent_context=_GLOBAL_CONTEXT,
                    )
                )
                if observation is not None:
                    state.add_observation(observation[0], observation[1], command_id)
                current_context = context
                current_parent = _GLOBAL_CONTEXT

                if context.kind is ContextKind.CRYPTO:
                    special_block = _SpecialBlock("crypto", context, line_number)
                elif name == "banner":
                    delimiter = _banner_delimiter(stripped)
                    if delimiter is None:
                        incomplete = True
                        state.diagnostics.append(
                            _diagnostic(
                                DiagnosticKind.MALFORMED_CONFIGURATION,
                                "CG-PARSE-MALFORMED-BANNER",
                                "A banner declaration has no usable delimiter.",
                                line_number,
                                command_id,
                            )
                        )
                    elif stripped.count(delimiter) < 2:
                        special_block = _SpecialBlock(
                            "banner",
                            context,
                            line_number,
                            delimiter,
                        )
                continue

            lowered = stripped.lower()
            if lowered == "end":
                self._record_control(state, raw_line, line_number, _GLOBAL_CONTEXT, "end")
                current_context = _GLOBAL_CONTEXT
                current_parent = None
                continue
            if lowered == "exit":
                self._record_control(state, raw_line, line_number, current_context, "exit")
                current_context = _GLOBAL_CONTEXT
                current_parent = None
                continue

            if indentation == 0 and current_context.kind is not ContextKind.GLOBAL:
                current_context = _GLOBAL_CONTEXT
                current_parent = None

            command_context = _single_line_context(stripped) or current_context
            parent_context = (
                current_parent if command_context is current_context else _GLOBAL_CONTEXT
            )
            self._record_command(
                state,
                raw_line,
                stripped,
                line_number,
                command_context,
                parent_context,
            )

        if special_block is not None:
            incomplete = True
            state.diagnostics.append(
                _diagnostic(
                    DiagnosticKind.INCOMPLETE_CONFIGURATION,
                    "CG-PARSE-INCOMPLETE-BLOCK",
                    "A sensitive configuration block was not terminated before end of input.",
                    special_block.opener_line,
                    _command_id(special_block.opener_line),
                )
            )

        if not state.commands:
            raise MalformedConfigurationError(
                "The input does not contain a usable configuration command."
            )

        status = ParseStatus.PARSED
        if incomplete:
            status = ParseStatus.INCOMPLETE
        elif state.unsupported or support.platform is PlatformFamily.UNKNOWN:
            status = ParseStatus.PARTIAL

        classified_count = sum(command.classified for command in state.commands)
        metrics = ParseMetrics(
            input_line_count=len(lines),
            command_count=len(state.commands),
            classified_command_count=classified_count,
            unsupported_command_count=len(state.unsupported),
            observation_count=len(state.observations),
        )
        return ParsedConfiguration(
            source_label=source.label,
            platform=support.platform,
            parser_name=self.name,
            parser_version=self.version,
            commands=tuple(state.commands),
            observations=tuple(state.observations),
            unsupported_syntax=tuple(state.unsupported),
            status=status,
            diagnostics=tuple(state.diagnostics),
            metrics=metrics,
        )

    def _validate_source(self, source: ConfigurationSource) -> None:
        try:
            encoded_size = len(source.text.encode("utf-8", errors="strict"))
        except UnicodeEncodeError:
            raise MalformedConfigurationError(
                "The configuration contains invalid Unicode text."
            ) from None
        if encoded_size > self._max_source_bytes:
            raise MalformedConfigurationError("The configuration exceeds the parser size limit.")
        if not source.text.strip():
            raise MalformedConfigurationError("The configuration is empty.")
        if "\x00" in source.text:
            raise MalformedConfigurationError("The configuration contains binary control data.")

    def _record_command(
        self,
        state: _ParseState,
        raw_line: str,
        stripped: str,
        line_number: int,
        context: ConfigurationContext,
        parent_context: ConfigurationContext | None,
    ) -> None:
        tokens = stripped.split()
        command_id = _command_id(line_number)
        specs = _observation_specs(
            context,
            tokens,
            state.acl_entry_counts,
            state.snmp_community_ids,
            state.local_user_ids,
        )
        unsupported_rule_scope = _unsupported_rule_scope(context, tokens, specs)
        classified = bool(specs) or (
            _is_known_command(context, tokens) and unsupported_rule_scope is None
        )
        name = _command_name(tokens) if classified else "unclassified"
        arguments = tuple(tokens[1:]) if classified else ()

        state.commands.append(
            CommandRecord(
                command_id=command_id,
                text=raw_line,
                location=SourceLocation(line_number, line_number),
                context=context,
                name=name,
                arguments=arguments,
                parent_context=parent_context,
                classified=classified,
            )
        )
        for kind, attributes in specs:
            state.add_observation(kind, attributes, command_id)

        if not classified:
            reason = "Command is not classified by parser version 1."
            state.unsupported.append(UnsupportedSyntax(command_id=command_id, reason=reason))
            state.diagnostics.append(
                _diagnostic(
                    DiagnosticKind.UNSUPPORTED_SYNTAX,
                    "CG-PARSE-UNSUPPORTED-COMMAND",
                    "A command was retained but could not be classified safely.",
                    line_number,
                    command_id,
                )
            )
            state.add_observation(
                "command.unclassified",
                {
                    "context_kind": context.kind.value,
                    "context_identifier": context.identifier,
                    "redacted": True,
                    "rule_scope": unsupported_rule_scope or "other",
                },
                command_id,
            )

    def _record_control(
        self,
        state: _ParseState,
        raw_line: str,
        line_number: int,
        context: ConfigurationContext,
        name: str,
    ) -> None:
        state.commands.append(
            CommandRecord(
                command_id=_command_id(line_number),
                text=raw_line,
                location=SourceLocation(line_number, line_number),
                context=context,
                name=name,
                parent_context=_GLOBAL_CONTEXT if context != _GLOBAL_CONTEXT else None,
            )
        )

    def _record_special_block_line(
        self,
        state: _ParseState,
        block: _SpecialBlock,
        raw_line: str,
        stripped: str,
        line_number: int,
    ) -> bool:
        is_crypto_close = block.kind == "crypto" and stripped.lower() in {"quit", "exit"}
        is_banner_close = (
            block.kind == "banner" and block.delimiter is not None and block.delimiter in stripped
        )
        state.commands.append(
            CommandRecord(
                command_id=_command_id(line_number),
                text=raw_line,
                location=SourceLocation(line_number, line_number),
                context=block.context,
                name=f"{block.kind}-content",
                parent_context=_GLOBAL_CONTEXT,
            )
        )
        return is_crypto_close or is_banner_close


def _declared_version_major(lines: tuple[str, ...]) -> int | None:
    for line in lines:
        match = _VERSION_PATTERN.match(line)
        if match is not None:
            return int(match.group("major"))
    return None


def _is_export_preamble(stripped: str) -> bool:
    lowered = stripped.lower()
    return lowered.startswith(
        (
            "building configuration",
            "current configuration",
            "last configuration change",
            "nvram config last updated",
        )
    )


def _section_header(
    stripped: str,
) -> (
    tuple[
        ConfigurationContext,
        str,
        tuple[str, ...],
        ObservationSpec | None,
    ]
    | None
):
    tokens = stripped.split()
    lowered = [token.lower() for token in tokens]
    if len(tokens) >= 2 and lowered[0] == "interface":
        identifier = " ".join(tokens[1:])
        return (
            ConfigurationContext(ContextKind.INTERFACE, identifier),
            "interface",
            tuple(tokens[1:]),
            (
                "interface.declaration",
                {
                    "name": identifier,
                    "interface_type": _interface_type(identifier),
                },
            ),
        )
    if len(tokens) >= 2 and lowered[0] == "line":
        identifier = " ".join(tokens[1:])
        return (
            ConfigurationContext(ContextKind.LINE, identifier),
            "line",
            tuple(tokens[1:]),
            (
                "line.declaration",
                {
                    "line_type": lowered[1],
                    "range": tuple(tokens[2:]),
                },
            ),
        )
    if (
        len(tokens) >= 4
        and lowered[:2] == ["ip", "access-list"]
        and lowered[2] in {"standard", "extended"}
    ):
        identifier = " ".join(tokens[3:])
        return (
            ConfigurationContext(ContextKind.ACL, identifier),
            "ip access-list",
            tuple(tokens[2:]),
            (
                "acl.definition",
                {
                    "name": identifier,
                    "acl_type": lowered[2],
                    "address_family": "ipv4",
                },
            ),
        )
    if len(tokens) >= 3 and lowered[:2] == ["ipv6", "access-list"]:
        identifier = " ".join(tokens[2:])
        return (
            ConfigurationContext(ContextKind.ACL, identifier),
            "ipv6 access-list",
            tuple(tokens[2:]),
            (
                "acl.definition",
                {
                    "name": identifier,
                    "acl_type": "extended",
                    "address_family": "ipv6",
                },
            ),
        )
    if len(tokens) >= 2 and lowered[0] == "router":
        identifier = " ".join(tokens[1:])
        return (
            ConfigurationContext(ContextKind.ROUTER, identifier),
            "router",
            tuple(tokens[1:]),
            (
                "routing.process",
                {
                    "protocol": lowered[1],
                    "process": tuple(tokens[2:]),
                },
            ),
        )
    if len(tokens) >= 2 and lowered[0] == "vlan":
        identifier = " ".join(tokens[1:])
        return (
            ConfigurationContext(ContextKind.VLAN, identifier),
            "vlan",
            tuple(tokens[1:]),
            ("vlan.declaration", {"identifier": identifier}),
        )
    if len(tokens) >= 4 and lowered[:3] == ["aaa", "group", "server"]:
        identifier = " ".join(tokens[1:])
        return (
            ConfigurationContext(ContextKind.AAA, identifier),
            "aaa group server",
            tuple(tokens[3:]),
            (
                "authentication.server_group",
                {
                    "protocol": lowered[3] if len(lowered) > 3 else "unknown",
                    "name": tokens[4] if len(tokens) > 4 else "",
                },
            ),
        )
    if len(tokens) >= 3 and lowered[:2] in (["radius", "server"], ["tacacs", "server"]):
        identifier = " ".join(tokens)
        return (
            ConfigurationContext(ContextKind.AAA, identifier),
            " ".join(tokens[:2]),
            tuple(tokens[2:]),
            (
                "authentication.server",
                {"protocol": lowered[0], "name": tokens[2]},
            ),
        )
    if len(tokens) >= 3 and lowered[:2] == ["key", "chain"]:
        identifier = " ".join(tokens)
        return (
            ConfigurationContext(ContextKind.AAA, identifier),
            "key chain",
            tuple(tokens[2:]),
            ("authentication.key_chain", {"name": tokens[2]}),
        )
    if len(tokens) >= 5 and lowered[:4] == ["crypto", "pki", "certificate", "chain"]:
        identifier = " ".join(tokens[4:])
        return (
            ConfigurationContext(ContextKind.CRYPTO, identifier),
            "crypto pki certificate chain",
            tuple(tokens[4:]),
            ("crypto.certificate_chain", {"present": True}),
        )
    if len(tokens) >= 2 and lowered[0] == "banner":
        return (
            _GLOBAL_CONTEXT,
            "banner",
            tuple(tokens[1:]),
            ("configuration.banner", {"banner_type": lowered[1]}),
        )
    return None


def _single_line_context(stripped: str) -> ConfigurationContext | None:
    tokens = stripped.split()
    lowered = [token.lower() for token in tokens]
    if lowered and (lowered[0] == "aaa" or lowered[:2] == ["no", "aaa"]):
        return ConfigurationContext(ContextKind.AAA)
    if len(tokens) >= 3 and lowered[0] == "access-list":
        return ConfigurationContext(ContextKind.ACL, tokens[1])
    return None


def _observation_specs(
    context: ConfigurationContext,
    tokens: list[str],
    acl_entry_counts: dict[str, int],
    snmp_community_ids: dict[str, str],
    local_user_ids: dict[str, str],
) -> tuple[ObservationSpec, ...]:
    if not tokens:
        return ()
    lowered = [token.lower() for token in tokens]
    specs: list[ObservationSpec] = []

    if context.kind is ContextKind.LINE:
        specs.extend(_line_observations(context, tokens, lowered))
    elif context.kind is ContextKind.INTERFACE:
        specs.extend(_interface_observations(context, tokens, lowered))
    elif context.kind is ContextKind.ACL:
        acl_spec = _acl_observation(context, tokens, lowered, acl_entry_counts)
        if acl_spec is not None:
            specs.append(acl_spec)
    elif context.kind is ContextKind.ROUTER:
        specs.extend(_routing_observations(context, tokens, lowered))
    elif context.kind is ContextKind.VLAN:
        if lowered[0] == "name":
            specs.append(("vlan.name", {"configured": True}))
        elif lowered[0] == "shutdown" or lowered[:2] == ["no", "shutdown"]:
            specs.append(("vlan.shutdown", {"enabled": lowered[0] == "shutdown"}))
    elif context.kind is ContextKind.AAA:
        specs.extend(_aaa_observations(tokens, lowered))

    if context.kind is ContextKind.GLOBAL:
        specs.extend(
            _global_observations(tokens, lowered, snmp_community_ids, local_user_ids)
        )
    return tuple(specs)


def _line_observations(
    context: ConfigurationContext,
    tokens: list[str],
    lowered: list[str],
) -> list[ObservationSpec]:
    specs: list[ObservationSpec] = []
    if lowered[:3] in (["no", "transport", "input"], ["no", "transport", "output"]):
        specs.append(
            (
                "line.transport",
                {
                    "line": context.identifier,
                    "direction": lowered[2],
                    "protocols": (),
                    "configured": False,
                },
            )
        )
    elif lowered[:2] in (["transport", "input"], ["transport", "output"]):
        specs.append(
            (
                "line.transport",
                {
                    "line": context.identifier,
                    "direction": lowered[1],
                    "protocols": tuple(lowered[2:]),
                    "configured": True,
                },
            )
        )
    elif lowered == ["login"]:
        mode = "default"
        method_list: str | None = None
        specs.append(
            (
                "line.authentication",
                {"line": context.identifier, "mode": mode, "method_list": method_list},
            )
        )
    elif lowered == ["login", "local"]:
        specs.append(
            (
                "line.authentication",
                {"line": context.identifier, "mode": "local", "method_list": None},
            )
        )
    elif len(lowered) == 3 and lowered[:2] == ["login", "authentication"]:
        specs.append(
            (
                "line.authentication",
                {"line": context.identifier, "mode": "method_list", "method_list": tokens[2]},
            )
        )
    elif lowered == ["no", "login"]:
        specs.append(("line.authentication", {"line": context.identifier, "mode": "disabled"}))
    elif lowered[0] == "access-class" and len(tokens) >= 3:
        specs.append(
            (
                "line.access_class",
                {
                    "line": context.identifier,
                    "access_list": tokens[1],
                    "direction": lowered[2],
                    "address_family": "ipv4",
                    "configured": True,
                    "modifiers": tuple(lowered[3:]),
                },
            )
        )
    elif lowered[:2] == ["no", "access-class"] and len(tokens) >= 4:
        specs.append(
            (
                "line.access_class",
                {
                    "line": context.identifier,
                    "access_list": tokens[2],
                    "direction": lowered[3],
                    "address_family": "ipv4",
                    "configured": False,
                    "modifiers": tuple(lowered[4:]),
                },
            )
        )
    elif lowered[:2] == ["ipv6", "access-class"] and len(tokens) >= 4:
        specs.append(
            (
                "line.access_class",
                {
                    "line": context.identifier,
                    "access_list": tokens[2],
                    "direction": lowered[3],
                    "address_family": "ipv6",
                    "configured": True,
                    "modifiers": tuple(lowered[4:]),
                },
            )
        )
    elif lowered[:3] == ["no", "ipv6", "access-class"] and len(tokens) >= 5:
        specs.append(
            (
                "line.access_class",
                {
                    "line": context.identifier,
                    "access_list": tokens[3],
                    "direction": lowered[4],
                    "address_family": "ipv6",
                    "configured": False,
                    "modifiers": tuple(lowered[5:]),
                },
            )
        )
    elif lowered[0] == "exec-timeout" and len(tokens) >= 2:
        specs.append(
            (
                "line.exec_timeout",
                {
                    "line": context.identifier,
                    "minutes": _to_int(tokens[1]),
                    "seconds": _to_int(tokens[2]) if len(tokens) > 2 else 0,
                },
            )
        )
    elif lowered[0] == "password" and len(tokens) >= 2:
        algorithm_type, storage = _password_storage(tokens, lowered, 1)
        specs.append(
            (
                "line.password",
                {
                    "line": context.identifier,
                    "configured": True,
                    "algorithm_type": algorithm_type,
                    "storage": storage,
                    "value": "[REDACTED]",
                },
            )
        )
    elif lowered == ["no", "password"]:
        specs.append(
            (
                "line.password",
                {
                    "line": context.identifier,
                    "configured": False,
                    "algorithm_type": None,
                    "storage": "none",
                    "value": "[REDACTED]",
                },
            )
        )
    return specs


def _interface_observations(
    context: ConfigurationContext,
    tokens: list[str],
    lowered: list[str],
) -> list[ObservationSpec]:
    specs: list[ObservationSpec] = []
    if lowered[0] == "shutdown" or lowered[:2] == ["no", "shutdown"]:
        specs.append(
            (
                "interface.shutdown",
                {"interface": context.identifier, "enabled": lowered[0] == "shutdown"},
            )
        )
    elif lowered[:2] == ["ip", "access-group"] and len(tokens) >= 4:
        specs.append(
            (
                "interface.access_group",
                {
                    "interface": context.identifier,
                    "access_list": tokens[2],
                    "direction": lowered[3],
                    "address_family": "ipv4",
                },
            )
        )
    elif lowered[:2] == ["ipv6", "traffic-filter"] and len(tokens) >= 4:
        specs.append(
            (
                "interface.access_group",
                {
                    "interface": context.identifier,
                    "access_list": tokens[2],
                    "direction": lowered[3],
                    "address_family": "ipv6",
                },
            )
        )
    elif (
        len(tokens) == 3
        and lowered[:2] == ["switchport", "mode"]
        and lowered[2] in {"access", "trunk"}
    ):
        specs.append(
            (
                "interface.switchport_mode",
                {
                    "interface": context.identifier,
                    "mode": lowered[2],
                    "configured": True,
                },
            )
        )
    elif lowered == ["no", "switchport", "mode"]:
        specs.append(
            (
                "interface.switchport_mode",
                {
                    "interface": context.identifier,
                    "mode": None,
                    "configured": False,
                },
            )
        )
    elif len(tokens) == 4 and lowered[:3] == ["switchport", "access", "vlan"]:
        vlan = _to_int(tokens[3])
        if vlan is not None and 1 <= vlan <= 4094:
            specs.append(
                (
                    "interface.access_vlan",
                    {
                        "interface": context.identifier,
                        "vlan": str(vlan),
                        "configured": True,
                    },
                )
            )
    elif lowered == ["no", "switchport", "access", "vlan"]:
        specs.append(
            (
                "interface.access_vlan",
                {
                    "interface": context.identifier,
                    "vlan": None,
                    "configured": False,
                },
            )
        )
    elif lowered == ["switchport", "port-security"]:
        specs.append(
            (
                "interface.port_security",
                {
                    "interface": context.identifier,
                    "setting": "state",
                    "configured": True,
                    "enabled": True,
                    "value": None,
                },
            )
        )
    elif lowered == ["no", "switchport", "port-security"]:
        specs.append(
            (
                "interface.port_security",
                {
                    "interface": context.identifier,
                    "setting": "state",
                    "configured": True,
                    "enabled": False,
                    "value": None,
                },
            )
        )
    elif len(tokens) == 4 and lowered[:3] == ["switchport", "port-security", "maximum"]:
        maximum = _to_int(tokens[3])
        if maximum is not None and maximum > 0:
            specs.append(
                (
                    "interface.port_security",
                    {
                        "interface": context.identifier,
                        "setting": "maximum",
                        "configured": True,
                        "enabled": None,
                        "value": maximum,
                    },
                )
            )
    elif lowered == ["no", "switchport", "port-security", "maximum"]:
        specs.append(
            (
                "interface.port_security",
                {
                    "interface": context.identifier,
                    "setting": "maximum",
                    "configured": False,
                    "enabled": None,
                    "value": None,
                },
            )
        )
    elif (
        len(tokens) == 4
        and lowered[:3] == ["switchport", "port-security", "violation"]
        and lowered[3] in {"protect", "restrict", "shutdown"}
    ):
        specs.append(
            (
                "interface.port_security",
                {
                    "interface": context.identifier,
                    "setting": "violation",
                    "configured": True,
                    "enabled": None,
                    "value": lowered[3],
                },
            )
        )
    elif lowered == ["no", "switchport", "port-security", "violation"]:
        specs.append(
            (
                "interface.port_security",
                {
                    "interface": context.identifier,
                    "setting": "violation",
                    "configured": False,
                    "enabled": None,
                    "value": None,
                },
            )
        )
    elif lowered == ["ip", "dhcp", "snooping", "trust"]:
        specs.append(
            (
                "interface.dhcp_snooping_trust",
                {"interface": context.identifier, "enabled": True},
            )
        )
    elif lowered == ["no", "ip", "dhcp", "snooping", "trust"]:
        specs.append(
            (
                "interface.dhcp_snooping_trust",
                {"interface": context.identifier, "enabled": False},
            )
        )
    elif lowered == ["ip", "arp", "inspection", "trust"]:
        specs.append(
            (
                "interface.arp_inspection_trust",
                {"interface": context.identifier, "enabled": True},
            )
        )
    elif lowered == ["no", "ip", "arp", "inspection", "trust"]:
        specs.append(
            (
                "interface.arp_inspection_trust",
                {"interface": context.identifier, "enabled": False},
            )
        )
    elif len(tokens) >= 2 and lowered[0] == "channel-group" and tokens[1].isdigit():
        specs.append(
            (
                "interface.channel_group",
                {
                    "interface": context.identifier,
                    "group": tokens[1],
                    "configured": True,
                },
            )
        )
    elif (
        len(tokens) == 3
        and lowered[:2] == ["no", "channel-group"]
        and tokens[2].isdigit()
    ):
        specs.append(
            (
                "interface.channel_group",
                {
                    "interface": context.identifier,
                    "group": tokens[2],
                    "configured": False,
                },
            )
        )
    elif lowered in (["spanning-tree", "portfast"], ["spanning-tree", "portfast", "edge"]):
        specs.append(
            (
                "interface.spanning_tree_portfast",
                {
                    "interface": context.identifier,
                    "enabled": True,
                    "mode": "edge" if len(lowered) == 3 else "portfast",
                },
            )
        )
    elif lowered in (["no", "spanning-tree", "portfast"], ["spanning-tree", "portfast", "disable"]):
        specs.append(
            (
                "interface.spanning_tree_portfast",
                {"interface": context.identifier, "enabled": False, "mode": "disabled"},
            )
        )
    elif len(lowered) == 3 and lowered[:2] == ["spanning-tree", "bpduguard"] and lowered[2] in {
        "enable",
        "disable",
    }:
        specs.append(
            (
                "interface.bpdu_guard",
                {
                    "interface": context.identifier,
                    "configured": True,
                    "enabled": lowered[2] == "enable",
                },
            )
        )
    elif lowered == ["no", "spanning-tree", "bpduguard"]:
        specs.append(
            (
                "interface.bpdu_guard",
                {
                    "interface": context.identifier,
                    "configured": False,
                    "enabled": None,
                },
            )
        )
    elif lowered[:3] == ["ip", "ospf", "authentication-key"]:
        specs.append(
            (
                "routing.interface_authentication",
                {
                    "interface": context.identifier,
                    "protocol": "ospf",
                    "mode": "authentication_key",
                    "secret": "[REDACTED]",
                },
            )
        )
    elif lowered[:3] == ["ip", "ospf", "message-digest-key"]:
        specs.append(
            (
                "routing.interface_authentication",
                {
                    "interface": context.identifier,
                    "protocol": "ospf",
                    "mode": "message_digest",
                    "secret": "[REDACTED]",
                },
            )
        )
    elif lowered[:3] == ["ip", "rip", "authentication"]:
        specs.append(
            (
                "routing.interface_authentication",
                {
                    "interface": context.identifier,
                    "protocol": "rip",
                    "arguments": tuple(lowered[3:]),
                },
            )
        )
    elif "authentication" in lowered and "eigrp" in lowered:
        specs.append(
            (
                "routing.interface_authentication",
                {
                    "interface": context.identifier,
                    "protocol": "eigrp",
                    "arguments": tuple(lowered[1:]),
                },
            )
        )
    return specs


def _acl_observation(
    context: ConfigurationContext,
    tokens: list[str],
    lowered: list[str],
    acl_entry_counts: dict[str, int],
) -> ObservationSpec | None:
    acl_name = context.identifier or "unknown"
    entry_tokens = tokens
    entry_lowered = lowered
    if lowered[0] == "access-list" and len(tokens) >= 3:
        acl_name = tokens[1]
        entry_tokens = tokens[2:]
        entry_lowered = lowered[2:]
    if not entry_tokens:
        return None

    sequence: int | None = None
    if entry_tokens[0].isdigit() and len(entry_tokens) > 1:
        sequence = int(entry_tokens[0])
        entry_tokens = entry_tokens[1:]
        entry_lowered = entry_lowered[1:]
    if not entry_tokens:
        return None

    acl_entry_counts[acl_name] = acl_entry_counts.get(acl_name, 0) + 1
    if entry_lowered[0] == "remark":
        return (
            "acl.remark",
            {
                "access_list": acl_name,
                "entry_index": acl_entry_counts[acl_name],
                "sequence": sequence,
                "text": "[REDACTED]",
            },
        )
    if entry_lowered[0] in {"permit", "deny", "dynamic", "evaluate"}:
        return (
            "acl.entry",
            {
                "access_list": acl_name,
                "entry_index": acl_entry_counts[acl_name],
                "sequence": sequence,
                "action": entry_lowered[0],
                "arguments": tuple(entry_tokens[1:]),
                "acl_type": _numbered_acl_type(acl_name),
            },
        )
    return None


def _routing_observations(
    context: ConfigurationContext,
    tokens: list[str],
    lowered: list[str],
) -> list[ObservationSpec]:
    protocol = (context.identifier or "unknown").split()[0].lower()
    if "authentication" in lowered:
        return [
            (
                "routing.authentication",
                {
                    "protocol": protocol,
                    "command": tuple(lowered[:3]),
                    "arguments": _safe_routing_arguments(tokens, lowered),
                },
            )
        ]
    if lowered[0] == "neighbor" and "password" in lowered:
        return [
            (
                "routing.authentication",
                {"protocol": protocol, "command": ("neighbor", "password"), "configured": True},
            )
        ]
    return []


def _aaa_observations(tokens: list[str], lowered: list[str]) -> list[ObservationSpec]:
    if lowered in (["aaa", "new-model"], ["no", "aaa", "new-model"]):
        return [("authentication.aaa_model", {"enabled": lowered[0] == "aaa"})]
    if len(tokens) >= 5 and lowered[:3] == ["aaa", "authentication", "login"]:
        return [
            (
                "authentication.aaa_method_list",
                {
                    "service": lowered[2],
                    "name": tokens[3],
                    "methods": tuple(tokens[4:]),
                    "configured": True,
                },
            )
        ]
    if len(tokens) == 5 and lowered[:4] == ["no", "aaa", "authentication", "login"]:
        return [
            (
                "authentication.aaa_method_list",
                {
                    "service": "login",
                    "name": tokens[4],
                    "methods": (),
                    "configured": False,
                },
            )
        ]
    if lowered[0] in {"key", "key-string"}:
        return [("authentication.server_key", {"configured": True, "value": "[REDACTED]"})]
    return []


def _global_observations(
    tokens: list[str],
    lowered: list[str],
    snmp_community_ids: dict[str, str],
    local_user_ids: dict[str, str],
) -> list[ObservationSpec]:
    specs: list[ObservationSpec] = []
    if lowered[0] == "version" and len(tokens) >= 2:
        specs.append(("platform.version_declaration", {"value": tokens[1]}))
    elif lowered[:2] == ["no", "username"] and len(tokens) >= 3:
        specs.append(
            (
                "authentication.local_user",
                {
                    "principal_id": _local_user_id(tokens[2], local_user_ids),
                    "username": "[REDACTED]",
                    "configured": False,
                    "credential_kind": None,
                    "algorithm_type": None,
                    "storage": "none",
                },
            )
        )
    elif lowered[0] == "username" and len(tokens) >= 2:
        credential_kind = next(
            (keyword for keyword in ("secret", "password") if keyword in lowered),
            None,
        )
        algorithm_type: str | None = None
        storage = "none"
        if credential_kind is not None:
            index = lowered.index(credential_kind)
            if credential_kind == "password":
                algorithm_type, storage = _password_storage(tokens, lowered, index + 1)
            elif index + 1 < len(tokens):
                algorithm_type = tokens[index + 1] if tokens[index + 1].isdigit() else None
                storage = "plaintext" if algorithm_type == "0" else "secret"
        specs.append(
            (
                "authentication.local_user",
                {
                    "principal_id": _local_user_id(tokens[1], local_user_ids),
                    "username": "[REDACTED]",
                    "configured": True,
                    "credential_kind": credential_kind,
                    "algorithm_type": algorithm_type,
                    "storage": storage,
                },
            )
        )
    elif lowered[:3] in (["no", "enable", "secret"], ["no", "enable", "password"]):
        specs.append(
            (
                "authentication.enable_credential",
                {
                    "credential_kind": lowered[2],
                    "configured": False,
                    "algorithm_type": None,
                    "storage": "none",
                    "value": "[REDACTED]",
                },
            )
        )
    elif lowered[:2] in (["enable", "secret"], ["enable", "password"]):
        enable_algorithm_type: str | None = None
        enable_storage = "secret"
        if lowered[1] == "password":
            enable_algorithm_type, enable_storage = _password_storage(tokens, lowered, 2)
        elif len(tokens) > 2 and tokens[2].isdigit():
            enable_algorithm_type = tokens[2]
            enable_storage = "plaintext" if enable_algorithm_type == "0" else "secret"
        specs.append(
            (
                "authentication.enable_credential",
                {
                    "credential_kind": lowered[1],
                    "configured": True,
                    "algorithm_type": enable_algorithm_type,
                    "storage": enable_storage,
                    "value": "[REDACTED]",
                },
            )
        )
    elif lowered[:4] == ["no", "ip", "ssh", "version"]:
        specs.append(
            (
                "management.ssh_setting",
                {"setting": "version", "arguments": (), "configured": False},
            )
        )
    elif lowered[:2] == ["ip", "ssh"] and len(tokens) >= 3:
        specs.append(
            (
                "management.ssh_setting",
                {
                    "setting": lowered[2],
                    "arguments": tuple(tokens[3:]),
                    "configured": True,
                },
            )
        )
    elif lowered[:2] == ["ip", "http"] or lowered[:3] == ["no", "ip", "http"]:
        offset = 1 if lowered[0] == "no" else 0
        setting = lowered[offset + 2] if len(lowered) > offset + 2 else "unknown"
        specs.append(
            (
                "management.http_setting",
                {
                    "setting": setting,
                    "enabled": lowered[0] != "no",
                    "arguments": tuple(tokens[offset + 3 :]),
                },
            )
        )
    elif lowered[:3] == ["no", "snmp-server", "community"] and len(tokens) >= 4:
        specs.append(
            (
                "snmp.community",
                {
                    "community": "[REDACTED]",
                    "community_id": _community_id(tokens[3], snmp_community_ids),
                    "configured": False,
                    "access_mode": None,
                    "access_list": None,
                },
            )
        )
    elif lowered[:2] == ["snmp-server", "community"] and len(tokens) >= 3:
        mode_offset = next(
            (index for index, item in enumerate(lowered[3:], start=3) if item in {"ro", "rw"}),
            None,
        )
        mode = lowered[mode_offset] if mode_offset is not None else None
        acl = (
            tokens[mode_offset + 1]
            if mode_offset is not None and mode_offset + 1 < len(tokens)
            else None
        )
        specs.append(
            (
                "snmp.community",
                {
                    "community": "[REDACTED]",
                    "community_id": _community_id(tokens[2], snmp_community_ids),
                    "configured": True,
                    "access_mode": mode,
                    "access_list": acl,
                },
            )
        )
    elif lowered[:2] == ["snmp-server", "group"] and len(tokens) >= 4:
        security_level = next(
            (item for item in lowered if item in {"noauth", "auth", "priv"}),
            None,
        )
        specs.append(
            (
                "snmp.group",
                {
                    "name": tokens[2],
                    "version": tokens[3],
                    "security_level": security_level,
                },
            )
        )
    elif lowered[:2] == ["snmp-server", "user"] and len(tokens) >= 5:
        auth_protocol = _token_after(lowered, tokens, "auth")
        privacy_protocol = _token_after(lowered, tokens, "priv")
        access_list = _token_after(lowered, tokens, "access")
        specs.append(
            (
                "snmp.user",
                {
                    "username": "[REDACTED]",
                    "group": tokens[3],
                    "version": tokens[4],
                    "auth_protocol": auth_protocol,
                    "privacy_protocol": privacy_protocol,
                    "access_list": access_list,
                },
            )
        )
    elif lowered == ["ip", "dhcp", "snooping"]:
        specs.append(("layer2.dhcp_snooping", {"enabled": True}))
    elif lowered == ["no", "ip", "dhcp", "snooping"]:
        specs.append(("layer2.dhcp_snooping", {"enabled": False}))
    elif len(tokens) >= 5 and lowered[:4] == ["ip", "dhcp", "snooping", "vlan"]:
        vlans = _parse_vlan_spec(tokens[4:])
        if vlans is not None:
            specs.append(
                (
                    "layer2.dhcp_snooping_vlan",
                    {"configured": True, "vlans": vlans},
                )
            )
    elif len(tokens) >= 6 and lowered[:5] == ["no", "ip", "dhcp", "snooping", "vlan"]:
        vlans = _parse_vlan_spec(tokens[5:])
        if vlans is not None:
            specs.append(
                (
                    "layer2.dhcp_snooping_vlan",
                    {"configured": False, "vlans": vlans},
                )
            )
    elif len(tokens) >= 5 and lowered[:4] == ["ip", "arp", "inspection", "vlan"]:
        vlans = _parse_vlan_spec(tokens[4:])
        if vlans is not None:
            specs.append(
                (
                    "layer2.arp_inspection_vlan",
                    {"configured": True, "vlans": vlans},
                )
            )
    elif len(tokens) >= 6 and lowered[:5] == ["no", "ip", "arp", "inspection", "vlan"]:
        vlans = _parse_vlan_spec(tokens[5:])
        if vlans is not None:
            specs.append(
                (
                    "layer2.arp_inspection_vlan",
                    {"configured": False, "vlans": vlans},
                )
            )
    elif lowered == ["spanning-tree", "portfast", "bpduguard", "default"]:
        specs.append(("layer2.bpdu_guard_default", {"enabled": True}))
    elif lowered == ["no", "spanning-tree", "portfast", "bpduguard", "default"]:
        specs.append(("layer2.bpdu_guard_default", {"enabled": False}))
    return specs


def _is_known_command(context: ConfigurationContext, tokens: list[str]) -> bool:
    if not tokens:
        return False
    lowered = [token.lower() for token in tokens]
    first = lowered[0]
    if first in {"exit", "exit-address-family", "end"}:
        return True
    if context.kind is ContextKind.GLOBAL:
        return first in {
            "aaa",
            "archive",
            "boot-start-marker",
            "boot-end-marker",
            "clock",
            "control-plane",
            "crypto",
            "enable",
            "errdisable",
            "hostname",
            "ip",
            "ipv6",
            "license",
            "logging",
            "multilink",
            "no",
            "ntp",
            "platform",
            "redundancy",
            "service",
            "snmp-server",
            "spanning-tree",
            "switch",
            "username",
            "version",
        }
    known_by_context: dict[ContextKind, set[str]] = {
        ContextKind.INTERFACE: {
            "authentication",
            "channel-group",
            "description",
            "duplex",
            "encapsulation",
            "ip",
            "ipv6",
            "load-interval",
            "media-type",
            "mtu",
            "negotiation",
            "no",
            "service-policy",
            "serial",
            "shutdown",
            "spanning-tree",
            "speed",
            "storm-control",
            "switchport",
            "vrf",
        },
        ContextKind.LINE: {
            "access-class",
            "exec-timeout",
            "ipv6",
            "login",
            "logging",
            "no",
            "password",
            "privilege",
            "rotary",
            "session-timeout",
            "stopbits",
            "transport",
        },
        ContextKind.AAA: {
            "aaa",
            "address",
            "automate-tester",
            "ip",
            "key",
            "key-string",
            "no",
            "server",
            "timeout",
        },
        ContextKind.ACL: {"deny", "dynamic", "evaluate", "permit", "remark", "no"},
        ContextKind.ROUTER: {
            "address-family",
            "area",
            "authentication",
            "auto-summary",
            "default-information",
            "distance",
            "eigrp",
            "exit-address-family",
            "neighbor",
            "network",
            "no",
            "passive-interface",
            "redistribute",
            "router-id",
            "timers",
            "version",
        },
        ContextKind.VLAN: {"name", "no", "private-vlan", "remote-span", "shutdown", "state"},
        ContextKind.CRYPTO: {"certificate", "quit"},
    }
    if first.isdigit() and context.kind is ContextKind.ACL:
        return len(lowered) > 1 and lowered[1] in {"permit", "deny", "remark"}
    return first in known_by_context.get(context.kind, set())


def _unsupported_rule_scope(
    context: ConfigurationContext,
    tokens: list[str],
    specs: tuple[ObservationSpec, ...],
) -> str | None:
    """Identify malformed syntax that can affect one implemented rule family."""

    if not tokens or specs:
        return None
    lowered = [token.lower() for token in tokens]
    if context.kind is ContextKind.LINE and (
        lowered[0] == "transport" or lowered[:2] == ["no", "transport"]
    ):
        return "line.transport"
    if context.kind is ContextKind.LINE and (
        lowered[0] == "access-class"
        or lowered[:2] == ["no", "access-class"]
        or lowered[:2] == ["ipv6", "access-class"]
        or lowered[:3] == ["no", "ipv6", "access-class"]
    ):
        return "line.access_class"
    if context.kind is ContextKind.LINE and (
        lowered[0] == "login" or lowered[:2] == ["no", "login"]
    ):
        return "line.authentication"
    if context.kind is ContextKind.LINE and (
        lowered[0] == "password" or lowered[:2] == ["no", "password"]
    ):
        return "line.password"
    if context.kind is ContextKind.ACL:
        return "acl.entry"
    if context.kind is ContextKind.AAA and (
        lowered[:3] == ["aaa", "authentication", "login"]
        or lowered[:4] == ["no", "aaa", "authentication", "login"]
    ):
        return "line.authentication"
    if context.kind is ContextKind.GLOBAL and (
        lowered[0] == "username" or lowered[:2] == ["no", "username"]
    ):
        return "authentication.local_user"
    if context.kind is ContextKind.GLOBAL and (
        lowered[:2] in (["enable", "password"], ["enable", "secret"])
        or lowered[:3] in (["no", "enable", "password"], ["no", "enable", "secret"])
    ):
        return "credential.storage"
    if context.kind is ContextKind.GLOBAL and (
        lowered[:2] == ["snmp-server", "community"]
        or lowered[:3] == ["no", "snmp-server", "community"]
    ):
        return "snmp.community"
    if context.kind is ContextKind.INTERFACE and (
        lowered[:2] == ["switchport", "mode"]
        or lowered[:3] == ["no", "switchport", "mode"]
    ):
        return "layer2.interface_role"
    if context.kind is ContextKind.INTERFACE and (
        lowered[:2] == ["switchport", "port-security"]
        or lowered[:3] == ["no", "switchport", "port-security"]
    ):
        return "layer2.port_security"
    if context.kind is ContextKind.INTERFACE and (
        lowered[:4] == ["ip", "dhcp", "snooping", "trust"]
        or lowered[:5] == ["no", "ip", "dhcp", "snooping", "trust"]
        or lowered[:3] == ["switchport", "access", "vlan"]
        or lowered[:4] == ["no", "switchport", "access", "vlan"]
    ):
        return "layer2.dhcp_snooping"
    if context.kind is ContextKind.GLOBAL and (
        lowered[:3] == ["ip", "dhcp", "snooping"]
        or lowered[:4] == ["no", "ip", "dhcp", "snooping"]
    ):
        return "layer2.dhcp_snooping"
    if context.kind is ContextKind.INTERFACE and (
        lowered[:4] == ["ip", "arp", "inspection", "trust"]
        or lowered[:5] == ["no", "ip", "arp", "inspection", "trust"]
        or lowered[0] == "channel-group"
        or lowered[:2] == ["no", "channel-group"]
    ):
        return "layer2.dai"
    if context.kind is ContextKind.GLOBAL and (
        lowered[:3] == ["ip", "arp", "inspection"]
        or lowered[:4] == ["no", "ip", "arp", "inspection"]
    ):
        return "layer2.dai"
    if context.kind is ContextKind.INTERFACE and (
        lowered[:2] == ["spanning-tree", "portfast"]
        or lowered[:3] == ["no", "spanning-tree", "portfast"]
        or lowered[:2] == ["spanning-tree", "bpduguard"]
        or lowered[:3] == ["no", "spanning-tree", "bpduguard"]
    ):
        return "layer2.bpdu_guard"
    if context.kind is ContextKind.GLOBAL and (
        lowered[:3] == ["spanning-tree", "portfast", "bpduguard"]
        or lowered[:4] == ["no", "spanning-tree", "portfast", "bpduguard"]
    ):
        return "layer2.bpdu_guard"
    return None


def _command_name(tokens: list[str]) -> str:
    if not tokens:
        return ""
    if tokens[0].lower() == "no" and len(tokens) > 1:
        return f"no {tokens[1].lower()}"
    return tokens[0].lower()


def _banner_delimiter(stripped: str) -> str | None:
    tokens = stripped.split(maxsplit=2)
    if len(tokens) < 3 or not tokens[2]:
        return None
    delimiter_part = tokens[2]
    if delimiter_part.startswith("^C"):
        return "^C"
    return delimiter_part[0]


def _interface_type(identifier: str) -> str:
    match = re.match(r"[A-Za-z-]+", identifier)
    return match.group(0) if match is not None else "unknown"


def _numbered_acl_type(name: str) -> str:
    if not name.isdigit():
        return "named_or_unknown"
    number = int(name)
    if 1 <= number <= 99 or 1300 <= number <= 1999:
        return "standard"
    if 100 <= number <= 199 or 2000 <= number <= 2699:
        return "extended"
    return "unknown"


def _safe_routing_arguments(tokens: list[str], lowered: list[str]) -> tuple[str, ...]:
    sensitive = {"password", "secret", "key", "authentication-key"}
    if any(token in sensitive for token in lowered):
        return ("[REDACTED]",)
    return tuple(tokens[1:])


def _token_after(lowered: list[str], tokens: list[str], keyword: str) -> str | None:
    if keyword not in lowered:
        return None
    index = lowered.index(keyword)
    return tokens[index + 1] if index + 1 < len(tokens) else None


def _community_id(value: str, community_ids: dict[str, str]) -> str:
    existing = community_ids.get(value)
    if existing is not None:
        return existing
    identifier = f"community-{len(community_ids) + 1:03d}"
    community_ids[value] = identifier
    return identifier


def _local_user_id(value: str, local_user_ids: dict[str, str]) -> str:
    existing = local_user_ids.get(value)
    if existing is not None:
        return existing
    identifier = f"local-user-{len(local_user_ids) + 1:03d}"
    local_user_ids[value] = identifier
    return identifier


def _password_storage(
    tokens: list[str],
    lowered: list[str],
    value_offset: int,
) -> tuple[str | None, str]:
    if value_offset >= len(tokens):
        return None, "untyped"
    if lowered[value_offset].isdigit():
        algorithm_type = tokens[value_offset]
        return algorithm_type, "plaintext" if algorithm_type == "0" else "encoded"
    return None, "untyped"


def _parse_vlan_spec(tokens: list[str]) -> tuple[str, ...] | None:
    values: set[int] = set()
    for token in tokens:
        for part in token.split(","):
            if not part:
                return None
            boundaries = part.split("-")
            if len(boundaries) == 1 and boundaries[0].isdigit():
                start = end = int(boundaries[0])
            elif (
                len(boundaries) == 2
                and boundaries[0].isdigit()
                and boundaries[1].isdigit()
            ):
                start, end = int(boundaries[0]), int(boundaries[1])
            else:
                return None
            if start < 1 or end > 4094 or end < start:
                return None
            values.update(range(start, end + 1))
    return tuple(str(value) for value in sorted(values))


def _to_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def _command_id(line_number: int) -> str:
    return f"cmd-{line_number:06d}"


def _diagnostic(
    kind: DiagnosticKind,
    code: str,
    message: str,
    line_number: int,
    command_id: str,
) -> ParserDiagnostic:
    return ParserDiagnostic(
        kind=kind,
        code=code,
        message=message,
        location=SourceLocation(line_number, line_number),
        command_id=command_id,
    )
