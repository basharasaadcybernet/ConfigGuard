"""Conservative resolution for IPv4 ACLs explicitly attached to interfaces."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import StrEnum

from configguard.analysis.interface_resolution import (
    InterfaceResolutionIssue,
    ResolvedInterfaceObservation,
    resolve_interface_configuration,
)
from configguard.domain import ParsedConfiguration, StructuredObservation


class AclPolicyStatus(StrEnum):
    """Whether one referenced policy can be evaluated by the supported subset."""

    SUPPORTED = "supported"
    EMPTY = "empty"
    UNSUPPORTED = "unsupported"


class AclPermitBreadth(StrEnum):
    """Supported broad-permit classes used by the first ACL rule."""

    UNIVERSAL = "universal"
    PROTOCOL_WIDE = "protocol_wide"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class AclAddress:
    """One supported IPv4 ACL address expression."""

    address: str | None = field(repr=False)
    wildcard: str | None = field(repr=False)
    is_any: bool


@dataclass(frozen=True, slots=True)
class ResolvedAclEntry:
    """One fully interpreted permit/deny entry in effective ACL order."""

    observation: StructuredObservation
    action: str
    protocol: str
    source: AclAddress
    destination: AclAddress | None
    source_port: tuple[str, ...] = ()
    destination_port: tuple[str, ...] = ()

    def permit_breadth(self, acl_type: str) -> AclPermitBreadth:
        if self.action != "permit":
            return AclPermitBreadth.NONE
        if acl_type == "standard":
            return AclPermitBreadth.UNIVERSAL if self.source.is_any else AclPermitBreadth.NONE
        if self.destination is None or not self.source.is_any or not self.destination.is_any:
            return AclPermitBreadth.NONE
        if self.protocol == "ip":
            return AclPermitBreadth.UNIVERSAL
        return AclPermitBreadth.PROTOCOL_WIDE

    def terminates_acl(self, acl_type: str) -> bool:
        if acl_type == "standard":
            return self.source.is_any
        return (
            self.protocol == "ip"
            and self.source.is_any
            and self.destination is not None
            and self.destination.is_any
            and not self.source_port
            and not self.destination_port
        )


@dataclass(frozen=True, slots=True)
class ResolvedIpv4Acl:
    """Effective supported state of one IPv4 ACL definition."""

    name: str = field(repr=False)
    acl_type: str
    status: AclPolicyStatus
    definition: StructuredObservation | None
    entries: tuple[ResolvedAclEntry, ...]
    unsupported_evidence: tuple[StructuredObservation, ...] = ()

    def broad_permits(self) -> tuple[tuple[ResolvedAclEntry, AclPermitBreadth], ...]:
        """Return reachable supported broad permits under first-match ordering."""

        broad: list[tuple[ResolvedAclEntry, AclPermitBreadth]] = []
        preceding_denies: list[ResolvedAclEntry] = []
        for entry in self.entries:
            breadth = entry.permit_breadth(self.acl_type)
            if breadth is not AclPermitBreadth.NONE and not any(
                _deny_covers_candidate(deny, entry, self.acl_type) for deny in preceding_denies
            ):
                broad.append((entry, breadth))
            if entry.action == "deny":
                preceding_denies.append(entry)
            if entry.terminates_acl(self.acl_type):
                break
        return tuple(broad)


@dataclass(frozen=True, slots=True)
class InterfaceAclResolution:
    """Effective IPv4 attachments, resolved policies, and scoped uncertainty."""

    attachments: tuple[ResolvedInterfaceObservation, ...]
    removed_attachments: tuple[ResolvedInterfaceObservation, ...]
    policies: tuple[ResolvedIpv4Acl, ...]
    issues: tuple[InterfaceResolutionIssue, ...]

    def policy(self, name: str) -> ResolvedIpv4Acl | None:
        return next((item for item in self.policies if item.name == name), None)


@dataclass(slots=True)
class _AclBuilder:
    name: str
    acl_type: str | None = None
    address_family: str = "ipv4"
    definition: StructuredObservation | None = None
    entries: list[StructuredObservation] = field(default_factory=list)
    unsupported: list[StructuredObservation] = field(default_factory=list)


_SUPPORTED_PROTOCOLS = {"ip", "tcp", "udp", "icmp"}
_PORT_OPERATORS = {"eq": 1, "neq": 1, "lt": 1, "gt": 1, "range": 2}
_NAMED_PORTS = {
    "bootpc",
    "bootps",
    "domain",
    "https",
    "snmp",
    "snmptrap",
    "ssh",
    "telnet",
    "www",
}


def resolve_ipv4_interface_acls(configuration: ParsedConfiguration) -> InterfaceAclResolution:
    """Resolve effective attachments and the IPv4 ACLs they reference."""

    interface_resolution = resolve_interface_configuration(configuration)
    attachment_facts = tuple(
        item
        for item in interface_resolution.facts
        if item.observation.kind == "interface.access_group"
    )
    effective: dict[tuple[str, str], ResolvedInterfaceObservation] = {}
    attachments: list[ResolvedInterfaceObservation] = []
    removed: list[ResolvedInterfaceObservation] = []
    issues: list[InterfaceResolutionIssue] = []
    for fact in attachment_facts:
        if _string(fact.observation, "address_family") != "ipv4":
            continue
        direction = _string(fact.observation, "direction")
        name = _string(fact.observation, "access_list")
        if direction is None or name is None:
            continue
        key = (fact.target_interface, direction)
        if _boolean(fact.observation, "configured") is True:
            effective[key] = fact
            continue
        removed.append(fact)
        current = effective.get(key)
        if current is None:
            continue
        if _string(current.observation, "access_list") == name:
            effective.pop(key)
            continue
        issues.append(
            InterfaceResolutionIssue(
                code="conflicting_interface_acl_removal",
                reason="An interface ACL removal does not match the effective attachment.",
                rule_scopes=("network.interface_acl",),
                evidence=(current, fact),
                target_interfaces=(fact.target_interface,),
            )
        )

    attachments.extend(effective[key] for key in sorted(effective))
    attachment_targets = {item.target_interface for item in attachments}
    issues.extend(
        item
        for item in interface_resolution.relevant_issues({"network.interface_acl"})
        if _relationship_issue_is_relevant(item, configuration, attachment_targets)
    )
    for observation in configuration.observations:
        if (
            observation.kind != "command.unclassified"
            or _string(observation, "rule_scope") != "network.interface_acl"
            or _string(observation, "context_kind") == "interface_template"
        ):
            continue
        identifier = _string(observation, "context_identifier")
        issues.append(
            InterfaceResolutionIssue(
                code="unsupported_interface_acl_attachment",
                reason="An interface IPv4 ACL attachment could not be interpreted safely.",
                rule_scopes=("network.interface_acl",),
                evidence=(observation,),
                target_interfaces=interface_resolution.targets_for_context(identifier),
                unsupported_syntax=True,
            )
        )

    return InterfaceAclResolution(
        attachments=tuple(attachments),
        removed_attachments=tuple(removed),
        policies=_resolve_policies(configuration),
        issues=tuple(issues),
    )


def _resolve_policies(configuration: ParsedConfiguration) -> tuple[ResolvedIpv4Acl, ...]:
    builders: dict[str, _AclBuilder] = {}
    for observation in configuration.observations:
        if observation.kind == "acl.deletion":
            name = _string(observation, "access_list")
            if name is not None:
                builders.pop(name, None)
            continue
        if observation.kind == "acl.definition":
            name = _string(observation, "name")
            if name is None:
                continue
            builder = builders.setdefault(name, _AclBuilder(name))
            acl_type = _string(observation, "acl_type")
            family = _string(observation, "address_family") or "unknown"
            if builder.acl_type is not None and builder.acl_type != acl_type:
                _append_unique(builder.unsupported, observation)
            builder.acl_type = acl_type
            builder.address_family = family
            builder.definition = observation
            continue
        if observation.kind == "acl.entry":
            name = _string(observation, "access_list")
            if name is None:
                continue
            builder = builders.setdefault(name, _AclBuilder(name))
            inferred_type = _string(observation, "acl_type")
            if inferred_type in {"standard", "extended"}:
                if builder.acl_type is not None and builder.acl_type != inferred_type:
                    _append_unique(builder.unsupported, observation)
                builder.acl_type = inferred_type
            builder.entries.append(observation)
            continue
        if observation.kind == "acl.entry_deletion":
            name = _string(observation, "access_list")
            if name is None:
                continue
            builder = builders.setdefault(name, _AclBuilder(name))
            sequence = _integer(observation, "sequence")
            if sequence is not None:
                builder.entries = [
                    item for item in builder.entries if _integer(item, "sequence") != sequence
                ]
                continue
            action = _string(observation, "action")
            arguments = _strings(observation, "arguments")
            builder.entries = [
                item
                for item in builder.entries
                if not (
                    _string(item, "action") == action and _strings(item, "arguments") == arguments
                )
            ]
            continue
        if (
            observation.kind == "command.unclassified"
            and _string(observation, "rule_scope") == "acl.entry"
        ):
            name = _string(observation, "context_identifier")
            if name is not None:
                _append_unique(
                    builders.setdefault(name, _AclBuilder(name)).unsupported, observation
                )

    policies = tuple(_finish_policy(builders[name]) for name in sorted(builders))
    return policies


def _finish_policy(builder: _AclBuilder) -> ResolvedIpv4Acl:
    unsupported = list(builder.unsupported)
    if builder.address_family != "ipv4" or builder.acl_type not in {"standard", "extended"}:
        evidence = builder.definition or (builder.entries[0] if builder.entries else None)
        if evidence is not None:
            _append_unique(unsupported, evidence)

    ordered = _ordered_entries(builder.entries)
    if ordered is None:
        for observation in builder.entries:
            _append_unique(unsupported, observation)
        ordered = ()

    resolved_entries: list[ResolvedAclEntry] = []
    if not unsupported and builder.acl_type in {"standard", "extended"}:
        for observation in ordered:
            resolved = _parse_entry(observation, builder.acl_type)
            if resolved is None:
                _append_unique(unsupported, observation)
            else:
                resolved_entries.append(resolved)

    if unsupported:
        status = AclPolicyStatus.UNSUPPORTED
    elif not resolved_entries:
        status = AclPolicyStatus.EMPTY
    else:
        status = AclPolicyStatus.SUPPORTED
    return ResolvedIpv4Acl(
        name=builder.name,
        acl_type=builder.acl_type or "unknown",
        status=status,
        definition=builder.definition,
        entries=tuple(resolved_entries),
        unsupported_evidence=tuple(unsupported),
    )


def _ordered_entries(
    entries: list[StructuredObservation],
) -> tuple[StructuredObservation, ...] | None:
    if not entries:
        return ()
    sequences = tuple(_integer(item, "sequence") for item in entries)
    if all(sequence is None for sequence in sequences):
        return tuple(entries)
    if any(sequence is None for sequence in sequences):
        return None
    concrete = tuple(sequence for sequence in sequences if sequence is not None)
    if len(set(concrete)) != len(concrete):
        return None
    ordered = sorted(zip(concrete, entries, strict=True), key=lambda item: item[0])
    return tuple(item for _, item in ordered)


def _deny_covers_candidate(
    deny: ResolvedAclEntry,
    candidate: ResolvedAclEntry,
    acl_type: str,
) -> bool:
    if deny.action != "deny":
        return False
    if acl_type == "standard":
        return deny.source.is_any
    if deny.protocol not in {"ip", candidate.protocol}:
        return False
    if not deny.source.is_any or deny.destination is None or not deny.destination.is_any:
        return False
    if deny.protocol == "ip":
        return not deny.source_port and not deny.destination_port
    return (not deny.source_port or deny.source_port == candidate.source_port) and (
        not deny.destination_port or deny.destination_port == candidate.destination_port
    )


def _relationship_issue_is_relevant(
    issue: InterfaceResolutionIssue,
    configuration: ParsedConfiguration,
    attachment_targets: set[str],
) -> bool:
    if issue.code == "unsupported_interface_range":
        return True
    if issue.code == "missing_interface_template":
        return True
    if "template" in issue.code:
        relevant_templates = _templates_with_acl_evidence(configuration)
        return bool(relevant_templates) and _issue_mentions_template(
            issue, configuration, relevant_templates
        )
    if issue.target_interfaces:
        return bool(attachment_targets.intersection(issue.target_interfaces))
    return bool(attachment_targets)


def _templates_with_acl_evidence(configuration: ParsedConfiguration) -> set[str]:
    commands = {item.command_id: item for item in configuration.commands}
    names: set[str] = set()
    for observation in configuration.observations:
        if observation.kind != "interface.access_group" and not (
            observation.kind == "command.unclassified"
            and _string(observation, "rule_scope") == "network.interface_acl"
        ):
            continue
        if not observation.source_command_ids:
            continue
        command = commands.get(observation.source_command_ids[0])
        if (
            command is not None
            and command.context.kind.value == "interface_template"
            and command.context.identifier is not None
        ):
            names.add(command.context.identifier)
    return names


def _issue_mentions_template(
    issue: InterfaceResolutionIssue,
    configuration: ParsedConfiguration,
    relevant_templates: set[str],
) -> bool:
    commands = {item.command_id: item for item in configuration.commands}
    for item in issue.evidence:
        observation = item.observation if isinstance(item, ResolvedInterfaceObservation) else item
        if _string(observation, "template") in relevant_templates:
            return True
        if not observation.source_command_ids:
            continue
        command = commands.get(observation.source_command_ids[0])
        if command is not None and command.context.identifier in relevant_templates:
            return True
    return False


def _parse_entry(observation: StructuredObservation, acl_type: str) -> ResolvedAclEntry | None:
    action = _string(observation, "action")
    arguments = tuple(item.lower() for item in _strings(observation, "arguments"))
    if action not in {"permit", "deny"}:
        return None
    if acl_type == "standard":
        parsed = _parse_address(arguments, 0)
        if parsed is None or parsed[1] != len(arguments):
            return None
        return ResolvedAclEntry(observation, action, "ip", parsed[0], None)
    if not arguments or arguments[0] not in _SUPPORTED_PROTOCOLS:
        return None

    protocol = arguments[0]
    source_result = _parse_address(arguments, 1)
    if source_result is None:
        return None
    source, index = source_result
    source_port: tuple[str, ...] = ()
    if protocol in {"tcp", "udp"}:
        port_result = _parse_port(arguments, index)
        if port_result is not None:
            source_port, index = port_result

    destination_result = _parse_address(arguments, index)
    if destination_result is None:
        return None
    destination, index = destination_result
    destination_port: tuple[str, ...] = ()
    if protocol in {"tcp", "udp"}:
        port_result = _parse_port(arguments, index)
        if port_result is not None:
            destination_port, index = port_result
    if index != len(arguments):
        return None
    return ResolvedAclEntry(
        observation,
        action,
        protocol,
        source,
        destination,
        source_port,
        destination_port,
    )


def _parse_address(tokens: tuple[str, ...], index: int) -> tuple[AclAddress, int] | None:
    if index >= len(tokens):
        return None
    token = tokens[index]
    if token == "any":
        return AclAddress(None, None, True), index + 1
    if token == "host" and index + 1 < len(tokens) and _is_ipv4(tokens[index + 1]):
        return AclAddress(tokens[index + 1], "0.0.0.0", False), index + 2
    if _is_ipv4(token) and index + 1 < len(tokens) and _is_ipv4(tokens[index + 1]):
        wildcard = tokens[index + 1]
        return AclAddress(token, wildcard, wildcard == "255.255.255.255"), index + 2
    return None


def _parse_port(tokens: tuple[str, ...], index: int) -> tuple[tuple[str, ...], int] | None:
    if index >= len(tokens) or tokens[index] not in _PORT_OPERATORS:
        return None
    count = _PORT_OPERATORS[tokens[index]]
    end = index + count + 1
    if end > len(tokens) or any(not _valid_port(item) for item in tokens[index + 1 : end]):
        return None
    return tokens[index:end], end


def _valid_port(value: str) -> bool:
    if value.isdigit():
        return 0 <= int(value) <= 65535
    return value in _NAMED_PORTS


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    return True


def _append_unique(
    items: list[StructuredObservation],
    observation: StructuredObservation,
) -> None:
    if observation not in items:
        items.append(observation)


def _string(observation: StructuredObservation, key: str) -> str | None:
    value = observation.attributes.get(key)
    return value if isinstance(value, str) else None


def _strings(observation: StructuredObservation, key: str) -> tuple[str, ...]:
    value = observation.attributes.get(key)
    return value if isinstance(value, tuple) else ()


def _integer(observation: StructuredObservation, key: str) -> int | None:
    value = observation.attributes.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _boolean(observation: StructuredObservation, key: str) -> bool | None:
    value = observation.attributes.get(key)
    return value if isinstance(value, bool) else None
