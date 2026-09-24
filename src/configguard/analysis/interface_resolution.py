"""Typed, deterministic resolution of supported interface configuration sources."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from configguard.domain import (
    CommandRecord,
    Confidence,
    ConfigurationContext,
    ContextKind,
    ParsedConfiguration,
    StructuredObservation,
)
from configguard.parsing.interface_ranges import canonical_interface_name


class InterfaceFactOrigin(StrEnum):
    """How a resolved fact reached its target interface."""

    DIRECT = "direct"
    RANGE = "range"


@dataclass(frozen=True, slots=True)
class ResolvedInterfaceObservation:
    """One supported observation resolved to one concrete target interface."""

    observation: StructuredObservation
    target_interface: str
    origin: InterfaceFactOrigin
    source_order: int
    source_context: ConfigurationContext
    origin_observation: StructuredObservation | None = None
    confidence: Confidence = Confidence.HIGH


@dataclass(frozen=True, slots=True)
class PortChannelRelationship:
    """A configured member declaration without inferred runtime inheritance."""

    member_interface: str
    logical_interface: str
    observation: ResolvedInterfaceObservation
    logical_definition_present: bool


@dataclass(frozen=True, slots=True)
class InterfaceResolutionIssue:
    """A scoped relationship that cannot be resolved safely."""

    code: str
    reason: str
    rule_scopes: tuple[str, ...]
    evidence: tuple[StructuredObservation | ResolvedInterfaceObservation, ...]
    target_interfaces: tuple[str, ...] = ()
    unsupported_syntax: bool = False


@dataclass(frozen=True, slots=True)
class InterfaceResolution:
    """All resolved facts and conservative relationship limitations."""

    facts: tuple[ResolvedInterfaceObservation, ...]
    issues: tuple[InterfaceResolutionIssue, ...]
    port_channels: tuple[PortChannelRelationship, ...]
    context_targets: tuple[tuple[str, tuple[str, ...]], ...]

    def effective(
        self,
        kind: str,
    ) -> dict[str, ResolvedInterfaceObservation]:
        """Return the last source-ordered fact of ``kind`` for each target."""

        result: dict[str, ResolvedInterfaceObservation] = {}
        for fact in self.facts:
            if fact.observation.kind == kind:
                result[fact.target_interface] = fact
        return result

    def effective_settings(
        self,
        kind: str,
        attribute: str,
    ) -> dict[str, dict[str, ResolvedInterfaceObservation]]:
        """Return last source-ordered facts partitioned by a setting attribute."""

        result: dict[str, dict[str, ResolvedInterfaceObservation]] = {}
        for fact in self.facts:
            if fact.observation.kind != kind:
                continue
            value = fact.observation.attributes.get(attribute)
            if isinstance(value, str):
                result.setdefault(fact.target_interface, {})[value] = fact
        return result

    def relevant_issues(
        self,
        rule_scopes: set[str],
    ) -> tuple[InterfaceResolutionIssue, ...]:
        """Select issues that can change one rule's evaluated interfaces."""

        selected: list[InterfaceResolutionIssue] = []
        for issue in self.issues:
            if not rule_scopes.intersection(issue.rule_scopes):
                continue
            selected.append(issue)
        return tuple(selected)

    def targets_for_context(self, identifier: str | None) -> tuple[str, ...]:
        if identifier is None:
            return ()
        targets = dict(self.context_targets)
        if identifier in targets:
            return targets[identifier]
        return (_canonical_or_original(identifier),)


_INTERFACE_RELATIONSHIP_SCOPES = (
    "layer2.interface_role",
    "layer2.port_security",
    "layer2.dhcp_snooping",
    "layer2.dai",
    "layer2.bpdu_guard",
    "network.interface_acl",
    "routing.rip",
    "routing.ospf",
    "routing.eigrp",
)
_RESOLVABLE_KINDS = {
    "interface.switchport_mode",
    "interface.access_vlan",
    "interface.port_security",
    "interface.dhcp_snooping_trust",
    "interface.arp_inspection_trust",
    "interface.channel_group",
    "interface.spanning_tree_portfast",
    "interface.bpdu_guard",
    "interface.access_group",
    "interface.ipv4_address",
    "routing.rip_auth_mode",
    "routing.rip_key_chain",
    "routing.ospf_interface",
    "routing.ospf_auth_mode",
    "routing.ospf_auth_key",
    "routing.eigrp_auth_mode",
    "routing.eigrp_key_chain",
}
_KIND_SCOPES = {
    "interface.switchport_mode": ("layer2.interface_role",),
    "interface.access_vlan": ("layer2.dhcp_snooping", "layer2.dai"),
    "interface.port_security": ("layer2.port_security",),
    "interface.dhcp_snooping_trust": ("layer2.dhcp_snooping", "layer2.dai"),
    "interface.arp_inspection_trust": ("layer2.dai",),
    "interface.channel_group": _INTERFACE_RELATIONSHIP_SCOPES,
    "interface.spanning_tree_portfast": ("layer2.bpdu_guard",),
    "interface.bpdu_guard": ("layer2.bpdu_guard",),
    "interface.access_group": ("network.interface_acl",),
    "interface.ipv4_address": ("routing.rip", "routing.ospf", "routing.eigrp"),
    "routing.rip_auth_mode": ("routing.rip",),
    "routing.rip_key_chain": ("routing.rip",),
    "routing.ospf_interface": ("routing.ospf",),
    "routing.ospf_auth_mode": ("routing.ospf",),
    "routing.ospf_auth_key": ("routing.ospf",),
    "routing.eigrp_auth_mode": ("routing.eigrp",),
    "routing.eigrp_key_chain": ("routing.eigrp",),
}


def resolve_interface_configuration(configuration: ParsedConfiguration) -> InterfaceResolution:
    """Resolve direct/range facts and detect unsafe template/channel inheritance."""

    commands = {item.command_id: item for item in configuration.commands}
    observation_order = {
        item.observation_id: index for index, item in enumerate(configuration.observations)
    }

    range_targets: dict[str, tuple[str, ...]] = {}
    range_declarations: dict[str, StructuredObservation] = {}
    direct_interfaces: set[str] = set()
    template_names: set[str] = set()
    for observation in configuration.observations:
        command = _source_command(observation, commands)
        if command is None:
            continue
        if observation.kind == "interface.range_declaration":
            identifier = command.context.identifier
            if identifier is not None:
                targets = observation.attributes.get("targets")
                range_targets[identifier] = targets if isinstance(targets, tuple) else ()
                range_declarations[identifier] = observation
        elif observation.kind == "interface.declaration":
            name = observation.attributes.get("name")
            if isinstance(name, str):
                direct_interfaces.add(_canonical_or_original(name))
        elif observation.kind == "interface.template_declaration":
            name = observation.attributes.get("name")
            if isinstance(name, str):
                template_names.add(name)

    facts: list[ResolvedInterfaceObservation] = []
    for observation in configuration.observations:
        if observation.kind not in _RESOLVABLE_KINDS:
            continue
        command = _source_command(observation, commands)
        if command is None or command.context.kind is ContextKind.INTERFACE_TEMPLATE:
            continue
        identifier = command.context.identifier
        if identifier is None:
            continue
        if identifier in range_declarations:
            origin = InterfaceFactOrigin.RANGE
            targets = range_targets.get(identifier, ())
        else:
            origin = InterfaceFactOrigin.DIRECT
            targets = (_canonical_or_original(identifier),)
        for target in targets:
            facts.append(
                ResolvedInterfaceObservation(
                    observation=observation,
                    target_interface=target,
                    origin=origin,
                    source_order=command.location.line_start,
                    source_context=command.context,
                    origin_observation=(
                        range_declarations.get(identifier)
                        if origin is InterfaceFactOrigin.RANGE
                        else None
                    ),
                )
            )
    facts.sort(
        key=lambda item: (item.source_order, observation_order[item.observation.observation_id])
    )

    issues: list[InterfaceResolutionIssue] = []
    for identifier, declaration in range_declarations.items():
        if range_targets.get(identifier):
            continue
        contained_items: list[StructuredObservation] = []
        for item in configuration.observations:
            command = _source_command(item, commands)
            if (
                item.kind in _RESOLVABLE_KINDS
                and command is not None
                and command.context.identifier == identifier
            ):
                contained_items.append(item)
        contained = tuple(contained_items)
        scopes = _scopes_for_observations(contained)
        if contained and scopes:
            issues.append(
                InterfaceResolutionIssue(
                    code="unsupported_interface_range",
                    reason="The interface range could not be expanded safely.",
                    rule_scopes=scopes,
                    evidence=(declaration, *contained),
                    unsupported_syntax=True,
                )
            )

    for observation in configuration.observations:
        if (
            observation.kind != "command.unclassified"
            or observation.attributes.get("rule_scope") != "layer2.interface_relationship"
        ):
            continue
        command = _source_command(observation, commands)
        if command is None or command.context.kind is not ContextKind.INTERFACE:
            continue
        identifier = command.context.identifier
        targets = range_targets.get(
            identifier or "",
            (_canonical_or_original(identifier),) if identifier is not None else (),
        )
        issues.append(
            InterfaceResolutionIssue(
                code="unsupported_interface_relationship",
                reason="An interface relationship command could not be interpreted safely.",
                rule_scopes=_INTERFACE_RELATIONSHIP_SCOPES,
                evidence=(observation,),
                target_interfaces=targets,
                unsupported_syntax=True,
            )
        )

    issues.extend(_template_issues(configuration, commands, range_targets, template_names))

    effective_membership: dict[str, ResolvedInterfaceObservation] = {}
    for fact in facts:
        if fact.observation.kind == "interface.channel_group":
            effective_membership[fact.target_interface] = fact
    relationships: list[PortChannelRelationship] = []
    for member, fact in sorted(effective_membership.items()):
        configured = fact.observation.attributes.get("configured")
        group = fact.observation.attributes.get("group")
        if configured is not True or not isinstance(group, str):
            continue
        logical = f"Port-channel{group}"
        relationship = PortChannelRelationship(
            member_interface=member,
            logical_interface=logical,
            observation=fact,
            logical_definition_present=logical in direct_interfaces,
        )
        relationships.append(relationship)
        issues.append(
            InterfaceResolutionIssue(
                code=(
                    "port_channel_inheritance_unresolved"
                    if relationship.logical_definition_present
                    else "missing_port_channel_definition"
                ),
                reason=(
                    "Port-channel inheritance and runtime membership cannot be established."
                    if relationship.logical_definition_present
                    else "The referenced logical Port-channel definition is absent."
                ),
                rule_scopes=_INTERFACE_RELATIONSHIP_SCOPES,
                evidence=(fact,),
                target_interfaces=(member, logical),
            )
        )

    contexts = tuple(sorted(range_targets.items()))
    return InterfaceResolution(tuple(facts), tuple(issues), tuple(relationships), contexts)


def _template_issues(
    configuration: ParsedConfiguration,
    commands: dict[str, CommandRecord],
    range_targets: dict[str, tuple[str, ...]],
    template_names: set[str],
) -> tuple[InterfaceResolutionIssue, ...]:
    applications = tuple(
        item for item in configuration.observations if item.kind == "interface.template_application"
    )
    effective: dict[tuple[str, str], StructuredObservation] = {}
    for item in applications:
        command = _source_command(item, commands)
        template = item.attributes.get("template")
        if command is None or command.context.identifier is None or not isinstance(template, str):
            continue
        effective[(command.context.identifier, template)] = item

    graph: dict[str, set[str]] = {}
    root_templates: set[str] = set()
    for (source, target), item in effective.items():
        command = _source_command(item, commands)
        if command is None or item.attributes.get("configured") is not True:
            continue
        if command.context.kind is ContextKind.INTERFACE_TEMPLATE:
            graph.setdefault(source, set()).add(target)
        elif command.context.kind is ContextKind.INTERFACE:
            root_templates.add(target)
    cyclic = _cyclic_template_names(graph)
    reachable = _reachable_template_names(root_templates, graph)

    issues: list[InterfaceResolutionIssue] = []
    for (source, target), item in effective.items():
        if item.attributes.get("configured") is not True:
            continue
        command = _source_command(item, commands)
        if command is None:
            continue
        if command.context.kind is ContextKind.INTERFACE_TEMPLATE and source not in reachable:
            continue
        targets = range_targets.get(source, (_canonical_or_original(source),))
        if command.context.kind is ContextKind.INTERFACE_TEMPLATE:
            code = (
                "cyclic_template_relationship" if source in cyclic else "nested_template_unresolved"
            )
            reason = (
                "A cyclic interface-template relationship cannot be resolved safely."
                if source in cyclic
                else "Nested interface-template inheritance is not resolved."
            )
            targets = ()
        elif target not in template_names:
            code = "missing_interface_template"
            reason = "An applied interface template has no matching definition."
        else:
            code = "template_inheritance_unresolved"
            reason = "Interface-template precedence is not established for this configuration."
        issues.append(
            InterfaceResolutionIssue(
                code=code,
                reason=reason,
                rule_scopes=_INTERFACE_RELATIONSHIP_SCOPES,
                evidence=(item,),
                target_interfaces=targets,
            )
        )
    return tuple(issues)


def _reachable_template_names(roots: set[str], graph: dict[str, set[str]]) -> set[str]:
    reachable: set[str] = set()
    pending = list(roots)
    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        reachable.add(name)
        pending.extend(graph.get(name, ()))
    return reachable


def _cyclic_template_names(graph: dict[str, set[str]]) -> set[str]:
    cyclic: set[str] = set()
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str, path: tuple[str, ...]) -> None:
        if name in visiting:
            start = path.index(name) if name in path else 0
            cyclic.update(path[start:])
            return
        if name in visited:
            return
        visiting.add(name)
        for target in graph.get(name, set()):
            visit(target, (*path, name))
        visiting.remove(name)
        visited.add(name)

    for name in graph:
        visit(name, ())
    return cyclic


def _source_command(
    observation: StructuredObservation,
    commands: dict[str, CommandRecord],
) -> CommandRecord | None:
    if not observation.source_command_ids:
        return None
    return commands.get(observation.source_command_ids[0])


def _canonical_or_original(name: str) -> str:
    return canonical_interface_name(name) or name


def _scopes_for_observations(
    observations: tuple[StructuredObservation, ...],
) -> tuple[str, ...]:
    scopes: list[str] = []
    for observation in observations:
        for scope in _KIND_SCOPES.get(observation.kind, ()):
            if scope not in scopes:
                scopes.append(scope)
    return tuple(scopes)
