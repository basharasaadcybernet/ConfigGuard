"""Conservative resolution for supported IPv4 routing authentication syntax."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum

from configguard.analysis.interface_resolution import (
    InterfaceResolution,
    InterfaceResolutionIssue,
    ResolvedInterfaceObservation,
    resolve_interface_configuration,
)
from configguard.domain import CommandRecord, ParsedConfiguration, StructuredObservation
from configguard.parsing.interface_ranges import canonical_interface_name

type RoutingEvidence = StructuredObservation | ResolvedInterfaceObservation


class RoutingAuthenticationStatus(StrEnum):
    """A supported target's statically resolved authentication state."""

    CONFIGURED = "configured"
    WEAK = "weak"
    DISABLED = "disabled"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ResolvedRoutingTarget:
    """One non-passive interface participating in a routing process."""

    interface: str
    process_id: str
    area: str | None
    status: RoutingAuthenticationStatus
    reason: str
    evidence: tuple[RoutingEvidence, ...]


@dataclass(frozen=True, slots=True)
class RoutingAuthenticationResolution:
    """One protocol's active processes, targets, and scoped uncertainty."""

    protocol: str
    processes: tuple[StructuredObservation, ...]
    targets: tuple[ResolvedRoutingTarget, ...]
    issues: tuple[InterfaceResolutionIssue, ...]
    unsupported: tuple[StructuredObservation, ...]
    passive_only: bool = False
    unsupported_process_mode: bool = False


@dataclass(frozen=True, slots=True)
class _Process:
    observation: StructuredObservation
    process_id: str
    start_line: int
    mode: str


@dataclass(slots=True)
class _KeyChain:
    active: bool = False
    current_key: str | None = None
    keys: set[str] | None = None
    secrets: set[str] | None = None

    def __post_init__(self) -> None:
        if self.keys is None:
            self.keys = set()
        if self.secrets is None:
            self.secrets = set()

    @property
    def usable(self) -> bool:
        assert self.keys is not None
        assert self.secrets is not None
        return self.active and bool(self.keys.intersection(self.secrets))


def resolve_routing_authentication(
    configuration: ParsedConfiguration,
    protocol: str,
) -> RoutingAuthenticationResolution:
    """Resolve supported RIP, OSPFv2, or classic IPv4 EIGRP authentication."""

    if protocol not in {"rip", "ospf", "eigrp"}:
        raise ValueError("protocol must be rip, ospf, or eigrp")
    commands = {item.command_id: item for item in configuration.commands}
    processes = _active_processes(configuration, commands, protocol)
    supported_modes = {"rip": "ipv4", "ospf": "ospfv2", "eigrp": "classic"}
    unsupported_mode = any(item.mode != supported_modes[protocol] for item in processes)
    supported_processes = tuple(
        item
        for item in processes
        if (protocol, item.mode) in {("rip", "ipv4"), ("ospf", "ospfv2"), ("eigrp", "classic")}
    )
    interface_resolution = resolve_interface_configuration(configuration)
    facts = interface_resolution.facts
    key_chains = _key_chains(configuration, commands)
    targets: list[ResolvedRoutingTarget] = []
    associated: set[str] = set()
    passive_count = 0

    for process in supported_processes:
        participants = _participants(process, protocol, configuration, commands, facts)
        passive = _passive_interfaces(process, protocol, configuration, commands)
        for interface, area, association_evidence in participants:
            associated.add(interface)
            if _is_passive(interface, passive):
                passive_count += 1
                continue
            target = _target(
                protocol,
                process,
                interface,
                area,
                association_evidence,
                facts,
                key_chains,
                configuration,
                commands,
            )
            targets.append(target)

    referenced_chains = {
        value
        for target in targets
        for evidence in target.evidence
        for value in [_string(_structured(evidence), "key_chain")]
        if value is not None
    }
    unsupported = _unsupported(
        configuration,
        commands,
        protocol,
        associated,
        referenced_chains,
        interface_resolution,
    )
    issues = _issues(interface_resolution.issues, protocol, associated)
    return RoutingAuthenticationResolution(
        protocol=protocol,
        processes=tuple(item.observation for item in supported_processes),
        targets=tuple(targets),
        issues=issues,
        unsupported=unsupported,
        passive_only=bool(associated) and passive_count == len(associated),
        unsupported_process_mode=unsupported_mode,
    )


def _active_processes(
    configuration: ParsedConfiguration,
    commands: dict[str, CommandRecord],
    protocol: str,
) -> tuple[_Process, ...]:
    active: dict[str, _Process] = {}
    for item in configuration.observations:
        if item.kind != "routing.process" or _string(item, "protocol") != protocol:
            continue
        process_id = _string(item, "process_id")
        command = _command(item, commands)
        if process_id is None or command is None:
            continue
        if _boolean(item, "configured") is False:
            active.pop(process_id, None)
            continue
        previous = active.get(process_id)
        active[process_id] = _Process(
            observation=item,
            process_id=process_id,
            start_line=previous.start_line if previous is not None else command.location.line_start,
            mode=_string(item, "mode") or "other",
        )
    return tuple(active[key] for key in sorted(active))


def _participants(
    process: _Process,
    protocol: str,
    configuration: ParsedConfiguration,
    commands: dict[str, CommandRecord],
    facts: tuple[ResolvedInterfaceObservation, ...],
) -> tuple[tuple[str, str | None, tuple[RoutingEvidence, ...]], ...]:
    addresses = _effective_facts(facts, "interface.ipv4_address")
    explicit = _effective_ospf_associations(facts, process.process_id) if protocol == "ospf" else {}
    networks = _effective_networks(configuration, commands, process, protocol)
    result: dict[str, tuple[str | None, tuple[RoutingEvidence, ...]]] = {}
    for interface, fact in addresses.items():
        if _boolean(fact.observation, "configured") is not True:
            continue
        address = _ipv4_address(fact.observation)
        if address is None:
            continue
        matches = tuple(
            network for network in networks if _network_matches(address, network, protocol)
        )
        if not matches:
            continue
        areas = {_string(network, "area") for network in matches}
        area = next(iter(areas)) if len(areas) == 1 else None
        result[interface] = (area, (fact, *matches))
    for interface, fact in explicit.items():
        if _boolean(fact.observation, "configured") is True:
            result[interface] = (_string(fact.observation, "area"), (fact,))
        else:
            result.pop(interface, None)
    return tuple(
        (interface, area, evidence) for interface, (area, evidence) in sorted(result.items())
    )


def _effective_networks(
    configuration: ParsedConfiguration,
    commands: dict[str, CommandRecord],
    process: _Process,
    protocol: str,
) -> tuple[StructuredObservation, ...]:
    effective: dict[tuple[str | None, str | None, str | None], StructuredObservation] = {}
    for item in configuration.observations:
        if (
            item.kind != "routing.network"
            or _string(item, "protocol") != protocol
            or _string(item, "process_id") != process.process_id
        ):
            continue
        command = _command(item, commands)
        if command is None or command.location.line_start < process.start_line:
            continue
        key = (_string(item, "network"), _string(item, "wildcard"), _string(item, "area"))
        effective[key] = item
    return tuple(item for item in effective.values() if _boolean(item, "configured") is True)


def _passive_interfaces(
    process: _Process,
    protocol: str,
    configuration: ParsedConfiguration,
    commands: dict[str, CommandRecord],
) -> dict[str, bool]:
    result: dict[str, bool] = {}
    for item in configuration.observations:
        if (
            item.kind != "routing.passive_interface"
            or _string(item, "protocol") != protocol
            or _string(item, "process_id") != process.process_id
        ):
            continue
        command = _command(item, commands)
        name = _string(item, "interface")
        if command is not None and command.location.line_start >= process.start_line and name:
            result[name] = _boolean(item, "configured") is True
    return result


def _is_passive(interface: str, settings: dict[str, bool]) -> bool:
    canonical_settings = {
        canonical_interface_name(name) or name: value
        for name, value in settings.items()
        if name != "default"
    }
    if interface in canonical_settings:
        return canonical_settings[interface]
    return settings.get("default", False)


def _target(
    protocol: str,
    process: _Process,
    interface: str,
    area: str | None,
    association: tuple[RoutingEvidence, ...],
    facts: tuple[ResolvedInterfaceObservation, ...],
    key_chains: dict[str, _KeyChain],
    configuration: ParsedConfiguration,
    commands: dict[str, CommandRecord],
) -> ResolvedRoutingTarget:
    if protocol == "rip":
        return _rip_target(
            process, interface, association, facts, key_chains, configuration, commands
        )
    if protocol == "ospf":
        return _ospf_target(process, interface, area, association, facts, configuration, commands)
    return _eigrp_target(process, interface, association, facts, key_chains)


def _rip_target(
    process: _Process,
    interface: str,
    association: tuple[RoutingEvidence, ...],
    facts: tuple[ResolvedInterfaceObservation, ...],
    key_chains: dict[str, _KeyChain],
    configuration: ParsedConfiguration,
    commands: dict[str, CommandRecord],
) -> ResolvedRoutingTarget:
    version = _last_process_observation(configuration, commands, process, "routing.rip_version")
    mode = _effective_facts(facts, "routing.rip_auth_mode").get(interface)
    chain = _effective_facts(facts, "routing.rip_key_chain").get(interface)
    evidence = _unique((*association, version, mode, chain))
    if version is None or _boolean(version, "configured") is not True:
        return _resolved(
            interface,
            process,
            None,
            RoutingAuthenticationStatus.UNKNOWN,
            "RIPv2 is not explicitly established.",
            evidence,
        )
    if _string(version, "version") != "2":
        return _resolved(
            interface,
            process,
            None,
            RoutingAuthenticationStatus.WEAK,
            "The active RIP process is not explicitly restricted to version 2.",
            evidence,
        )
    if (
        mode is None
        or chain is None
        or _boolean(mode.observation, "configured") is not True
        or _boolean(chain.observation, "configured") is not True
    ):
        return _resolved(
            interface,
            process,
            None,
            RoutingAuthenticationStatus.UNKNOWN,
            "The RIP authentication mode or key-chain reference is not fully established.",
            evidence,
        )
    chain_name = _string(chain.observation, "key_chain")
    if chain_name is None or not key_chains.get(chain_name, _KeyChain()).usable:
        return _resolved(
            interface,
            process,
            None,
            RoutingAuthenticationStatus.UNKNOWN,
            "The referenced RIP key chain has no supported active key secret.",
            evidence,
        )
    status = (
        RoutingAuthenticationStatus.WEAK
        if _string(mode.observation, "mode") == "text"
        else RoutingAuthenticationStatus.CONFIGURED
    )
    reason = (
        "Plain-text RIP authentication is configured."
        if status is RoutingAuthenticationStatus.WEAK
        else "RIPv2 MD5 authentication is configured with a supported key chain."
    )
    return _resolved(interface, process, None, status, reason, evidence)


def _ospf_target(
    process: _Process,
    interface: str,
    area: str | None,
    association: tuple[RoutingEvidence, ...],
    facts: tuple[ResolvedInterfaceObservation, ...],
    configuration: ParsedConfiguration,
    commands: dict[str, CommandRecord],
) -> ResolvedRoutingTarget:
    interface_mode = _effective_facts(facts, "routing.ospf_auth_mode").get(interface)
    mode: str | None = None
    mode_evidence: RoutingEvidence | None = interface_mode
    if interface_mode is not None and _boolean(interface_mode.observation, "configured") is True:
        mode = _string(interface_mode.observation, "mode")
    else:
        area_auth = _last_area_auth(configuration, commands, process, area)
        mode_evidence = area_auth
        if area_auth is not None and _boolean(area_auth, "configured") is True:
            mode = _string(area_auth, "mode")
    keys = [
        item
        for item in facts
        if item.target_interface == interface and item.observation.kind == "routing.ospf_auth_key"
    ]
    effective_keys: dict[tuple[str | None, str | None], ResolvedInterfaceObservation] = {}
    for item in keys:
        effective_keys[
            (_string(item.observation, "key_type"), _string(item.observation, "key_id"))
        ] = item
    evidence = _unique((*association, mode_evidence, *effective_keys.values()))
    if mode == "null":
        return _resolved(
            interface,
            process,
            area,
            RoutingAuthenticationStatus.DISABLED,
            "OSPF authentication is explicitly disabled on the interface.",
            evidence,
        )
    if mode is None:
        return _resolved(
            interface,
            process,
            area,
            RoutingAuthenticationStatus.UNKNOWN,
            "No supported effective OSPF authentication mode is established.",
            evidence,
        )
    required = "message_digest" if mode == "message_digest" else "simple"
    usable = any(
        _boolean(item.observation, "configured") is True and key[0] == required
        for key, item in effective_keys.items()
    )
    if not usable:
        return _resolved(
            interface,
            process,
            area,
            RoutingAuthenticationStatus.UNKNOWN,
            "The effective OSPF authentication mode lacks a supported matching key.",
            evidence,
        )
    status = (
        RoutingAuthenticationStatus.WEAK
        if mode == "simple"
        else RoutingAuthenticationStatus.CONFIGURED
    )
    reason = (
        "OSPF simple-password authentication is configured."
        if status is RoutingAuthenticationStatus.WEAK
        else "OSPF message-digest authentication is configured with a supported key."
    )
    return _resolved(interface, process, area, status, reason, evidence)


def _eigrp_target(
    process: _Process,
    interface: str,
    association: tuple[RoutingEvidence, ...],
    facts: tuple[ResolvedInterfaceObservation, ...],
    key_chains: dict[str, _KeyChain],
) -> ResolvedRoutingTarget:
    modes = _effective_facts_by_process(facts, "routing.eigrp_auth_mode", process.process_id)
    chains = _effective_facts_by_process(facts, "routing.eigrp_key_chain", process.process_id)
    mode = modes.get(interface)
    chain = chains.get(interface)
    evidence = _unique((*association, mode, chain))
    if (
        mode is None
        or chain is None
        or _boolean(mode.observation, "configured") is not True
        or _boolean(chain.observation, "configured") is not True
    ):
        return _resolved(
            interface,
            process,
            None,
            RoutingAuthenticationStatus.UNKNOWN,
            "Classic EIGRP authentication mode or key-chain evidence is incomplete.",
            evidence,
        )
    chain_name = _string(chain.observation, "key_chain")
    if chain_name is None or not key_chains.get(chain_name, _KeyChain()).usable:
        return _resolved(
            interface,
            process,
            None,
            RoutingAuthenticationStatus.UNKNOWN,
            "The referenced EIGRP key chain has no supported active key secret.",
            evidence,
        )
    return _resolved(
        interface,
        process,
        None,
        RoutingAuthenticationStatus.CONFIGURED,
        "Classic IPv4 EIGRP MD5 authentication is configured with a supported key chain.",
        evidence,
    )


def _key_chains(
    configuration: ParsedConfiguration,
    commands: dict[str, CommandRecord],
) -> dict[str, _KeyChain]:
    chains: dict[str, _KeyChain] = {}
    for item in configuration.observations:
        if item.kind not in {
            "authentication.key_chain",
            "authentication.key_chain_key",
            "authentication.key_chain_secret",
        }:
            continue
        name = _string(item, "name") or _string(item, "key_chain")
        if name is None:
            continue
        state = chains.setdefault(name, _KeyChain())
        if item.kind == "authentication.key_chain":
            state.active = _boolean(item, "configured") is not False
            state.current_key = None
            if not state.active:
                assert state.keys is not None and state.secrets is not None
                state.keys.clear()
                state.secrets.clear()
        elif item.kind == "authentication.key_chain_key":
            key_id = _string(item, "key_id")
            if key_id is None:
                continue
            assert state.keys is not None and state.secrets is not None
            if _boolean(item, "configured") is True:
                state.keys.add(key_id)
                state.current_key = key_id
            else:
                state.keys.discard(key_id)
                state.secrets.discard(key_id)
                state.current_key = None
        elif state.current_key is not None:
            assert state.secrets is not None
            if _boolean(item, "configured") is True:
                state.secrets.add(state.current_key)
            else:
                state.secrets.discard(state.current_key)
    return chains


def _last_process_observation(
    configuration: ParsedConfiguration,
    commands: dict[str, CommandRecord],
    process: _Process,
    kind: str,
) -> StructuredObservation | None:
    result = None
    for item in configuration.observations:
        command = _command(item, commands)
        if (
            item.kind == kind
            and _string(item, "process_id") == process.process_id
            and command is not None
            and command.location.line_start >= process.start_line
        ):
            result = item
    return result


def _last_area_auth(
    configuration: ParsedConfiguration,
    commands: dict[str, CommandRecord],
    process: _Process,
    area: str | None,
) -> StructuredObservation | None:
    result = None
    for item in configuration.observations:
        command = _command(item, commands)
        if (
            item.kind == "routing.ospf_area_auth"
            and _string(item, "process_id") == process.process_id
            and _string(item, "area") == area
            and command is not None
            and command.location.line_start >= process.start_line
        ):
            result = item
    return result


def _effective_facts(
    facts: tuple[ResolvedInterfaceObservation, ...],
    kind: str,
) -> dict[str, ResolvedInterfaceObservation]:
    result: dict[str, ResolvedInterfaceObservation] = {}
    for item in facts:
        if item.observation.kind == kind:
            result[item.target_interface] = item
    return result


def _effective_facts_by_process(
    facts: tuple[ResolvedInterfaceObservation, ...],
    kind: str,
    process_id: str,
) -> dict[str, ResolvedInterfaceObservation]:
    result: dict[str, ResolvedInterfaceObservation] = {}
    for item in facts:
        if item.observation.kind == kind and _string(item.observation, "process_id") == process_id:
            result[item.target_interface] = item
    return result


def _effective_ospf_associations(
    facts: tuple[ResolvedInterfaceObservation, ...],
    process_id: str,
) -> dict[str, ResolvedInterfaceObservation]:
    return _effective_facts_by_process(facts, "routing.ospf_interface", process_id)


def _network_matches(
    address: ipaddress.IPv4Address, item: StructuredObservation, protocol: str
) -> bool:
    network_text = _string(item, "network")
    wildcard_text = _string(item, "wildcard")
    if network_text is None:
        return False
    try:
        network = ipaddress.IPv4Address(network_text)
        if wildcard_text is not None:
            wildcard = int(ipaddress.IPv4Address(wildcard_text))
            mask = (~wildcard) & 0xFFFFFFFF
            return int(address) & mask == int(network) & mask
        if protocol == "rip" or protocol == "eigrp":
            first = int(str(network).split(".")[0])
            prefix = 8 if first < 128 else 16 if first < 192 else 24
            return address in ipaddress.IPv4Network(f"{network}/{prefix}", strict=False)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError):
        return False
    return False


def _ipv4_address(item: StructuredObservation) -> ipaddress.IPv4Address | None:
    address = _string(item, "address")
    mask = _string(item, "mask")
    if address is None or mask is None:
        return None
    try:
        ipaddress.IPv4Network(f"{address}/{mask}", strict=False)
        return ipaddress.IPv4Address(address)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return None


def _unsupported(
    configuration: ParsedConfiguration,
    commands: dict[str, CommandRecord],
    protocol: str,
    associated: set[str],
    referenced_chains: set[str],
    interface_resolution: InterfaceResolution,
) -> tuple[StructuredObservation, ...]:
    result: list[StructuredObservation] = []
    scopes = {f"routing.{protocol}", "routing.interface_address"}
    for item in configuration.observations:
        if item.kind != "command.unclassified":
            continue
        scope = _string(item, "rule_scope")
        command = _command(item, commands)
        if command is None:
            continue
        if scope in scopes:
            identifier = command.context.identifier
            if (
                command.context.kind.value.startswith("interface")
                and associated
                and not associated.intersection(
                    interface_resolution.targets_for_context(identifier)
                )
            ):
                continue
            result.append(item)
        elif scope == "routing.key_chain":
            identifier = command.context.identifier or ""
            name = (
                identifier.split(maxsplit=2)[2]
                if identifier.lower().startswith("key chain ")
                else None
            )
            if name in referenced_chains:
                result.append(item)
    return tuple(result)


def _issues(
    issues: tuple[InterfaceResolutionIssue, ...],
    protocol: str,
    associated: set[str],
) -> tuple[InterfaceResolutionIssue, ...]:
    result: list[InterfaceResolutionIssue] = []
    for issue in issues:
        if f"routing.{protocol}" not in issue.rule_scopes:
            continue
        if (
            issue.target_interfaces
            and associated
            and not associated.intersection(issue.target_interfaces)
        ):
            continue
        result.append(issue)
    return tuple(result)


def _resolved(
    interface: str,
    process: _Process,
    area: str | None,
    status: RoutingAuthenticationStatus,
    reason: str,
    evidence: tuple[RoutingEvidence, ...],
) -> ResolvedRoutingTarget:
    return ResolvedRoutingTarget(interface, process.process_id, area, status, reason, evidence)


def _unique(items: tuple[RoutingEvidence | None, ...]) -> tuple[RoutingEvidence, ...]:
    result: list[RoutingEvidence] = []
    for item in items:
        if item is not None and item not in result:
            result.append(item)
    return tuple(result)


def _structured(item: RoutingEvidence) -> StructuredObservation:
    return item.observation if isinstance(item, ResolvedInterfaceObservation) else item


def _command(
    item: StructuredObservation,
    commands: dict[str, CommandRecord],
) -> CommandRecord | None:
    return commands.get(item.source_command_ids[0]) if item.source_command_ids else None


def _string(item: StructuredObservation, key: str) -> str | None:
    value = item.attributes.get(key)
    return value if isinstance(value, str) else None


def _boolean(item: StructuredObservation, key: str) -> bool | None:
    value = item.attributes.get(key)
    return value if isinstance(value, bool) else None
