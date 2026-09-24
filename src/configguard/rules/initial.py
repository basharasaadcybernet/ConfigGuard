"""The deterministic security checks approved through Phase 5B."""

from __future__ import annotations

from configguard.domain import (
    AssessmentOutcome,
    Confidence,
    EvidenceReference,
    ParsedConfiguration,
    ParseStatus,
    Severity,
    StructuredObservation,
)
from configguard.rules.contracts import (
    RuleCategory,
    RuleEvaluation,
    RuleMetadata,
    SecurityRule,
)
from configguard.rules.layer2 import layer2_rules

_RFC_854 = "https://www.rfc-editor.org/rfc/rfc854"
_RFC_9110 = "https://www.rfc-editor.org/rfc/rfc9110"
_RFC_4253 = "https://www.rfc-editor.org/rfc/rfc4253"
_RFC_3414 = "https://www.rfc-editor.org/rfc/rfc3414"
_RFC_3415 = "https://www.rfc-editor.org/rfc/rfc3415"
_CISCO_VTY_ACCESS = (
    "https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/"
    "application-services/b-application-services/m-bba-vrf-aware-access-class-line.html"
)
_CISCO_PASSWORD_SECURITY = (
    "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/"
    "15-mt/sec-usr-cfg-15-mt-book/sec-cfg-sec-4cli.html"
)
_CISCO_AAA_LOGIN = (
    "https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/security-vpn/security-vpn/"
    "m_sec-cfg-authentifcn-0.html"
)
_REACHABILITY_LIMITATION = (
    "Configuration evidence does not establish network reachability or Internet exposure."
)


class VtyTelnetRule:
    """Detect effective VTY ranges that explicitly permit Telnet."""

    metadata = RuleMetadata(
        rule_id="CG-MGMT-001",
        title="Insecure VTY transport",
        category=RuleCategory.MANAGEMENT_PLANE,
        description="Evaluates explicit inbound VTY transport configuration.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        declarations = tuple(
            item
            for item in _observations(configuration, "line.declaration")
            if _string(item, "line_type") == "vty"
        )
        transports = tuple(
            item
            for item in _observations(configuration, "line.transport")
            if _string(item, "direction") == "input"
        )
        evidence = _references(transports)

        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "The VTY transport state cannot be established from an incomplete configuration.",
                evidence,
            )
        if _has_unsupported_rule_scope(configuration, "line.transport"):
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported line configuration prevents a reliable VTY transport conclusion.",
                evidence,
            )
        if not declarations:
            return _unknown(
                self.metadata.rule_id,
                "No supported VTY line declaration was available for evaluation.",
                (),
            )

        declared_lines: set[int] = set()
        declaration_by_line: dict[int, StructuredObservation] = {}
        unsupported_declarations: list[StructuredObservation] = []
        for declaration in declarations:
            line_numbers = _vty_declaration_numbers(declaration)
            if line_numbers is None:
                unsupported_declarations.append(declaration)
                continue
            for line_number in line_numbers:
                declared_lines.add(line_number)
                declaration_by_line[line_number] = declaration

        effective: dict[int, StructuredObservation] = {}
        unsupported_transports: list[StructuredObservation] = []
        for transport in transports:
            line_numbers = _vty_identifier_numbers(_string(transport, "line"))
            if line_numbers is None:
                if (_string(transport, "line") or "").startswith("vty"):
                    unsupported_transports.append(transport)
                continue
            for line_number in line_numbers:
                effective[line_number] = transport

        if unsupported_declarations or unsupported_transports:
            return _unsupported(
                self.metadata.rule_id,
                "At least one VTY range could not be resolved safely.",
                _references(tuple((*unsupported_declarations, *unsupported_transports))),
            )

        telnet: list[StructuredObservation] = []
        uncertain: list[StructuredObservation] = []
        unsupported: list[StructuredObservation] = []
        effective_evidence: list[StructuredObservation] = []
        for line_number in sorted(declared_lines):
            effective_transport = effective.get(line_number)
            if effective_transport is None:
                _append_unique(uncertain, declaration_by_line[line_number])
                continue
            _append_unique(effective_evidence, effective_transport)
            configured = _boolean(effective_transport, "configured")
            protocols = _strings(effective_transport, "protocols")
            if configured is False or not protocols:
                _append_unique(uncertain, effective_transport)
            elif "telnet" in protocols or "all" in protocols:
                _append_unique(telnet, effective_transport)
            elif protocols == ("none",) or set(protocols) <= {"ssh"}:
                continue
            else:
                _append_unique(unsupported, effective_transport)

        if telnet:
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.CONFIRMED_INSECURE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                summary="At least one VTY range explicitly permits Telnet management access.",
                impact=(
                    "Telnet does not protect management credentials or session traffic with "
                    "SSH-style encryption."
                ),
                recommendation=(
                    "Remove Telnet from every applicable VTY range, permit SSH only, and apply "
                    "least-privilege source restrictions."
                ),
                evidence=_references(tuple(telnet)),
                references=(_RFC_854,),
                limitations=(_REACHABILITY_LIMITATION,),
            )
        if unsupported:
            return _unsupported(
                self.metadata.rule_id,
                "At least one VTY range uses an unsupported inbound transport value.",
                _references(tuple(unsupported)),
            )
        if uncertain:
            return _unknown(
                self.metadata.rule_id,
                "One or more VTY ranges depend on defaults or unsupported transport values.",
                _references(tuple(uncertain)),
            )
        return _secure(
            self.metadata.rule_id,
            "Every supported VTY range explicitly excludes Telnet inbound transport.",
            _references(tuple(effective_evidence)),
            (_REACHABILITY_LIMITATION,),
        )


class PlaintextHttpManagementRule:
    """Resolve the last supported explicit state of the plaintext HTTP server."""

    metadata = RuleMetadata(
        rule_id="CG-MGMT-006",
        title="Plaintext HTTP management service",
        category=RuleCategory.MANAGEMENT_PLANE,
        description="Evaluates explicit ip http server enable and disable commands.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        observations = tuple(
            item
            for item in _observations(configuration, "management.http_setting")
            if _string(item, "setting") == "server"
        )
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "The effective HTTP service state cannot be established from incomplete input.",
                _references(observations),
            )
        if not observations:
            return _unknown(
                self.metadata.rule_id,
                "No explicit supported plaintext HTTP service state was observed.",
                (),
            )
        effective = observations[-1]
        enabled = _boolean(effective, "enabled")
        if enabled is True:
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.CONFIRMED_INSECURE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                summary="The effective supported configuration explicitly enables HTTP management.",
                impact=(
                    "Plaintext HTTP does not provide transport encryption for management traffic."
                ),
                recommendation=(
                    "Disable the plaintext HTTP server. If browser management is required, use "
                    "HTTPS with approved authentication and source restrictions."
                ),
                evidence=_references((effective,)),
                references=(_RFC_9110,),
                limitations=(_REACHABILITY_LIMITATION,),
            )
        if enabled is False:
            return _secure(
                self.metadata.rule_id,
                "The effective supported configuration explicitly disables plaintext HTTP.",
                _references((effective,)),
                (_REACHABILITY_LIMITATION,),
            )
        return _unknown(
            self.metadata.rule_id,
            "The explicit HTTP service state could not be interpreted safely.",
            _references((effective,)),
        )


class SshVersionOneRule:
    """Detect an explicit effective SSH protocol version 1 selection."""

    metadata = RuleMetadata(
        rule_id="CG-MGMT-002",
        title="SSH protocol version 1 configured",
        category=RuleCategory.MANAGEMENT_PLANE,
        description="Evaluates explicit ip ssh version configuration only.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        observations = tuple(
            item
            for item in _observations(configuration, "management.ssh_setting")
            if _string(item, "setting") == "version"
        )
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "The effective SSH version cannot be established from incomplete input.",
                _references(observations),
            )
        if not observations:
            return _unknown(
                self.metadata.rule_id,
                "No explicit supported SSH protocol version selection was observed.",
                (),
            )
        effective = observations[-1]
        if _boolean(effective, "configured") is False:
            return _unknown(
                self.metadata.rule_id,
                "The SSH version command is negated, so behavior depends on platform defaults.",
                _references((effective,)),
            )
        arguments = _strings(effective, "arguments")
        if arguments == ("1",):
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.CONFIRMED_INSECURE,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                summary="The effective supported configuration explicitly selects SSH version 1.",
                impact="SSH version 1 is obsolete and does not provide SSHv2 security properties.",
                recommendation=(
                    "Configure SSH version 2 and validate supported cryptographic algorithms "
                    "against the organization's device baseline."
                ),
                evidence=_references((effective,)),
                references=(_RFC_4253,),
                limitations=(
                    "The version command alone does not prove that the SSH service is reachable.",
                ),
            )
        if arguments == ("2",):
            return _secure(
                self.metadata.rule_id,
                "The effective supported configuration explicitly selects SSH version 2.",
                _references((effective,)),
                ("This rule does not evaluate SSH service reachability, keys, or algorithms.",),
            )
        return _unsupported(
            self.metadata.rule_id,
            "The explicit SSH version value is unsupported by this rule.",
            _references((effective,)),
        )


class SnmpCommunityConfigurationRule:
    """Identify effective SNMP community-based management configuration."""

    metadata = RuleMetadata(
        rule_id="CG-SNMP-001",
        title="SNMP community-based management configured",
        category=RuleCategory.SNMP,
        description="Evaluates effective supported SNMP community declarations.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        effective = _effective_communities(configuration)
        evidence = _references(tuple(effective.values()))
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "SNMP community state cannot be established from incomplete input.",
                evidence,
            )
        active = tuple(item for item in effective.values() if _boolean(item, "configured") is True)
        if not active:
            if _has_unsupported_rule_scope(configuration, "snmp.community"):
                return _unsupported(
                    self.metadata.rule_id,
                    "Unsupported SNMP community syntax prevents a complete community conclusion.",
                    (),
                )
            return _not_applicable(
                self.metadata.rule_id,
                "No effective supported SNMP community declaration was observed.",
            )

        has_write = any(_string(item, "access_mode") == "rw" for item in active)
        severity = Severity.MEDIUM if has_write else Severity.LOW
        modes = tuple(sorted({_string(item, "access_mode") or "unknown" for item in active}))
        return RuleEvaluation(
            rule_id=self.metadata.rule_id,
            outcome=AssessmentOutcome.POTENTIAL_RISK,
            severity=severity,
            confidence=Confidence.HIGH,
            summary=(
                "The configuration contains effective SNMP community-based management "
                f"declarations with observed modes: {', '.join(modes)}."
            ),
            impact=(
                "Community-based SNMP does not provide the authenticated and private user-based "
                "security model available in SNMPv3."
            ),
            recommendation=(
                "Migrate to an approved SNMPv3 authentication/privacy design; during migration, "
                "restrict sources and use read-only access wherever possible."
            ),
            evidence=_references(active),
            references=(_RFC_3414,),
            limitations=(_REACHABILITY_LIMITATION,),
        )


class SnmpCommunityAccessRestrictionRule:
    """Assess explicit SNMP community ACL references without topology claims."""

    metadata = RuleMetadata(
        rule_id="CG-SNMP-002",
        title="SNMP community source restriction",
        category=RuleCategory.SNMP,
        description="Checks supported community declarations for resolvable ACL references.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        effective = _effective_communities(configuration)
        active = tuple(item for item in effective.values() if _boolean(item, "configured") is True)
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "SNMP restriction state cannot be established from incomplete input.",
                _references(active),
            )
        if _has_unsupported_rule_scope(configuration, "snmp.community"):
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported SNMP community syntax prevents an applicability conclusion.",
                _references(active),
            )
        if not active:
            return _not_applicable(
                self.metadata.rule_id,
                "No effective supported SNMP community requires source-restriction evaluation.",
            )
        if any(_string(item, "access_mode") not in {"ro", "rw"} for item in active):
            return _unsupported(
                self.metadata.rule_id,
                "At least one community declaration has unsupported permission syntax.",
                _references(active),
            )

        acl_observations = tuple(
            item
            for item in configuration.observations
            if item.kind in {"acl.definition", "acl.entry"}
        )
        acl_names = {
            name
            for item in acl_observations
            if (name := _string(item, "name") or _string(item, "access_list")) is not None
        }
        missing = tuple(item for item in active if _string(item, "access_list") is None)
        unresolved = tuple(
            item
            for item in active
            if (reference := _string(item, "access_list")) is not None
            and reference not in acl_names
        )
        if unresolved:
            return _unknown(
                self.metadata.rule_id,
                "At least one SNMP community references an ACL not present in the parsed input.",
                _references(unresolved),
            )
        if missing:
            has_write = any(_string(item, "access_mode") == "rw" for item in missing)
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.POTENTIAL_RISK,
                severity=Severity.MEDIUM if has_write else Severity.LOW,
                confidence=Confidence.HIGH,
                summary=(
                    "At least one effective SNMP community has no supported source ACL reference."
                ),
                impact=(
                    "The configuration does not show a community-specific source-address "
                    "restriction; actual reachability may still be constrained elsewhere."
                ),
                recommendation=(
                    "Attach a least-privilege source ACL to each retained community and prefer "
                    "migration to authenticated, private SNMPv3 management."
                ),
                evidence=_references(missing),
                references=(_RFC_3415,),
                limitations=(
                    "This rule does not evaluate topology, ACL reachability, or external controls.",
                ),
            )

        referenced_names = {
            reference for item in active if (reference := _string(item, "access_list")) is not None
        }
        matching_acl_evidence = tuple(
            item
            for item in acl_observations
            if (_string(item, "name") or _string(item, "access_list")) in referenced_names
        )
        return _secure(
            self.metadata.rule_id,
            "Every effective supported SNMP community references an ACL present in the input.",
            _references((*active, *matching_acl_evidence)),
            ("ACL presence does not prove effective reachability, correctness, or topology.",),
        )


class VtySourceRestrictionRule:
    """Evaluate effective inbound VTY access-class configuration and its ACL."""

    metadata = RuleMetadata(
        rule_id="CG-MGMT-003",
        title="VTY inbound source restriction",
        category=RuleCategory.MANAGEMENT_PLANE,
        description="Evaluates effective inbound VTY access-class references and ACL scope.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        declarations = tuple(
            item
            for item in _observations(configuration, "line.declaration")
            if _string(item, "line_type") == "vty"
        )
        inbound = tuple(
            item
            for item in _observations(configuration, "line.access_class")
            if _string(item, "direction") == "in"
        )
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "The VTY source-restriction state cannot be established from incomplete input.",
                _references(inbound),
            )
        if _has_unsupported_rule_scope(configuration, "line.access_class"):
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported VTY access-class syntax prevents a reliable conclusion.",
                _references(inbound),
            )
        if not declarations:
            return _unknown(
                self.metadata.rule_id,
                "No supported VTY line declaration was available for evaluation.",
                (),
            )

        declared, declaration_evidence, declaration_error = _effective_vty_declarations(
            declarations
        )
        if declaration_error:
            return _unsupported(
                self.metadata.rule_id,
                "At least one VTY range could not be resolved safely.",
                _references(declarations),
            )

        effective: dict[int, StructuredObservation] = {}
        for restriction in inbound:
            line_numbers = _vty_identifier_numbers(_string(restriction, "line"))
            if line_numbers is None:
                if (_string(restriction, "line") or "").startswith("vty"):
                    return _unsupported(
                        self.metadata.rule_id,
                        "At least one inbound VTY access-class range could not be resolved.",
                        _references((restriction,)),
                    )
                continue
            for line_number in line_numbers:
                effective[line_number] = restriction

        missing: list[StructuredObservation] = []
        removed: list[StructuredObservation] = []
        active: list[StructuredObservation] = []
        for line_number in sorted(declared):
            current_restriction = effective.get(line_number)
            if current_restriction is None:
                _append_unique(missing, declaration_evidence[line_number])
            elif _boolean(current_restriction, "configured") is False:
                _append_unique(removed, current_restriction)
            else:
                _append_unique(active, current_restriction)

        unsupported_modifiers = tuple(
            item for item in active if _strings(item, "modifiers") not in {(), ("vrf-also",)}
        )
        if unsupported_modifiers:
            return _unsupported(
                self.metadata.rule_id,
                "An inbound VTY access-class uses unsupported trailing syntax.",
                _references(unsupported_modifiers),
            )

        if removed:
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.POTENTIAL_RISK,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                summary="An effective VTY range explicitly removes its inbound source ACL.",
                impact=(
                    "The VTY configuration does not apply a line-level inbound source filter; "
                    "other controls and actual reachability remain outside this rule."
                ),
                recommendation=(
                    "Apply a least-privilege inbound access-class to every VTY range and verify "
                    "the referenced ACL against the approved management sources."
                ),
                evidence=_references(tuple(removed)),
                references=(_CISCO_VTY_ACCESS,),
                limitations=(_REACHABILITY_LIMITATION,),
            )
        if missing:
            return _unknown(
                self.metadata.rule_id,
                "One or more VTY ranges have no explicit supported inbound access-class state.",
                _references(tuple(missing)),
            )

        acl_definitions = {
            name: item
            for item in _observations(configuration, "acl.definition")
            if (name := _string(item, "name")) is not None
        }
        acl_entries: dict[str, list[StructuredObservation]] = {}
        for entry in _observations(configuration, "acl.entry"):
            name = _string(entry, "access_list")
            if name is not None:
                acl_entries.setdefault(name, []).append(entry)

        referenced_names = {
            name for item in active if (name := _string(item, "access_list")) is not None
        }
        unresolved = tuple(
            item
            for item in active
            if (name := _string(item, "access_list")) is None
            or (name not in acl_definitions and name not in acl_entries)
        )
        if unresolved:
            return _unknown(
                self.metadata.rule_id,
                "At least one inbound VTY access-class references an ACL absent from the input.",
                _references(unresolved),
            )
        if _has_unclassified_acl(configuration, referenced_names):
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported syntax occurs inside a referenced VTY source ACL.",
                _references(tuple(active)),
            )

        broad: list[StructuredObservation] = []
        uncertain: list[StructuredObservation] = []
        acl_evidence: list[StructuredObservation] = []
        for name in sorted(referenced_names):
            definition = acl_definitions.get(name)
            entries = acl_entries.get(name, [])
            if definition is not None:
                _append_unique(acl_evidence, definition)
            for entry in entries:
                _append_unique(acl_evidence, entry)
            classification = _classify_source_acl(name, definition, entries)
            if classification == "broad":
                broad.extend(entries)
            elif classification != "restrictive":
                uncertain.extend(entries or ([definition] if definition is not None else []))

        if broad:
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.POTENTIAL_RISK,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                summary="A referenced inbound VTY ACL permits a broad source set.",
                impact=(
                    "The explicit line filter may allow management attempts from sources beyond "
                    "a least-privilege administration boundary."
                ),
                recommendation=(
                    "Narrow the VTY ACL to approved management sources and validate effective "
                    "reachability and ACL ordering on the target platform."
                ),
                evidence=_references(tuple((*active, *broad))),
                references=(_CISCO_VTY_ACCESS,),
                limitations=(_REACHABILITY_LIMITATION,),
            )
        if uncertain:
            return _unknown(
                self.metadata.rule_id,
                "A referenced VTY ACL could not be classified safely as source-restrictive.",
                _references(tuple((*active, *uncertain))),
            )
        return _secure(
            self.metadata.rule_id,
            "Every supported VTY range has a resolvable, potentially restrictive inbound ACL.",
            _references(tuple((*active, *acl_evidence))),
            (
                "ACL structure does not prove intended topology, reachability, or policy quality.",
            ),
        )


class PlaintextCredentialStorageRule:
    """Detect only explicit type 0 passwords retained by supported syntax."""

    metadata = RuleMetadata(
        rule_id="CG-MGMT-005",
        title="Explicit plaintext credential storage",
        category=RuleCategory.MANAGEMENT_PLANE,
        description="Detects effective explicit type 0 local, enable, and line credentials.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        relevant = tuple(
            item
            for item in configuration.observations
            if item.kind
            in {
                "authentication.local_user",
                "authentication.enable_credential",
                "line.password",
            }
        )
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "Credential storage cannot be established from incomplete input.",
                _references(relevant),
            )

        effective = _effective_credentials(configuration)
        plaintext = tuple(
            item
            for item in effective
            if _boolean(item, "configured") is True
            and _string(item, "storage") == "plaintext"
        )
        if plaintext:
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.CONFIRMED_INSECURE,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                summary="At least one effective supported credential uses explicit type 0 storage.",
                impact=(
                    "The credential is represented as reversible plaintext configuration data "
                    "and may be exposed through configuration access or backups."
                ),
                recommendation=(
                    "Replace explicit type 0 passwords with a platform-supported secret or "
                    "approved non-plaintext credential mechanism, then rotate the credential."
                ),
                evidence=_references(plaintext),
                references=(_CISCO_PASSWORD_SECURITY,),
                limitations=(
                    "This rule does not assess credential strength or prove protection of "
                    "non-type-0 representations.",
                ),
            )

        unsupported_scopes = (
            "credential.storage",
            "authentication.local_user",
            "line.password",
        )
        if any(_has_unsupported_rule_scope(configuration, scope) for scope in unsupported_scopes):
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported credential syntax prevents a complete storage conclusion.",
                _references(effective),
            )
        untyped = tuple(
            item
            for item in effective
            if _boolean(item, "configured") is True and _string(item, "storage") == "untyped"
        )
        if untyped:
            return _unknown(
                self.metadata.rule_id,
                "At least one effective password has no reliably interpretable storage type.",
                _references(untyped),
            )
        return _not_applicable(
            self.metadata.rule_id,
            "No effective supported credential explicitly uses type 0 plaintext storage.",
        )


class ManagementLineLoginAuthenticationRule:
    """Evaluate explicit login authentication on VTY and console lines."""

    metadata = RuleMetadata(
        rule_id="CG-MGMT-004",
        title="Management-line login authentication",
        category=RuleCategory.MANAGEMENT_PLANE,
        description="Evaluates explicit VTY and console login authentication configuration.",
    )

    def evaluate(self, configuration: ParsedConfiguration) -> RuleEvaluation:
        declarations = tuple(
            item
            for item in _observations(configuration, "line.declaration")
            if _string(item, "line_type") in {"vty", "console"}
        )
        authentication = _observations(configuration, "line.authentication")
        if configuration.status is ParseStatus.INCOMPLETE:
            return _unknown(
                self.metadata.rule_id,
                "Management-line authentication cannot be established from incomplete input.",
                _references(authentication),
            )
        if _has_unsupported_rule_scope(configuration, "line.authentication"):
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported login or AAA syntax prevents a reliable authentication conclusion.",
                _references(authentication),
            )
        if not declarations:
            return _unknown(
                self.metadata.rule_id,
                "No supported VTY or console declaration was available for evaluation.",
                (),
            )

        declared, declaration_evidence, declaration_error = _effective_management_declarations(
            declarations
        )
        if declaration_error:
            return _unsupported(
                self.metadata.rule_id,
                "At least one management-line range could not be resolved safely.",
                _references(declarations),
            )
        effective_auth = _effective_line_observations(authentication)
        effective_passwords = _effective_line_observations(
            _observations(configuration, "line.password")
        )
        local_users = _active_local_users(configuration)
        aaa_enabled = _effective_aaa_enabled(configuration)
        method_lists = _effective_aaa_method_lists(configuration)
        server_groups = {
            name
            for item in _observations(configuration, "authentication.server_group")
            if (name := _string(item, "name"))
        }

        insecure: list[StructuredObservation] = []
        potential: list[StructuredObservation] = []
        uncertain: list[StructuredObservation] = []
        unsupported_dependencies: list[StructuredObservation] = []
        secure_evidence: list[StructuredObservation] = []
        insecure_vty = False
        for target in sorted(declared):
            auth = effective_auth.get(target)
            if auth is None:
                _append_unique(uncertain, declaration_evidence[target])
                continue
            mode = _string(auth, "mode")
            if mode == "disabled":
                _append_unique(insecure, auth)
                insecure_vty = insecure_vty or target.startswith("vty:")
                continue
            if mode == "local":
                if local_users:
                    _append_unique(secure_evidence, auth)
                else:
                    _append_unique(uncertain, auth)
                continue
            if mode == "default" and not aaa_enabled:
                unsupported_password = _unsupported_line_scope_for_target(
                    configuration,
                    "line.password",
                    target,
                )
                if unsupported_password:
                    for item in unsupported_password:
                        _append_unique(unsupported_dependencies, item)
                    continue
                password = effective_passwords.get(target)
                if password is not None and _boolean(password, "configured") is True:
                    _append_unique(secure_evidence, auth)
                    _append_unique(secure_evidence, password)
                else:
                    _append_unique(uncertain, auth)
                continue

            list_name = "default" if mode == "default" else _string(auth, "method_list")
            method_list = method_lists.get(list_name or "") if aaa_enabled else None
            if method_list is None:
                _append_unique(uncertain, auth)
                continue
            methods = tuple(item.lower() for item in _strings(method_list, "methods"))
            classification = _classify_aaa_methods(methods, local_users, server_groups)
            if classification == "insecure":
                _append_unique(insecure, auth)
                _append_unique(insecure, method_list)
                insecure_vty = insecure_vty or target.startswith("vty:")
            elif classification == "potential":
                _append_unique(potential, auth)
                _append_unique(potential, method_list)
            elif classification == "secure":
                _append_unique(secure_evidence, auth)
                _append_unique(secure_evidence, method_list)
            else:
                _append_unique(uncertain, auth)
                _append_unique(uncertain, method_list)

        if insecure:
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.CONFIRMED_INSECURE,
                severity=Severity.HIGH if insecure_vty else Severity.MEDIUM,
                confidence=Confidence.HIGH,
                summary="At least one management-line range explicitly disables authentication.",
                impact="The affected line can accept a session without the configured login check.",
                recommendation=(
                    "Enable explicit authentication on every affected management-line range and "
                    "validate its local or AAA prerequisite configuration."
                ),
                evidence=_references(tuple(insecure)),
                references=(_CISCO_AAA_LOGIN,),
                limitations=(_REACHABILITY_LIMITATION,),
            )
        if potential:
            return RuleEvaluation(
                rule_id=self.metadata.rule_id,
                outcome=AssessmentOutcome.POTENTIAL_RISK,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                summary="An effective AAA login method list includes an unauthenticated fallback.",
                impact=(
                    "A fallback method can permit management access without identity validation "
                    "when earlier methods do not complete successfully."
                ),
                recommendation=(
                    "Remove unauthenticated fallback methods and validate the remaining AAA "
                    "method order and availability."
                ),
                evidence=_references(tuple(potential)),
                references=(_CISCO_AAA_LOGIN,),
                limitations=(
                    "Runtime AAA server availability and failure behavior are not simulated.",
                ),
            )
        if unsupported_dependencies:
            return _unsupported(
                self.metadata.rule_id,
                "Unsupported line-password syntax blocks an explicit login prerequisite.",
                _references(tuple(unsupported_dependencies)),
            )
        if uncertain:
            return _unknown(
                self.metadata.rule_id,
                "At least one management-line authentication prerequisite is unresolved.",
                _references(tuple(uncertain)),
            )
        return _secure(
            self.metadata.rule_id,
            "Every declared VTY and console range has resolved explicit login authentication.",
            _references(tuple(secure_evidence)),
            (
                "Configuration evidence does not prove runtime AAA availability or reachability.",
            ),
        )


def initial_rules() -> tuple[SecurityRule, ...]:
    """Return the eleven Phase 5B rules in deterministic product order."""

    return (
        VtyTelnetRule(),
        PlaintextHttpManagementRule(),
        SshVersionOneRule(),
        SnmpCommunityConfigurationRule(),
        SnmpCommunityAccessRestrictionRule(),
        VtySourceRestrictionRule(),
        PlaintextCredentialStorageRule(),
        ManagementLineLoginAuthenticationRule(),
        *layer2_rules(),
    )


def _observations(
    configuration: ParsedConfiguration,
    kind: str,
) -> tuple[StructuredObservation, ...]:
    return tuple(item for item in configuration.observations if item.kind == kind)


def _string(observation: StructuredObservation, key: str) -> str | None:
    value = observation.attributes.get(key)
    return value if isinstance(value, str) else None


def _strings(observation: StructuredObservation, key: str) -> tuple[str, ...]:
    value = observation.attributes.get(key)
    return value if isinstance(value, tuple) else ()


def _boolean(observation: StructuredObservation, key: str) -> bool | None:
    value = observation.attributes.get(key)
    return value if isinstance(value, bool) else None


def _vty_declaration_numbers(observation: StructuredObservation) -> tuple[int, ...] | None:
    if _string(observation, "line_type") != "vty":
        return None
    return _bounded_line_numbers(_strings(observation, "range"))


def _vty_identifier_numbers(identifier: str | None) -> tuple[int, ...] | None:
    if identifier is None:
        return None
    parts = identifier.split()
    if not parts or parts[0].lower() != "vty":
        return None
    return _bounded_line_numbers(tuple(parts[1:]))


def _bounded_line_numbers(parts: tuple[str, ...]) -> tuple[int, ...] | None:
    if len(parts) not in {1, 2} or any(not item.isdigit() for item in parts):
        return None
    start = int(parts[0])
    end = int(parts[-1])
    if end < start or end - start > 4096:
        return None
    return tuple(range(start, end + 1))


def _effective_vty_declarations(
    declarations: tuple[StructuredObservation, ...],
) -> tuple[set[int], dict[int, StructuredObservation], bool]:
    declared: set[int] = set()
    evidence: dict[int, StructuredObservation] = {}
    for declaration in declarations:
        line_numbers = _vty_declaration_numbers(declaration)
        if line_numbers is None:
            return declared, evidence, True
        for line_number in line_numbers:
            declared.add(line_number)
            evidence[line_number] = declaration
    return declared, evidence, False


def _management_targets_from_declaration(
    observation: StructuredObservation,
) -> tuple[str, ...] | None:
    line_type = _string(observation, "line_type")
    if line_type not in {"vty", "console"}:
        return ()
    numbers = _bounded_line_numbers(_strings(observation, "range"))
    if numbers is None:
        return None
    return tuple(f"{line_type}:{number}" for number in numbers)


def _management_targets_from_identifier(identifier: str | None) -> tuple[str, ...] | None:
    if identifier is None:
        return None
    parts = identifier.split()
    if not parts or parts[0].lower() not in {"vty", "console"}:
        return ()
    numbers = _bounded_line_numbers(tuple(parts[1:]))
    if numbers is None:
        return None
    return tuple(f"{parts[0].lower()}:{number}" for number in numbers)


def _effective_management_declarations(
    declarations: tuple[StructuredObservation, ...],
) -> tuple[set[str], dict[str, StructuredObservation], bool]:
    declared: set[str] = set()
    evidence: dict[str, StructuredObservation] = {}
    for declaration in declarations:
        targets = _management_targets_from_declaration(declaration)
        if targets is None:
            return declared, evidence, True
        for target in targets:
            declared.add(target)
            evidence[target] = declaration
    return declared, evidence, False


def _effective_line_observations(
    observations: tuple[StructuredObservation, ...],
) -> dict[str, StructuredObservation]:
    effective: dict[str, StructuredObservation] = {}
    for observation in observations:
        targets = _management_targets_from_identifier(_string(observation, "line"))
        if targets is None:
            continue
        for target in targets:
            effective[target] = observation
    return effective


def _effective_credentials(
    configuration: ParsedConfiguration,
) -> tuple[StructuredObservation, ...]:
    effective_users: dict[str, StructuredObservation] = {}
    for item in _observations(configuration, "authentication.local_user"):
        principal_id = _string(item, "principal_id")
        if principal_id is not None:
            effective_users[principal_id] = item

    effective_enable: dict[str, StructuredObservation] = {}
    for item in _observations(configuration, "authentication.enable_credential"):
        kind = _string(item, "credential_kind")
        if kind is not None:
            effective_enable[kind] = item

    line_observations = _observations(configuration, "line.password")
    effective_lines: dict[str, StructuredObservation] = {}
    for item in line_observations:
        targets = _credential_line_targets(_string(item, "line"))
        if targets is not None:
            for target in targets:
                effective_lines[target] = item
    unresolved_lines = tuple(
        item
        for item in line_observations
        if _credential_line_targets(_string(item, "line")) is None
    )
    return tuple(
        (
            *effective_users.values(),
            *effective_enable.values(),
            *effective_lines.values(),
            *unresolved_lines,
        )
    )


def _credential_line_targets(identifier: str | None) -> tuple[str, ...] | None:
    if identifier is None:
        return None
    parts = identifier.split()
    if len(parts) < 2:
        return None
    numbers = _bounded_line_numbers(tuple(parts[1:]))
    if numbers is None:
        return None
    return tuple(f"{parts[0].lower()}:{number}" for number in numbers)


def _active_local_users(configuration: ParsedConfiguration) -> tuple[StructuredObservation, ...]:
    effective: dict[str, StructuredObservation] = {}
    for item in _observations(configuration, "authentication.local_user"):
        principal_id = _string(item, "principal_id")
        if principal_id is not None:
            effective[principal_id] = item
    return tuple(
        item
        for item in effective.values()
        if _boolean(item, "configured") is True
        and _string(item, "credential_kind") in {"password", "secret"}
    )


def _effective_aaa_enabled(configuration: ParsedConfiguration) -> bool:
    observations = _observations(configuration, "authentication.aaa_model")
    return bool(observations and _boolean(observations[-1], "enabled") is True)


def _effective_aaa_method_lists(
    configuration: ParsedConfiguration,
) -> dict[str, StructuredObservation]:
    effective: dict[str, StructuredObservation] = {}
    for item in _observations(configuration, "authentication.aaa_method_list"):
        if _string(item, "service") != "login":
            continue
        name = _string(item, "name")
        if name is None:
            continue
        if _boolean(item, "configured") is False:
            effective.pop(name, None)
        else:
            effective[name] = item
    return effective


def _classify_aaa_methods(
    methods: tuple[str, ...],
    local_users: tuple[StructuredObservation, ...],
    server_groups: set[str],
) -> str:
    if not methods:
        return "unknown"
    if "none" in methods:
        return "insecure" if methods == ("none",) else "potential"

    index = 0
    while index < len(methods):
        method = methods[index]
        if method in {"local", "local-case"}:
            if not local_users:
                return "unknown"
            index += 1
            continue
        if method == "group":
            if index + 1 >= len(methods):
                return "unknown"
            group = methods[index + 1]
            if group not in {"radius", "tacacs+"} and group not in server_groups:
                return "unknown"
            index += 2
            continue
        if method in {"radius", "tacacs+"}:
            index += 1
            continue
        return "unknown"
    return "secure"


def _has_unclassified_acl(
    configuration: ParsedConfiguration,
    referenced_names: set[str],
) -> bool:
    return any(
        item.kind == "command.unclassified"
        and _string(item, "rule_scope") == "acl.entry"
        and _string(item, "context_identifier") in referenced_names
        for item in configuration.observations
    )


def _unsupported_line_scope_for_target(
    configuration: ParsedConfiguration,
    rule_scope: str,
    target: str,
) -> tuple[StructuredObservation, ...]:
    relevant: list[StructuredObservation] = []
    for item in configuration.observations:
        if item.kind != "command.unclassified" or _string(item, "rule_scope") != rule_scope:
            continue
        targets = _management_targets_from_identifier(_string(item, "context_identifier"))
        if targets is None or target in targets:
            relevant.append(item)
    return tuple(relevant)


def _classify_source_acl(
    name: str,
    definition: StructuredObservation | None,
    entries: list[StructuredObservation],
) -> str:
    if not entries:
        return "unknown"
    acl_type = _string(definition, "acl_type") if definition is not None else None
    if acl_type is None:
        acl_type = _string(entries[0], "acl_type") or _numbered_acl_kind(name)
    if acl_type not in {"standard", "extended"}:
        return "unknown"

    ordered_entries = sorted(
        entries,
        key=lambda item: (
            _integer(item, "sequence") is None,
            _integer(item, "sequence") or _integer(item, "entry_index") or 0,
        ),
    )
    for entry in ordered_entries:
        action = _string(entry, "action")
        arguments = tuple(item.lower() for item in _strings(entry, "arguments"))
        if action not in {"permit", "deny"} or not arguments:
            return "unknown"
        if action == "permit" and _acl_has_broad_source(acl_type, arguments):
            return "broad"
        if action == "deny" and _acl_denies_all(acl_type, arguments):
            break
    return "restrictive"


def _numbered_acl_kind(name: str) -> str:
    if not name.isdigit():
        return "unknown"
    number = int(name)
    if 1 <= number <= 99 or 1300 <= number <= 1999:
        return "standard"
    if 100 <= number <= 199 or 2000 <= number <= 2699:
        return "extended"
    return "unknown"


def _acl_has_broad_source(acl_type: str, arguments: tuple[str, ...]) -> bool:
    source_offset = 0 if acl_type == "standard" else 1
    return len(arguments) > source_offset and arguments[source_offset] == "any"


def _acl_denies_all(acl_type: str, arguments: tuple[str, ...]) -> bool:
    if acl_type == "standard":
        return bool(arguments and arguments[0] == "any")
    return len(arguments) >= 3 and arguments[:3] == ("ip", "any", "any")


def _append_unique(
    items: list[StructuredObservation],
    observation: StructuredObservation,
) -> None:
    if observation not in items:
        items.append(observation)


def _integer(observation: StructuredObservation, key: str) -> int | None:
    value = observation.attributes.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _references(observations: tuple[StructuredObservation, ...]) -> tuple[EvidenceReference, ...]:
    return tuple(
        EvidenceReference(
            observation_id=item.observation_id,
            source_command_ids=item.source_command_ids,
        )
        for item in observations
    )


def _has_unsupported_rule_scope(
    configuration: ParsedConfiguration,
    rule_scope: str,
) -> bool:
    return any(
        item.kind == "command.unclassified" and _string(item, "rule_scope") == rule_scope
        for item in configuration.observations
    )


def _effective_communities(
    configuration: ParsedConfiguration,
) -> dict[str, StructuredObservation]:
    effective: dict[str, StructuredObservation] = {}
    for item in _observations(configuration, "snmp.community"):
        community_id = _string(item, "community_id")
        if community_id is not None:
            effective[community_id] = item
    return effective


def _unknown(
    rule_id: str,
    summary: str,
    evidence: tuple[EvidenceReference, ...],
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        outcome=AssessmentOutcome.UNKNOWN,
        severity=None,
        confidence=Confidence.LOW,
        summary=summary,
        impact=None,
        recommendation=None,
        evidence=evidence,
        limitations=("No security conclusion was inferred from insufficient evidence.",),
    )


def _unsupported(
    rule_id: str,
    summary: str,
    evidence: tuple[EvidenceReference, ...],
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        outcome=AssessmentOutcome.UNSUPPORTED_SYNTAX,
        severity=None,
        confidence=Confidence.LOW,
        summary=summary,
        impact=None,
        recommendation=None,
        evidence=evidence,
        limitations=("Unsupported syntax was not treated as secure.",),
    )


def _secure(
    rule_id: str,
    summary: str,
    evidence: tuple[EvidenceReference, ...],
    limitations: tuple[str, ...],
) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        outcome=AssessmentOutcome.SECURE,
        severity=None,
        confidence=Confidence.HIGH,
        summary=summary,
        impact=None,
        recommendation=None,
        evidence=evidence,
        limitations=limitations,
    )


def _not_applicable(rule_id: str, summary: str) -> RuleEvaluation:
    return RuleEvaluation(
        rule_id=rule_id,
        outcome=AssessmentOutcome.NOT_APPLICABLE,
        severity=None,
        confidence=Confidence.HIGH,
        summary=summary,
        impact=None,
        recommendation=None,
    )
