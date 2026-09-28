# Security-Check Catalog

This catalog defines the complete set of 17 rules implemented in ConfigGuard 0.1.0. Each rule
uses structured observations, supported effective command order, sanitized evidence, and
explicit uncertainty. The catalog does not reserve or advertise unimplemented checks.

| Category | Rule IDs |
| --- | --- |
| Management Plane (6) | `CG-MGMT-001` through `CG-MGMT-006` |
| SNMP (2) | `CG-SNMP-001`, `CG-SNMP-002` |
| Layer 2 (4) | `CG-L2-001` through `CG-L2-004` |
| Interface IPv4 ACLs (2) | `CG-ACL-001`, `CG-ACL-002` |
| Routing Authentication (3) | `CG-ROUTE-001`, `CG-ROUTE-002`, `CG-ROUTE-003` |

Implemented rules use structured observations, supported effective command order, sanitized
evidence, and explicit uncertainty. They do not prove reachability, runtime state, or
exploitability.

Common semantics:

- `UNKNOWN`: relevant context is missing or a safe conclusion needs facts outside the file.
- `NOT_EVALUATED`: required parser capability failed, was disabled, or is not implemented.
- `UNSUPPORTED_SYNTAX`: relevant syntax was found but cannot be interpreted safely.
- `NOT_APPLICABLE`: the configuration provides positive evidence that the feature or role is
  irrelevant. Mere absence of a command is not enough.

Severity is qualitative and applies only to adverse results. Confidence is assessed
separately. All secret-bearing evidence must pass through centralized redaction.

## Management plane

### CG-MGMT-001 — Insecure VTY transport

- **Implementation status:** Implemented in Phase 3.
- **Supported syntax:** Effective `transport input telnet`, `all`, `ssh`, `none`, and explicit
  `no transport input` across parsed VTY ranges. Other values are unsupported.
- **Implemented severity policy:** Explicit effective Telnet/all is confirmed insecure,
  High severity, High confidence. Missing/default-dependent state is Unknown; explicit
  SSH-only/none is secure for this narrow check. Overlapping VTY ranges are resolved per line
  in source order so a later broad or narrow range replaces only the lines it selects.
- **Technical reference:** [RFC 854 — Telnet Protocol](https://www.rfc-editor.org/rfc/rfc854).

- **Category:** Management plane security
- **Configuration context:** All `line vty` ranges and inherited line behavior.
- **Required evidence:** Parsed VTY ranges, `transport input` values, applicable defaults, and
  line numbers.
- **Detection conditions:** Confirmed insecure when an effective VTY range explicitly permits
  Telnet; secure only when every applicable range explicitly permits secure transports and
  Telnet is excluded. Treat default-dependent cases as potential risk or unknown.
- **Potential false positives:** An upstream management network or out-of-band boundary may
  prevent untrusted access; unused line ranges may be unreachable.
- **UNKNOWN / NOT_EVALUATED:** Unknown when transport behavior depends on an unknown platform
  default or incomplete line coverage. Unsupported syntax blocks the result only when it is
  transport-related; unrelated line commands do not invalidate an explicit transport state.
  Not evaluated when VTY contexts cannot be parsed.
- **Severity considerations:** Usually high for reachable Telnet; reduce only with defensible
  scope evidence. Confidence is high for an explicit `transport input telnet`.
- **Remediation:** Permit SSH only on required VTY ranges and restrict their sources.

### CG-MGMT-002 — SSH protocol version 1 configured

- **Implementation status:** Implemented in Phase 3 for protocol version only.
- **Supported syntax:** Ordered `ip ssh version 1`, `ip ssh version 2`, and
  `no ip ssh version`.
- **Implemented severity policy:** Effective explicit version 1 is confirmed insecure,
  Medium severity, High confidence. Version 2 is secure for this narrow check; missing or
  negated selection is Unknown.
- **Technical reference:** [RFC 4253 — SSH Transport Layer Protocol](https://www.rfc-editor.org/rfc/rfc4253).

- **Category:** Management plane security
- **Configuration context:** Global SSH commands plus VTY transport configuration.
- **Required evidence:** SSH version/settings, host/domain prerequisites where relevant, and
  whether any VTY line accepts SSH.
- **Detection conditions:** Potential risk when SSH management is enabled and the file
  explicitly selects an obsolete protocol version or insecure option. A modern explicit
  version can satisfy only the configuration-visible part of the check.
- **Potential false positives:** Effective defaults vary by IOS/IOS XE release; algorithms and
  key quality may not be fully represented in the export.
- **UNKNOWN / NOT_EVALUATED:** Unknown when version/default behavior or key properties cannot
  be established. Not evaluated when SSH observations are unavailable.
- **Severity considerations:** Medium to high depending on the explicitly enabled protocol;
  never infer key strength from the mere presence of SSH.
- **Remediation:** Use the strongest version and cryptographic settings supported by the
  approved platform baseline, and rotate weak keys through an authorized process.

### CG-MGMT-003 — VTY inbound source restriction

- **Implementation status:** Implemented in Phase 5A.
- **Supported syntax:** Ordered IPv4/IPv6 VTY `access-class` bindings in the inbound direction,
  optional `vrf-also`, explicit negation, overlapping numeric VTY ranges, and referenced
  named or numbered ACL entries supported by parser version 1. Outbound bindings do not
  satisfy this check.
- **Implemented severity policy:** An explicitly removed inbound restriction or a referenced
  ACL with a broad source permit is a Medium Potential Risk, not proof of reachability.
  Missing bindings and unresolved ACLs are Unknown. Relevant unsupported ACL or line syntax
  is Unsupported Syntax. A resolved, non-broad ACL is Secure only for this narrow structural
  check.
- **Technical reference:** [Cisco — VRF Awareness Access Class Line](https://www.cisco.com/c/en/us/td/docs/routers/ios/config/17-x/application-services/b-application-services/m-bba-vrf-aware-access-class-line.html).
- **Category:** Management plane security
- **Configuration context:** VTY `access-class` commands, referenced IPv4/IPv6 ACLs, VRF and
  direction modifiers.
- **Required evidence:** Every applicable VTY range, ACL binding, referenced ACL semantics,
  and unresolved references.
- **Detection conditions:** Potential risk when a binding is explicitly removed or its ACL
  permits a broad source. Mere absence remains Unknown because defaults and inherited/runtime
  behavior are not guessed.
- **Potential false positives:** Control-plane policing, upstream firewalls, management VRFs,
  or isolated out-of-band networks may compensate.
- **UNKNOWN / NOT_EVALUATED:** Unknown for unresolved ACLs, unknown device reachability, or
  partially parsed line ranges. Not evaluated when ACL application cannot be modeled.
- **Severity considerations:** Medium in this phase. No Critical result or exposure claim is
  derived from a static ACL alone.
- **Remediation:** Apply least-privilege IPv4/IPv6 management ACLs consistently to all VTY
  ranges and verify reachability before deployment.

### CG-MGMT-004 — Management-line login authentication

- **Implementation status:** Implemented in Phase 5A.
- **Supported syntax:** Effective `login`, `login local`, `login authentication <list>`, and
  `no login` across overlapping VTY and console ranges, plus `aaa new-model`, supported login
  method lists, local-user prerequisites, and named AAA server-group references.
- **Implemented severity policy:** Explicit `no login` is Confirmed Insecure (High on any VTY,
  Medium when limited to console). A method list containing `none` as fallback is a Medium
  Potential Risk. Missing local users, absent lists/groups, defaults, and other unresolved
  prerequisites are Unknown; complete supported bindings are Secure for this narrow check.
- **Technical reference:** [Cisco — Configuring AAA Authentication Methods](https://www.cisco.com/c/en/us/td/docs/routers/ios-xe/security-vpn/security-vpn/m_sec-cfg-authentifcn-0.html).
- **Category:** Management plane security
- **Configuration context:** VTY/console `login` commands, AAA method lists, local users, and
  applicable global AAA configuration.
- **Required evidence:** Effective login method for each declared management-line range and
  resolvable AAA/local prerequisites without exposing credentials.
- **Detection conditions:** Confirmed insecure for an explicit authentication disablement;
  resolved authentication is not a claim that a runtime login succeeds or resists attack.
- **Potential false positives:** External AAA availability and runtime fallback behavior are
  not proven by a static file; some line ranges may be unused.
- **UNKNOWN / NOT_EVALUATED:** Unknown when method lists or defaults cannot be resolved. Not
  evaluated when AAA/line contexts are unsupported.
- **Severity considerations:** High at most for explicit unauthenticated remote access;
  Medium for console-only disablement or unauthenticated fallback risk. Phase 5A emits no
  Critical result.
- **Remediation:** Bind an approved AAA method list with intentional fallback and restrict
  local emergency accounts according to policy.

### CG-MGMT-005 — Explicit plaintext credential storage

- **Implementation status:** Implemented in Phase 5A for explicit plaintext storage only.
- **Scope clarification:** This phase uses the reserved ID for the objectively supported
  storage slice of privileged-access review. It does not claim complete
  privileged-access protection, hash strength, password quality, or effective authorization.
- **Supported syntax:** Ordered `username ... password 0`, `username ... secret 0`, `enable
  password 0`, `enable secret 0`, and line `password 0`, their supported typed/non-typed
  alternatives, and explicit negation. Local principals are tracked with document-local
  opaque IDs and all values remain redacted.
- **Implemented severity policy:** An effective explicit type 0 credential is Confirmed
  Insecure, High severity, High confidence. Untyped password syntax is Unknown. If no active
  supported credential explicitly uses type 0, the narrow check is Not Applicable—not
  Secure. `service password-encryption` is never treated as proof of protection.
- **Technical reference:** [Cisco — Configuring Security with Passwords, Privileges, and Logins](https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr_cfg/configuration/15-mt/sec-usr-cfg-15-mt-book/sec-cfg-sec-4cli.html).
- **Category:** Management plane security
- **Configuration context:** Local username credentials, global enable credentials, and
  management-line passwords.
- **Required evidence:** Effective presence and explicit type metadata only; principal and
  secret values must be redacted.
- **Detection conditions:** Confirmed insecure only for an effective explicit type 0 credential.
- **Potential false positives:** AAA command authorization may reduce reliance on enable
  secrets; supported hash types vary by release.
- **UNKNOWN / NOT_EVALUATED:** Unknown for untyped storage or incomplete input. Relevant
  unsupported credential syntax is Unsupported Syntax. Encoded/hash-like alternatives are
  not certified as secure.
- **Severity considerations:** High for explicit type 0 storage. Never report, compare, or
  retain a public principal or credential value.
- **Remediation:** Replace explicit type 0 values with an approved platform-supported secret
  mechanism, remove obsolete values, and rotate any credential stored in plaintext.

### CG-MGMT-006 — Plaintext HTTP management service

- **Implementation status:** Implemented in Phase 3 for plaintext HTTP state only.
- **Supported syntax:** Ordered `ip http server` and `no ip http server`; `ip http
  secure-server` is kept distinct and does not enable this finding.
- **Implemented severity policy:** Effective explicit HTTP enablement is confirmed insecure,
  High severity, High confidence. Explicit disablement is secure for this narrow check;
  missing/default-dependent state is Unknown.
- **Technical reference:** [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110).

- **Category:** Management plane security
- **Configuration context:** Global HTTP/HTTPS server, authentication, ACL, and interface/VRF
  binding commands.
- **Required evidence:** Explicit service state, transport, authentication method, access
  restriction, and known defaults for the identified release.
- **Detection conditions:** Confirmed insecure when the clear-text HTTP server is explicitly
  enabled. Potential risk when HTTPS management is enabled without a visible source
  restriction or with ambiguous authentication.
- **Potential false positives:** The service may be unreachable or required by an authorized
  management platform; absence may rely on a known disabled default.
- **UNKNOWN / NOT_EVALUATED:** Unknown when service defaults, bindings, or ACLs are unresolved.
  Not evaluated when relevant global syntax is unsupported.
- **Severity considerations:** High for reachable clear-text management; medium for broadly
  exposed HTTPS. Reachability uncertainty affects confidence, not the explicit service fact.
- **Remediation:** Disable unused HTTP services; otherwise require HTTPS, approved
  authentication, current cryptography, and least-privilege source restrictions.

## SNMP

### CG-SNMP-001 — SNMP community-based management configured

- **Implementation status:** Implemented in Phase 3 as community-configuration detection.
- **Supported syntax:** Ordered `snmp-server community <redacted> [RO|RW] [ACL]` and matching
  `no snmp-server community <redacted>` declarations.
- **Implemented severity policy:** An effective community is a Potential Risk, not a claim of
  exposure: Low for observed RO/unknown permission and Medium for observed RW, with High
  evidence confidence.
- **Technical reference:** [RFC 3414 — SNMPv3 User-based Security Model](https://www.rfc-editor.org/rfc/rfc3414).

- **Category:** SNMP security
- **Configuration context:** Global SNMP community, host, group, and version commands.
- **Required evidence:** Version-specific configuration and community presence with values
  masked.
- **Detection conditions:** Confirmed insecure when SNMPv1 or v2c is explicitly enabled or a
  community configuration establishes their use. Do not expose the community.
- **Potential false positives:** An isolated management network can reduce exposure but does
  not add authentication or encryption to v1/v2c.
- **UNKNOWN / NOT_EVALUATED:** Unknown for ambiguous version defaults or unsupported command
  variants. Unrelated global syntax does not invalidate the result. Not evaluated when
  SNMP syntax parsing is unavailable.
- **Severity considerations:** High when write access is configured; generally medium for
  read-only use, adjusted for confidently known restrictions.
- **Remediation:** Migrate to SNMPv3 with authentication and privacy, restrict sources, and
  rotate/remove community credentials.

### CG-SNMP-002 — SNMP community source restriction

- **Implementation status:** Implemented in Phase 3 for recognizable ACL references.
- **Supported syntax:** Community RO/RW modifiers with named or numbered ACL references that
  have parsed `acl.definition` or `acl.entry` evidence.
- **Implemented severity policy:** Missing community-specific ACL reference is a conservative
  Potential Risk (Low for RO, Medium for RW). Missing referenced ACL or unsupported permission
  syntax is Unknown/Unsupported. A resolved reference is secure only for reference presence;
  ACL reachability and topology are not evaluated.
- **Technical reference:** [RFC 3415 — SNMP View-based Access Control Model](https://www.rfc-editor.org/rfc/rfc3415).

- **Category:** SNMP security
- **Configuration context:** Community access mode, attached ACLs/views, and referenced ACLs.
- **Required evidence:** Redacted community records, RO/RW mode, ACL/view bindings, and fully
  resolved referenced policies.
- **Detection conditions:** Confirmed insecure for an explicit unrestricted read-write
  community. Potential risk for read-only communities without resolvable source restrictions.
- **Potential false positives:** Upstream filtering or management VRFs may compensate; an ACL
  name alone does not prove its effective semantics.
- **UNKNOWN / NOT_EVALUATED:** Unknown when ACL/view references are absent, unresolved, or
  topology is required. Unsupported community syntax is never treated as proof that the rule
  is not applicable; it produces the same uncertainty boundary as the prerequisite community
  check. Not evaluated when community modifiers are unsupported.
- **Severity considerations:** High to critical for broadly accessible write communities;
  medium for unrestricted read-only communities.
- **Remediation:** Prefer SNMPv3; otherwise enforce read-only access, least-privilege views,
  and tightly scoped source ACLs during migration.

## Interface IPv4 ACLs

An ACL definition alone is not an interface traffic filter. Phase 7A evaluates only effective,
explicit IPv4 `ip access-group` attachments. VTY `access-class`, SNMP community restrictions,
and other ACL consumers remain within their own checks, while IPv6 policies are outside these
two rules. Missing or unsafe attachment/policy semantics remain uncertain; absence of an
interface ACL is not itself an insecure result.

### CG-ACL-001 — Broad permissions in interface IPv4 ACLs

- **Implementation status:** Implemented in Phase 7A.
- **Category:** Network access security.
- **Supported syntax:** Explicit effective `ip access-group NAME in|out` and matching
  negation; supported physical interface ranges; named/numbered standard and extended IPv4
  ACLs; `permit`/`deny`, remarks, all-sequenced or all-unsequenced entry order, ACE/whole-ACL
  deletion, `any`, `host A.B.C.D`, IPv4-plus-wildcard expressions, `ip`/`tcp`/`udp`/`icmp`,
  and bounded `eq`/`neq`/`lt`/`gt`/`range` port forms.
- **Required evidence:** An effective explicit IPv4 interface attachment, a present complete
  policy in the supported subset, entry order, direction, and any relevant range, template,
  or Port-channel relationship.
- **Detection/applicability:** A reachable inbound universal remaining permit is Medium
  Potential Risk with Medium confidence. A reachable protocol-wide permit, or a broad
  outbound permit, is Low Hardening with Medium confidence. Earlier terminal denies and
  supported denies that fully cover a later broad candidate prevent a false finding; a
  narrower preceding deny does not make the remaining broad permit disappear. Fully supported
  attached policies without a reachable broad permit are Secure only for this narrow check.
- **False-positive limitations:** Broad configuration does not prove Internet exposure,
  interface activity, unwanted traffic, topology, routing, NAT, upstream controls, or business
  intent. Direction changes operational context, so findings do not claim exploitability.
- **Uncertainty/applicability states:** `NOT_APPLICABLE` when no effective supported IPv4 ACL
  is explicitly attached and no relevant unresolved relationship exists. `UNKNOWN` for
  incomplete input, missing/empty policies, conflicting removals, or unresolved relevant
  template/Port-channel context. `UNSUPPORTED_SYNTAX` for relevant advanced/malformed syntax,
  mixed/duplicate sequence semantics, or an unexpandable relevant interface range.
- **Remediation:** Validate the interface trust boundary and required traffic, then replace
  unnecessarily broad remaining permits with documented least-privilege entries and test the
  operational change through an authorized process.

### CG-ACL-002 — Interface IPv4 ACL reference integrity

- **Implementation status:** Implemented in Phase 7A.
- **Category:** Network access security.
- **Supported syntax:** The same bounded IPv4 attachment, ACL definition, ordering, sequence,
  address/wildcard, protocol, port, negation, and range subset as `CG-ACL-001`.
- **Required evidence:** Every effective explicit interface IPv4 attachment and its complete
  referenced policy, plus relationship context that can alter effective application.
- **Detection/applicability:** Secure with High confidence only when every active supported
  attachment references a present, non-empty, fully evaluated policy. This confirms reference
  and evaluation integrity only; it does not certify policy quality or runtime enforcement.
- **False-positive limitations:** A missing definition may indicate a partial export, and an
  unresolved attachment does not prove that the running device lacks filtering. The rule does
  not duplicate VTY or SNMP restriction findings.
- **Uncertainty/applicability states:** `NOT_APPLICABLE` only when no effective interface IPv4
  attachment or relevant unresolved relationship exists. Missing/empty references, incomplete
  input, conflicting removals, and relevant template/Port-channel relationships are `UNKNOWN`.
  Relevant malformed or advanced ACL syntax is `UNSUPPORTED_SYNTAX`, never a pass.
- **Remediation:** Supply or restore the intended complete ACL definition, remove stale
  references, replace unsupported constructs only through an approved equivalent policy, and
  verify attachment direction and operational behavior before deployment.

## Layer 2 security

Phase 6 resolves direct interface commands and a bounded range subset before these four rules
run. Supported range members use `GigabitEthernet`/`Gi`, `FastEthernet`/`Fa`, or
`TenGigabitEthernet`/`Te` names with a numeric path; a range may vary only the final numeric
component and may contain comma-separated full members. Expansion is capped at 128 unique
targets. Direct and range observations resolve in source order, including overlap and
negation, and evidence retains the target plus original range context. Other interface types,
mixed paths/types, descending, malformed, ambiguous, or oversized ranges are unsupported.

Exact template declarations and `source template NAME` applications are detected, but applied,
missing, nested, and cyclic inheritance remains unresolved; unused definitions do not affect
interfaces. Exact `channel-group N mode active|passive|desirable|auto|on` declarations and
`no channel-group N` removals establish a physical/logical relationship only. No logical
Port-channel fact is copied to a member or vice versa, and no runtime bundle formation is
inferred.

### CG-L2-001 — Access-port security posture

- **Implementation status:** Implemented in Phase 5B.
- **Category:** Layer 2 security
- **Supported syntax:** Exact `switchport mode access|trunk`, `no switchport mode`,
  `switchport port-security`, `no switchport port-security`, supported `maximum`, and
  `violation protect|restrict|shutdown` declarations and negations.
- **Acceptance input context:** Exact Port Security commands remain attached to the active
  interface or supported interface-range stanza when a manually assembled mutation omits only
  their leading indentation. Section delimiters and new headers still terminate that context.
- **Required evidence:** An explicit access-mode interface plus explicit effective Port
  Security state and violation mode. Repeated supported commands resolve in source order.
- **Detection/applicability:** `restrict` or `shutdown` is a narrow configuration-visible
  pass. Explicit disablement or `protect` produces hardening guidance. Missing state or
  violation behavior is Unknown rather than a vulnerability. Router-only input and an
  explicit trunk-only configuration are Not Applicable.
- **Potential false positives:** 802.1X, NAC, MACsec, disabled ports, trunks, AP/phone designs,
  or platform limitations can make classic port security inappropriate.
- **UNKNOWN / UNSUPPORTED:** Unknown when role, explicit state, or violation behavior is
  missing. Relevant malformed syntax is Unsupported Syntax. Supported direct/range facts are
  source-ordered; applied template or channel/member inheritance remains Unknown.
- **Severity/confidence:** Explicit disablement is low-severity/high-confidence hardening;
  `protect` is low-severity/medium-confidence hardening because monitoring policy is unknown.
- **Remediation:** Apply the organization's approved edge-access control (port security,
  802.1X/NAC, or equivalent) with an intentional violation policy.

### CG-L2-002 — DHCP Snooping trust configuration

- **Implementation status:** Implemented in Phase 5B.
- **Category:** Layer 2 security
- **Supported syntax:** `ip dhcp snooping`, `no ip dhcp snooping`, VLAN lists/ranges and their
  negation, exact access/trunk mode, access VLAN, and interface trust/negation.
- **Required evidence:** Explicit global enablement, an explicit effective protected VLAN set,
  and explicit access VLAN and trust state for each evaluated access port.
- **Detection/applicability:** Explicit trust on an access-mode port is a medium potential risk
  pending role validation. Explicit global disablement or an access VLAN outside the protected
  set is medium hardening. A covered access port explicitly configured untrusted is a narrow
  pass. Trust on an explicit trunk is not flagged merely for being trusted.
- **Potential false positives:** Static addressing, external enforcement, non-access devices,
  legitimate DHCP-server paths, special appliances, or platforms without the feature may
  change applicability.
- **UNKNOWN / UNSUPPORTED:** Unknown without explicit global, VLAN, access-role, or trust
  evidence. Relevant malformed syntax is Unsupported Syntax. Router-only and explicit
  trunk-only inputs are Not Applicable. Runtime bindings and unresolved template or
  Port-channel inheritance are not modeled.
- **Severity/confidence:** Medium severity; explicit access trust or uncovered VLAN retains
  medium confidence because physical role and compensating controls are external facts.
- **Remediation:** Enable snooping on intended client VLANs and trust only validated DHCP
  server/uplink paths, accounting for operational dependencies.

### CG-L2-003 — Dynamic ARP Inspection coverage

- **Implementation status:** Implemented in Phase 5C.
- **Category:** Layer 2 security
- **Supported syntax:** `ip arp inspection vlan` VLAN lists/ranges and negation, exact
  interface `ip arp inspection trust` and negation, explicit access/trunk mode and access
  VLANs, plus the existing supported DHCP Snooping global/VLAN declarations.
- **Required evidence:** Explicit DAI VLAN selection, explicit access VLAN and trust state,
  plus supported DHCP Snooping VLAN and interface-untrusted state as a binding-source
  prerequisite. Repeated and overlapping VLAN/trust commands resolve in source order.
- **Detection/applicability:** A trusted access-mode interface is a medium potential risk
  pending role validation; a trusted trunk is not flagged merely for being trusted. Explicit
  DAI removal from an identified access VLAN is medium hardening. A narrow pass requires DAI
  on every evaluated access VLAN, explicitly DAI-untrusted access ports, and supported DHCP
  Snooping VLANs with those access ports explicitly DHCP-untrusted.
- **DHCP Snooping interaction:** Configuration proves declarations only, not a live or valid
  binding database. Missing/disabled snooping does not prove DAI is wholly nonfunctional
  because static validation may exist, but it prevents a supported positive conclusion.
- **Potential false positives:** Static hosts, ARP ACL/filter validation, legitimate trusted
  infrastructure paths, non-DHCP addressing, and compensating controls may change the result.
- **UNKNOWN / UNSUPPORTED / NOT_APPLICABLE:** Unknown when VLAN, trust, binding-source,
  template, or Port-channel inheritance cannot be resolved. Supported physical-interface
  ranges are evaluated; malformed/ambiguous/oversized ranges and relevant malformed DAI
  syntax yield Unsupported Syntax. Router-only and explicit trunk-only input is Not
  Applicable for this access-VLAN trust-boundary check.
- **Severity/confidence:** Medium potential risk/hardening only; trust roles and alternative
  validation keep confidence medium. No Critical outcome or exploitability claim is made.
- **Remediation:** Validate VLAN and interface roles, provide an approved binding or static
  validation design, enable DAI only on applicable VLANs, and trust only documented
  infrastructure paths before enforcement.
- **Limitations:** Static analysis does not verify bindings, traffic, live enforcement,
  template or Port-channel inheritance, or protection from every ARP-related attack.

### CG-L2-004 — BPDU Guard on PortFast edge ports

- **Implementation status:** Implemented in Phase 5B.
- **Category:** Layer 2 security
- **Supported syntax:** `spanning-tree portfast`, `spanning-tree portfast edge`, supported
  disable/negation forms, `spanning-tree bpduguard enable|disable`, its negation, and the
  global `spanning-tree portfast bpduguard default` enable/negation forms.
- **Required evidence:** Effective edge-port classification and effective BPDU Guard state.
- **Detection/applicability:** A supported per-interface declaration overrides the global
  default; removing the override falls back to that default. Explicitly disabled protection
  on an explicit PortFast/edge port is medium hardening. An explicit effective enablement is
  a narrow pass. No explicit edge port is Not Applicable.
- **Potential false positives:** Ports connected to downstream switches, hypervisors, bridges,
  or special appliances may intentionally receive BPDUs.
- **UNKNOWN / UNSUPPORTED:** Unknown when an edge port has no resolvable per-interface or
  global state. Relevant unsupported spanning-tree syntax produces Unsupported Syntax.
  Supported physical-interface ranges are evaluated; template/Port-channel inheritance,
  topology, and live STP state are not modeled.
- **Severity/confidence:** Explicit disablement is medium-severity/high-confidence hardening;
  the file cannot establish whether receiving BPDUs is intentional or whether enforcement is
  operational.
- **Remediation:** Enable BPDU Guard on verified edge ports and document intentional network-
  device links.

## Routing protocol security

### CG-ROUTE-001 — OSPFv2 neighbor authentication

- **Category:** Routing protocol security
- **Implementation status:** Implemented in Phase 7B for the documented OSPFv2 subset.
- **Supported syntax:** Classic `router ospf` processes, IPv4 `network ... area` statements,
  explicit interface/process-area bindings, passive-interface state, supported area/interface
  authentication modes, simple keys, message-digest keys, and their modeled negations.
- **Configuration context:** OSPF process/area authentication plus interface-level mode and
  key configuration.
- **Required evidence:** Active OSPF interfaces/areas, effective authentication mode, and key
  presence/type with all values masked.
- **Detection conditions:** Potential risk only for explicit `null` authentication on a
  resolved participating interface; hardening for supported simple-password authentication;
  secure only for a complete message-digest mode/key combination.
- **Potential false positives:** Passive interfaces, protected point-to-point links, tunnels,
  or external controls can affect exposure; neighbor state is not visible.
- **UNKNOWN / NOT_EVALUATED:** Unknown when process-to-interface, area inheritance, or a
  matching key cannot be resolved. OSPFv3 is not reinterpreted as OSPFv2; relevant unsupported
  syntax produces `UNSUPPORTED_SYNTAX`. A supported area negation that does not match the
  active explicit interface association remains unknown.
- **Severity considerations:** Medium for explicit null authentication and low for the
  supported simple-password hardening result; confidence is high only for resolved behavior.
- **Remediation:** Configure an approved authentication mechanism consistently on both ends,
  protect key material, and coordinate changes to avoid adjacency loss.

### CG-ROUTE-002 — Classic IPv4 EIGRP authentication

- **Category:** Routing protocol security
- **Implementation status:** Implemented in Phase 7B for classic IPv4 EIGRP only.
- **Supported syntax:** Classic `router eigrp <AS>` processes, IPv4 network statements,
  passive-interface state, AS-specific interface MD5 mode and key-chain bindings, supported
  key-chain/key/key-string declarations, and their modeled negations.
- **Configuration context:** Classic EIGRP processes, interfaces, key chains,
  and passive-interface behavior.
- **Required evidence:** Active adjacency-capable interfaces, effective authentication
  binding, and redacted key-chain metadata.
- **Detection conditions:** Secure only when a resolved participating interface has matching
  AS-specific MD5 mode, key-chain binding, and a supported active key secret.
- **Potential false positives:** Passive interfaces and isolated transports may make the
  control irrelevant; named-mode inheritance varies.
- **UNKNOWN / NOT_EVALUATED:** Unknown when participating interfaces, matching AS bindings, or
  key-chain completeness are unclear. A shortened network negation that does not exactly match
  an active wildcard statement remains unknown. Named EIGRP produces `UNSUPPORTED_SYNTAX`.
- **Severity considerations:** The initial supported subset produces secure or uncertainty
  outcomes; no adverse severity is assigned from missing/default-dependent evidence.
- **Remediation:** Apply a coordinated, approved authentication/key-chain policy to all
  adjacency-forming interfaces.

### CG-ROUTE-003 — RIPv2 authentication

- **Category:** Routing protocol security
- **Implementation status:** Implemented in Phase 7B for the documented RIPv2 subset.
- **Supported syntax:** `router rip`, explicit version and IPv4 network statements,
  passive-interface state, interface text/MD5 authentication mode and key-chain bindings,
  supported key-chain/key/key-string declarations, and their modeled negations.
- **Configuration context:** RIP process version/network statements, interfaces, and key-chain
  authentication settings.
- **Required evidence:** RIP applicability, active interfaces, effective version and
  authentication mode, and redacted key metadata.
- **Detection conditions:** Secure only with explicit version 2, a resolved participating
  interface, MD5 mode, and a usable referenced key chain. Text mode is hardening; missing
  version/mode/key evidence remains unknown rather than a vulnerability.
- **Potential false positives:** Passive interfaces, lab/isolated segments, or migration
  constraints may alter risk; runtime neighbors are unknown.
- **UNKNOWN / NOT_EVALUATED:** Unknown when interface activation, version, mode, or key-chain
  evidence is unresolved. Relevant unsupported RIP syntax produces `UNSUPPORTED_SYNTAX`.
- **Severity considerations:** Low for the supported text-mode/version hardening result;
  missing/default-dependent evidence carries no adverse severity.
- **Remediation:** Prefer a modern approved routing design; where RIP remains authorized, use
  supported authentication and tightly controlled interfaces.

For all three routing rules, an explicitly passive-only set is `NOT_APPLICABLE` only when
every resolved process/interface pair is passive. Missing passive declarations are not
reported as proof of a live adjacency. Unknown and passive-only results retain sanitized
association evidence and source lines so the conclusion can be reviewed without raw secrets.

Within the implemented subset, OSPFv2 can produce `SECURE`, `POTENTIAL_RISK` for explicit
null authentication, `HARDENING` for simple-password authentication, `UNKNOWN`,
`NOT_APPLICABLE`, or `UNSUPPORTED_SYNTAX`. Classic EIGRP produces secure/applicability or
uncertainty outcomes only. RIPv2 can additionally produce `HARDENING` for supported text-mode
or explicit non-version-2 evidence. None of these rules emits `CONFIRMED_INSECURE` from static
routing authentication evidence. `NOT_EVALUATED` is reserved for analysis/sanitization failure,
not for absent commands or unsupported protocol variants.

## Catalog limitations

The catalog intentionally avoids software-CVE checks, live reachability claims, credential
cracking, topology discovery, and operational-state assertions. It also does not yet define a
numerical score. Technical references should be attached during rule implementation and
versioned against the supported Cisco syntax matrix; citing a generic benchmark is not a
substitute for proving applicability to the parsed device and release.
