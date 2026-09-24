# Learning Guide

## The central idea

A router configuration is not a bag of words. The same word can mean different things in
different sections, and a missing command may mean a platform default, an inherited policy,
an irrelevant feature, or simply an incomplete export. ConfigGuard therefore separates
reading the file, understanding its structure, judging security, and presenting evidence.

## 1. Input is evidence, not executable content

The user exports a configuration and explicitly selects it. ConfigGuard reads at most 2 MiB
by default, accepts UTF-8 text with an optional BOM, and keeps the result in memory. It never
sends commands to the device and never executes lines from the file. This protects both the
network and the workstation running the tool.

The input itself is highly sensitive. Even without clear-text passwords, hostnames, internal
addresses, ACLs, routing settings, and hashed credentials can help an attacker. That is why
offline-by-default behavior, no telemetry, no automatic persistence, and careful logging are
architectural requirements rather than optional user settings.

## 2. Context-aware parsing

Cisco configuration is hierarchical even though it is plain text. For example:

```text
line vty 0 4
 transport input ssh
```

The indented command belongs to the VTY line section. A naive search for `ssh` cannot prove
which lines accept it, whether Telnet is also accepted, or whether an access class restricts
the source. A context-aware parser tracks section boundaries and records each command's line
number and owning context.

The parser then emits *observations*: small facts such as "VTY range 0-4 permits SSH" with
references to the commands that support the fact. It also records syntax it cannot safely
interpret. Unknown syntax is important evidence about assessment completeness; silently
discarding it could produce a false sense of safety.

Section openers establish context until `!`, `exit`, `end`, or another top-level section:

```text
interface GigabitEthernet1/0/1   <- interface section
 switchport mode access          <- belongs to that interface
!
line vty 0 4                     <- VTY line section
 transport input ssh             <- belongs only to those VTY lines
```

Named ACLs and routing processes work the same way. Numbered `access-list` commands are
single-line ACL contexts. Global `aaa` and `snmp-server` declarations remain global facts,
while AAA server groups have their own section. Exclamation comments are separators, never
configuration commands.

## 3. The intermediate representation

The intermediate representation is a common language between parsers and security rules.
It prevents every rule from re-reading raw text with its own regular expressions.

In Phase 2:

- `CommandRecord` stores sensitive in-memory source text, line location, and context.
- `StructuredObservation` stores a parser fact and the command IDs supporting it.
- `ParsedConfiguration` groups conservative platform identification, commands,
  observations, unsupported syntax, safe diagnostics, status, and completeness counters.

These records are immutable to make later analysis predictable. Identical input produces
identical IDs and output. A parsed result can be `parsed`, `partial`, or `incomplete`. Partial
means some syntax or the exact platform family remains unknown; incomplete means a structure
such as a banner or certificate block was truncated. Neither status is a security judgment.

## 4. Deterministic rules

A rule receives only the parsed representation. It does not open files, contact devices, or
make web requests. Given the same observations, it should return the same conclusion. This
makes behavior explainable and testable.

Rules need more than pass/fail:

- **Confirmed insecure** means the configuration explicitly demonstrates the condition.
- **Potential risk** means the evidence suggests risk but external context could change it.
- **Hardening** is a best-practice improvement, not automatically a vulnerability.
- **Not applicable** means the feature or device role clearly does not require the check.
- **Unknown** means the file lacks enough evidence to decide.
- **Not evaluated** means a prerequisite or analysis capability was unavailable.
- **Unsupported syntax** means relevant commands exist but the parser cannot interpret them.

`secure` must be earned by adequate evidence. It is not the default when nothing is found.

Severity describes possible security impact. Confidence describes how strongly the available
configuration supports the conclusion. A high-impact idea can still have low confidence,
and a clear low-impact hardening issue can have high confidence. Keeping these axes separate
prevents exaggerated findings.

Phase 3 implements five rules. Each asks a narrow question that the parser can support. For
example, the Telnet rule reads `line.declaration` and `line.transport` observations. It does
not search the raw file for the word `telnet`, so a description such as
`description TELNET-LABEL` cannot create a finding.

Order matters for commands that replace state:

```text
ip http server
no ip http server
```

The last supported declaration disables plaintext HTTP. Reversing the two lines enables it.
The same effective-state approach is used for SSH version and repeated VTY transport
commands. SNMP communities receive opaque document-local IDs, allowing a later `no
snmp-server community ...` to remove the correct declaration without storing the community
value in observations.

The `RuleRegistry` fixes execution order and rejects duplicate IDs. `AnalysisEngine` runs one
rule at a time. If a rule fails, the other rules continue and the failure becomes a safe
operational diagnostic plus `NOT_EVALUATED`, never a vulnerability.

## 5. Evidence without secret leakage

A useful finding points to the relevant command and line. Copying raw commands directly into
reports is dangerous because many commands embed secrets. ConfigGuard rules therefore return
opaque evidence references. A central sanitizer resolves those references, recognizes
secret-bearing syntax, masks sensitive values, and emits a safe excerpt such as a command
shape plus `[REDACTED]`.

Centralization matters: if each rule redacts independently, one forgotten code path can leak
a credential. Supported credential commands keep a useful command shape but replace values
with `[REDACTED]`. Unknown commands, banner bodies, and certificate bodies are shown only as
`[REDACTED]`. Future report renderers will accept sanitized evidence only.

## 6. What one configuration cannot prove

A `running-config` snapshot normally cannot prove Internet reachability, upstream firewalls,
physical port use, device role, runtime protocol neighbors, effective defaults, image
vulnerabilities, or whether a control is enforced elsewhere. It can also be incomplete or
stale. Rules must name these limitations and prefer `unknown` or `potential_risk` when a
stronger conclusion is not justified.

For example, the absence of DHCP snooping is not automatically a vulnerability on a router
with no access-layer switching role. Likewise, an ACL that looks broad may be constrained by
topology that the file does not reveal.

## 7. Interfaces stay thin

The CLI and any future local web interface are two doors into one analysis engine. They should
handle user interaction and presentation, then call the same parser, rules, sanitizer, and
report model. This avoids different findings for the same file depending on the interface.

Phase 4 reporting reinforced the same trust boundaries at the interface layer:

- Renderers should consume one sanitized assessment model, not parser command records. This
  prevents terminal, JSON, and HTML implementations from independently reaching raw input.
- Assessment completion and security outcome are separate axes. Exit code `0` means the tool
  completed; it does not mean the configuration is secure. Partial evidence receives its own
  exit code and never becomes an implicit pass.
- Deterministic JSON is easier to automate and test when it excludes timestamps, absolute
  source paths, and host-specific metadata.
- Safe file export needs both no-overwrite publication and failure cleanup. A completed
  temporary UTF-8 file can be linked to a new destination without replacing an existing
  report.
- HTML escaping and a restrictive Content Security Policy are complementary controls because
  even sanitized configuration evidence remains untrusted display content.

Phase 4 stops after the CLI and terminal/JSON/HTML reporting. The result is still a limited
static assessment without scoring, runtime reachability, device connectivity, an API, a
frontend, PDF generation, automatic remediation, or exploitability claims.

## 8. Real configurations require rule-scoped uncertainty

Phase 4.1 validation showed that parser completeness and rule completeness are related but
not interchangeable. Valid Multilink PPP and serial-interface timing commands were initially
unclassified even though they cannot change the five implemented rule states. Recognizing
those command families removes misleading parser noise without adding security conclusions.

Conversely, unsupported syntax must carry a narrow rule scope when its command family can
change an implemented result. A malformed transport command can block the VTY conclusion,
and malformed community syntax must block both SNMP community checks. An unrelated global or
line command must not turn an explicit supported result into uncertainty.

Real configuration validation also confirmed that missing explicit VTY transport and SSH
version selections remain legitimately unknown. ConfigGuard does not fill those gaps with
assumed Cisco defaults. Reports now explain the additional evidence needed and visually
separate adverse findings, passing observations, uncertainty, and operational diagnostics.

## 9. Phase 5A: effective management state crosses contexts

The next management checks cannot be implemented as isolated keyword matches. An inbound VTY
restriction connects an ordered line binding to an ordered named or numbered ACL. Login
authentication connects each effective VTY or console range to local-user state or a named
AAA method list and, where used, a server-group reference. Later overlapping line sections
replace state only for the selected line numbers.

This cross-context resolution also sharpens uncertainty. An outbound `access-class` does not
prove an inbound restriction. A missing ACL or AAA method list is Unknown, and unsupported
syntax inside a referenced ACL blocks only the source-restriction rule. Unrelated switchport
syntax may make parser completeness partial without turning explicit management results into
false passes or findings.

Credential observations require an additional privacy boundary. Phase 5A assigns local
principals opaque document-local IDs so effective negation can be resolved without retaining
usernames in structured observations. Only explicit password type 0 supports a plaintext
finding. Untyped values remain Unknown; hashes, secrets, and encoded forms are still redacted
but are not certified as strong. `NOT_APPLICABLE` for this narrow detector means no effective
supported type 0 value was proved—it is not a general credential-security pass.

Phase 5A ended with eight deterministic rules and intentionally added no Layer 2 conclusion.

## 10. Phase 5B: Layer 2 evidence is role-dependent

Layer 2 checks demonstrate why configuration presence and operational security are different
claims. Port Security on an access-mode interface does not prove the port serves an untrusted
endpoint, DHCP Snooping trust on a trunk can be a legitimate uplink, and PortFast does not by
itself prove that BPDU Guard is effective. The three Phase 5B rules therefore require explicit
supported state and report narrow configuration-visible conclusions.

Command order and scope remain essential. A later negation can disable Port Security, remove
a VLAN from the DHCP Snooping set, or remove a per-interface BPDU Guard override so the global
default applies again. Unknown syntax in one of these command families blocks only the rule
whose effective state it could change; an unrelated Layer 2 command does not erase supported
management findings or the other Layer 2 results.

Absence is handled conservatively. Missing Port Security, DHCP Snooping, or BPDU Guard is not
automatically an exploitable vulnerability because the device role, physical attachment,
templates, port channels, and compensating controls are outside one file. Router-only input
and explicit non-applicable port contexts can be Not Applicable, while unresolved access,
VLAN, trust, or inheritance evidence stays Unknown. Phase 5B ended with eleven rules and no
DAI conclusion, numerical score, Critical severity, runtime probing, or device connection.

## 11. Phase 5C: DAI needs both a trust boundary and a validation source

Dynamic ARP Inspection is enabled per VLAN, but that declaration alone does not establish
which interfaces bypass validation or where valid address bindings come from. Phase 5C
therefore correlates the effective DAI VLAN set with explicit access VLANs, interface trust,
and the supported DHCP Snooping configuration. The two rules remain separate: DHCP Snooping
assesses DHCP trust configuration, while DAI consumes only the prerequisite facts it needs.

Even when both declarations are present, a static file cannot prove that the live DHCP
binding database is valid. The DAI result can report that supported configuration-visible
prerequisites are present, but its limitation must retain that runtime uncertainty. Conversely,
missing DHCP Snooping does not prove DAI is useless because static ARP validation may exist.
When such alternative syntax is present but not modeled, the result is Unsupported Syntax;
when no supported binding source is established, it remains Unknown.

Trust also requires port context. Explicit trust on an access-mode interface is a potential
risk pending validation of its real role; the same declaration on a trunk is not automatically
wrong. Explicit DAI removal from an identified access VLAN is a hardening observation, not a
confirmed exploit. Interface ranges, templates, and port-channel inheritance stay unresolved
in this phase. The registry now contains twelve rules, with no additional security rule,
scoring, device connection, or automatic remediation added by Phase 5C.
