# Learning Guide

## The central idea

A router configuration is not a bag of words. The same word can mean different things in
different sections, and a missing command may mean a platform default, an inherited policy,
an irrelevant feature, or simply an incomplete export. ConfigGuard therefore separates
reading the file, understanding its structure, judging security, and presenting evidence.

## 1. Input is evidence, not executable content

The user exports a configuration and selects it for analysis. ConfigGuard should read a
bounded plain-text snapshot into memory. It never sends commands to the device and never
executes lines from the file. This protects both the network and the workstation running the
tool.

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

The parser then emits *observations*: small facts such as “VTY range 0–4 permits SSH” with
references to the commands that support the fact. It also records syntax it cannot safely
interpret. Unknown syntax is important evidence about assessment completeness; silently
discarding it could produce a false sense of safety.

## 3. The intermediate representation

The intermediate representation is a common language between parsers and security rules.
It prevents every rule from re-reading raw text with its own regular expressions.

In Phase 1:

- `CommandRecord` stores sensitive in-memory source text, line location, and context.
- `StructuredObservation` stores a parser fact and the command IDs supporting it.
- `ParsedConfiguration` groups platform identification, commands, observations, and
  unsupported syntax.

These records are immutable to make later analysis predictable. The generic observation
shape is a starting contract, not a promise that all future facts should be untyped maps.
When Phase 2 proves stable concepts, focused observation types can replace generic fields.

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

## 5. Evidence without secret leakage

A useful finding points to the relevant command and line. Copying raw commands directly into
reports is dangerous because many commands embed secrets. ConfigGuard rules therefore return
opaque evidence references. A central sanitizer resolves those references, recognizes
secret-bearing syntax, masks sensitive values, and emits a safe excerpt such as a command
shape plus `[REDACTED]`.

Centralization matters: if each rule redacts independently, one forgotten code path can leak
a credential. Future report renderers will accept sanitized evidence only.

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

The eventual CLI and local web interface are two doors into one analysis engine. They should
handle user interaction and presentation, then call the same parser, rules, sanitizer, and
report model. This avoids different findings for the same file depending on the interface.

Phase 1 stops at contracts and design. Phase 2 should prove safe ingestion, context parsing,
and redaction before any security rules are trusted.
