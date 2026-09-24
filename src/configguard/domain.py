"""Typed domain contracts shared by parsers, rules, and future interfaces."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType


class PlatformFamily(StrEnum):
    """Platform identification reported by a parser."""

    CISCO_IOS = "cisco_ios"
    CISCO_IOS_XE = "cisco_ios_xe"
    UNKNOWN = "unknown"
    UNSUPPORTED = "unsupported"


class ContextKind(StrEnum):
    """Configuration scopes relevant to the v0.1 parser design."""

    GLOBAL = "global"
    INTERFACE = "interface"
    INTERFACE_TEMPLATE = "interface_template"
    LINE = "line"
    AAA = "aaa"
    ACL = "acl"
    ROUTER = "router"
    VLAN = "vlan"
    CRYPTO = "crypto"
    UNKNOWN = "unknown"


class ParseStatus(StrEnum):
    """How completely the parser understood a supported configuration."""

    PARSED = "parsed"
    PARTIAL = "partial"
    INCOMPLETE = "incomplete"


class DiagnosticKind(StrEnum):
    """Non-finding parser conditions retained for future coverage reporting."""

    UNKNOWN_PLATFORM = "unknown_platform"
    UNSUPPORTED_SYNTAX = "unsupported_syntax"
    MALFORMED_CONFIGURATION = "malformed_configuration"
    INCOMPLETE_CONFIGURATION = "incomplete_configuration"


class Severity(StrEnum):
    """Qualitative security impact; numerical scoring is intentionally absent."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    """How strongly available configuration evidence supports a conclusion."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class AssessmentOutcome(StrEnum):
    """A rule outcome without overstating what one configuration can prove."""

    SECURE = "secure"
    CONFIRMED_INSECURE = "confirmed_insecure"
    POTENTIAL_RISK = "potential_risk"
    HARDENING = "hardening"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"
    NOT_EVALUATED = "not_evaluated"
    UNSUPPORTED_SYNTAX = "unsupported_syntax"


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """One-based location in the in-memory source document."""

    line_start: int
    line_end: int

    def __post_init__(self) -> None:
        if self.line_start < 1:
            raise ValueError("line_start must be one or greater")
        if self.line_end < self.line_start:
            raise ValueError("line_end must not precede line_start")


@dataclass(frozen=True, slots=True)
class ConfigurationContext:
    """The configuration section in which a command was observed."""

    kind: ContextKind
    identifier: str | None = None


@dataclass(frozen=True, slots=True)
class CommandRecord:
    """An in-memory source command with its exact structural context.

    ``text`` can contain secrets and must never cross a reporting or logging
    boundary without centralized sanitization.
    """

    command_id: str
    text: str = field(repr=False)
    location: SourceLocation
    context: ConfigurationContext
    name: str = ""
    arguments: tuple[str, ...] = field(default=(), repr=False)
    parent_context: ConfigurationContext | None = None
    classified: bool = True


type ObservationValue = str | int | bool | tuple[str, ...] | None


@dataclass(frozen=True, slots=True)
class StructuredObservation:
    """A parser-produced fact consumed by deterministic security rules."""

    observation_id: str
    kind: str
    attributes: MappingProxyType[str, ObservationValue]
    source_command_ids: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        observation_id: str,
        kind: str,
        attributes: dict[str, ObservationValue] | None = None,
        source_command_ids: tuple[str, ...] = (),
    ) -> StructuredObservation:
        """Create an immutable observation without retaining a mutable mapping."""

        return cls(
            observation_id=observation_id,
            kind=kind,
            attributes=MappingProxyType(dict(attributes or {})),
            source_command_ids=source_command_ids,
        )


@dataclass(frozen=True, slots=True)
class UnsupportedSyntax:
    """Syntax that could not be safely mapped into the intermediate representation."""

    command_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class ParserDiagnostic:
    """Secret-free diagnostic safe to expose to calling interfaces."""

    kind: DiagnosticKind
    code: str
    message: str
    location: SourceLocation | None = None
    command_id: str | None = None


@dataclass(frozen=True, slots=True)
class ParseMetrics:
    """Deterministic counters for future assessment-completeness calculations."""

    input_line_count: int
    command_count: int
    classified_command_count: int
    unsupported_command_count: int
    observation_count: int

    @classmethod
    def empty(cls) -> ParseMetrics:
        """Return zeroed metrics for contract doubles and compatibility."""

        return cls(0, 0, 0, 0, 0)


@dataclass(frozen=True, slots=True)
class ParsedConfiguration:
    """Parser-neutral intermediate representation for a single configuration."""

    source_label: str
    platform: PlatformFamily
    parser_name: str
    parser_version: str
    commands: tuple[CommandRecord, ...]
    observations: tuple[StructuredObservation, ...]
    unsupported_syntax: tuple[UnsupportedSyntax, ...] = ()
    status: ParseStatus = ParseStatus.PARSED
    diagnostics: tuple[ParserDiagnostic, ...] = ()
    metrics: ParseMetrics = field(default_factory=ParseMetrics.empty)

    def observation(self, observation_id: str) -> StructuredObservation | None:
        """Return an observation by stable document-local identifier."""

        return next(
            (item for item in self.observations if item.observation_id == observation_id),
            None,
        )


@dataclass(frozen=True, slots=True)
class EvidenceReference:
    """A rule's pointer to parser evidence, without copying sensitive command text."""

    observation_id: str
    source_command_ids: tuple[str, ...]
    target_interface: str | None = None
    resolution_origin: str | None = None


@dataclass(frozen=True, slots=True)
class SanitizedEvidence:
    """Evidence approved for logs, user interfaces, and exported reports."""

    location: SourceLocation
    context: ConfigurationContext
    redacted_excerpt: str
    target_interface: str | None = None
    resolution_origin: str | None = None
