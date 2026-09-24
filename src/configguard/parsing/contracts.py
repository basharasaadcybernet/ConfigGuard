"""Interfaces implemented by future Cisco IOS and IOS XE parsers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from configguard.domain import ParsedConfiguration, PlatformFamily


@dataclass(frozen=True, slots=True)
class ConfigurationSource:
    """Ephemeral text supplied to a parser after input validation."""

    label: str = field(repr=False)
    text: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ParserSupport:
    """Conservative syntax-identification result."""

    platform: PlatformFamily
    confidence: float
    reason: str
    compatible: bool = False

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


@runtime_checkable
class ConfigurationParser(Protocol):
    """A context-aware parser; implementations must not perform I/O."""

    @property
    def name(self) -> str:
        """Return a stable parser name."""
        ...

    @property
    def version(self) -> str:
        """Return the parser contract or implementation version."""
        ...

    def identify(self, source: ConfigurationSource) -> ParserSupport:
        """Identify whether the parser supports the supplied syntax."""
        ...

    def parse(self, source: ConfigurationSource) -> ParsedConfiguration:
        """Parse validated, in-memory text into structured observations."""
        ...
