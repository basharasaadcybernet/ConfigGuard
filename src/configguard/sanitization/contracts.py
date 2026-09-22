"""Contract for converting sensitive internal evidence to safe output."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from configguard.domain import EvidenceReference, ParsedConfiguration, SanitizedEvidence


@runtime_checkable
class EvidenceSanitizer(Protocol):
    """Resolve evidence references and redact secrets at one output boundary."""

    def sanitize(
        self,
        configuration: ParsedConfiguration,
        references: Sequence[EvidenceReference],
    ) -> tuple[SanitizedEvidence, ...]:
        """Return only evidence safe for display, logs, and reports."""
        ...
