"""Shared application service for CLI and local-web assessments."""

from __future__ import annotations

import os

from configguard.analysis import default_analysis_engine
from configguard.parsing import (
    CiscoConfigurationParser,
    ConfigurationIngestor,
    ConfigurationSource,
)
from configguard.reporting import AssessmentReport, build_assessment_report


class AssessmentService:
    """Run the existing deterministic assessment pipeline from validated input."""

    def __init__(self, ingestor: ConfigurationIngestor | None = None) -> None:
        self._ingestor = ingestor or ConfigurationIngestor()

    @property
    def max_input_bytes(self) -> int:
        """Return the enforced source byte limit."""

        return self._ingestor.max_bytes

    def assess_path(self, path: str | os.PathLike[str]) -> AssessmentReport:
        """Assess one explicitly selected local path without changing it."""

        return self._assess(self._ingestor.read(path))

    def assess_bytes(self, label: str, data: bytes) -> AssessmentReport:
        """Assess one ephemeral upload without filesystem persistence."""

        return self._assess(self._ingestor.read_bytes(label, data))

    @staticmethod
    def _assess(source: ConfigurationSource) -> AssessmentReport:
        parser = CiscoConfigurationParser()
        support = parser.identify(source)
        configuration = parser.parse(source)
        analysis = default_analysis_engine().analyze(configuration)
        return build_assessment_report(support, configuration, analysis)
