"""Shared deterministic configuration security analysis."""

from configguard.analysis.defaults import default_analysis_engine, default_rule_registry
from configguard.analysis.engine import AnalysisEngine
from configguard.analysis.interface_resolution import (
    InterfaceFactOrigin,
    InterfaceResolution,
    InterfaceResolutionIssue,
    PortChannelRelationship,
    ResolvedInterfaceObservation,
    resolve_interface_configuration,
)
from configguard.analysis.models import (
    AnalysisDiagnostic,
    AnalysisDiagnosticKind,
    AnalysisResult,
    Finding,
)
from configguard.analysis.registry import DuplicateRuleError, RuleRegistry

__all__ = [
    "AnalysisDiagnostic",
    "AnalysisDiagnosticKind",
    "AnalysisEngine",
    "AnalysisResult",
    "DuplicateRuleError",
    "Finding",
    "InterfaceFactOrigin",
    "InterfaceResolution",
    "InterfaceResolutionIssue",
    "PortChannelRelationship",
    "ResolvedInterfaceObservation",
    "RuleRegistry",
    "default_analysis_engine",
    "default_rule_registry",
    "resolve_interface_configuration",
]
