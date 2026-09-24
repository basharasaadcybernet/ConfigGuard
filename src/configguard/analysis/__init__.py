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
from configguard.analysis.routing_resolution import (
    ResolvedRoutingTarget,
    RoutingAuthenticationResolution,
    RoutingAuthenticationStatus,
    resolve_routing_authentication,
)

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
    "ResolvedRoutingTarget",
    "RoutingAuthenticationResolution",
    "RoutingAuthenticationStatus",
    "RuleRegistry",
    "default_analysis_engine",
    "default_rule_registry",
    "resolve_interface_configuration",
    "resolve_routing_authentication",
]
