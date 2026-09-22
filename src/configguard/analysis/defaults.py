"""Construction helpers for the approved Phase 3 analysis stack."""

from configguard.analysis.engine import AnalysisEngine
from configguard.analysis.registry import RuleRegistry
from configguard.rules import initial_rules
from configguard.sanitization import CiscoEvidenceSanitizer


def default_rule_registry() -> RuleRegistry:
    """Return a registry containing exactly the five Phase 3 rules."""

    return RuleRegistry(initial_rules())


def default_analysis_engine() -> AnalysisEngine:
    """Return the shared engine with the central Cisco evidence sanitizer."""

    return AnalysisEngine(default_rule_registry(), CiscoEvidenceSanitizer())
