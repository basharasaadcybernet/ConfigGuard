"""Typed, duplicate-safe rule registration."""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from configguard.rules.contracts import SecurityRule


class DuplicateRuleError(ValueError):
    """Raised when two registered rules use the same stable ID."""


class RuleRegistry:
    """An immutable rule sequence whose registration order is execution order."""

    def __init__(self, rules: Iterable[SecurityRule]) -> None:
        registered = tuple(rules)
        seen: set[str] = set()
        for rule in registered:
            rule_id = rule.metadata.rule_id
            if rule_id in seen:
                raise DuplicateRuleError(f"Duplicate rule ID: {rule_id}")
            seen.add(rule_id)
        self._rules = registered

    @property
    def rules(self) -> tuple[SecurityRule, ...]:
        """Return rules in deterministic execution order."""

        return self._rules

    def __iter__(self) -> Iterator[SecurityRule]:
        return iter(self._rules)

    def __len__(self) -> int:
        return len(self._rules)
