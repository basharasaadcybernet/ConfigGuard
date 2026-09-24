"""Bounded parser for the explicitly supported IOS interface-range subset."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

MAX_INTERFACE_RANGE_TARGETS = 128


class InterfaceRangeStatus(StrEnum):
    """Safe, bounded result of parsing an interface-range expression."""

    SUPPORTED = "supported"
    MALFORMED = "malformed"
    AMBIGUOUS = "ambiguous"
    OVERSIZED = "oversized"
    UNSUPPORTED_TYPE = "unsupported_type"


@dataclass(frozen=True, slots=True)
class InterfaceRangeParseResult:
    """Canonical targets, or a reason that expansion was not safe."""

    status: InterfaceRangeStatus
    targets: tuple[str, ...] = ()

    @property
    def supported(self) -> bool:
        return self.status is InterfaceRangeStatus.SUPPORTED


_PREFIXES = {
    "gigabitethernet": "GigabitEthernet",
    "gi": "GigabitEthernet",
    "fastethernet": "FastEthernet",
    "fa": "FastEthernet",
    "tengigabitethernet": "TenGigabitEthernet",
    "te": "TenGigabitEthernet",
}
_INTERFACE_PATTERN = re.compile(
    r"^(?P<prefix>GigabitEthernet|FastEthernet|TenGigabitEthernet|Gi|Fa|Te)"
    r"(?P<path>\d+(?:/\d+)+)$",
    re.IGNORECASE,
)


def parse_interface_range(
    expression: str,
    *,
    maximum_targets: int = MAX_INTERFACE_RANGE_TARGETS,
) -> InterfaceRangeParseResult:
    """Expand a conservative subset without guessing platform-specific syntax."""

    if maximum_targets < 1:
        raise ValueError("maximum_targets must be positive")
    if not expression.strip():
        return InterfaceRangeParseResult(InterfaceRangeStatus.MALFORMED)

    targets: list[str] = []
    seen: set[str] = set()
    for raw_member in expression.split(","):
        member = raw_member.strip()
        if not member:
            return InterfaceRangeParseResult(InterfaceRangeStatus.MALFORMED)
        parts = re.split(r"\s*-\s*", member)
        if len(parts) > 2 or any(not part for part in parts):
            return InterfaceRangeParseResult(InterfaceRangeStatus.AMBIGUOUS)

        start = _canonical_interface(parts[0])
        if start is None:
            return InterfaceRangeParseResult(InterfaceRangeStatus.UNSUPPORTED_TYPE)
        member_targets = iter((start,))
        if len(parts) == 2:
            bounds = _contiguous_bounds(start, parts[1])
            if bounds is None:
                return InterfaceRangeParseResult(InterfaceRangeStatus.AMBIGUOUS)
            prefix, path_prefix, start_index, end_index = bounds
            member_targets = (
                f"{prefix}{path_prefix}/{index}" for index in range(start_index, end_index + 1)
            )

        for target in member_targets:
            if target in seen:
                continue
            if len(targets) >= maximum_targets:
                return InterfaceRangeParseResult(InterfaceRangeStatus.OVERSIZED)
            targets.append(target)
            seen.add(target)

    return InterfaceRangeParseResult(InterfaceRangeStatus.SUPPORTED, tuple(targets))


def canonical_interface_name(value: str) -> str | None:
    """Return the canonical name for one supported physical interface spelling."""

    return _canonical_interface(value)


def _canonical_interface(value: str) -> str | None:
    match = _INTERFACE_PATTERN.fullmatch(value.strip())
    if match is None:
        return None
    prefix = _PREFIXES[match.group("prefix").lower()]
    return f"{prefix}{match.group('path')}"


def _contiguous_bounds(start: str, end_value: str) -> tuple[str, str, int, int] | None:
    start_match = _INTERFACE_PATTERN.fullmatch(start)
    if start_match is None:
        return None
    start_path = start_match.group("path")
    path_prefix, start_index_text = start_path.rsplit("/", 1)
    start_index = int(start_index_text)

    if end_value.strip().isdigit():
        end_index = int(end_value.strip())
    else:
        canonical_end = _canonical_interface(end_value)
        if canonical_end is None:
            return None
        end_match = _INTERFACE_PATTERN.fullmatch(canonical_end)
        if end_match is None or end_match.group("prefix") != start_match.group("prefix"):
            return None
        end_path_prefix, end_index_text = end_match.group("path").rsplit("/", 1)
        if end_path_prefix != path_prefix:
            return None
        end_index = int(end_index_text)

    if end_index < start_index:
        return None
    prefix = start_match.group("prefix")
    return prefix, path_prefix, start_index, end_index
