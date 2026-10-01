"""Data model of the policy engine: rules, settings, matches and decisions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .conditions import Condition

ACTION_ALERT = "alert"
ACTION_QUARANTINE = "quarantine"
ACTION_BLOCK = "block"
KNOWN_ACTIONS: tuple[str, ...] = (ACTION_ALERT, ACTION_QUARANTINE, ACTION_BLOCK)

# Alert is additive. Quarantine and block are dispositions: a file gets at most one, and
# the stronger one wins.
DISPOSITION_STRENGTH: Mapping[str, int] = {ACTION_QUARANTINE: 1, ACTION_BLOCK: 2}

CONFLICT_PRIORITY = "priority"
CONFLICT_MOST_RESTRICTIVE = "most_restrictive"
CONFLICT_STRATEGIES: tuple[str, ...] = (CONFLICT_PRIORITY, CONFLICT_MOST_RESTRICTIVE)


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @property
    def default_priority(self) -> int:
        return self * 10

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity {value!r}") from None


SEVERITY_LABELS: tuple[str, ...] = tuple(severity.label for severity in Severity)


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    severity: Severity
    priority: int
    actions: tuple[str, ...]
    condition: Condition
    description: str = ""
    enabled: bool = True


@dataclass(frozen=True, slots=True)
class Settings:
    corporate_domains: tuple[str, ...] = ()
    trusted_domains: tuple[str, ...] = ()
    conflict_resolution: str = CONFLICT_PRIORITY


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    rules: tuple[Rule, ...]
    settings: Settings = field(default_factory=Settings)
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A rule whose condition held for one evaluation."""

    rule: Rule
    matched_types: tuple[str, ...]
    counts: Mapping[str, int]
    suppressed_by: str | None = None

    @property
    def suppressed(self) -> bool:
        return self.suppressed_by is not None


@dataclass(frozen=True, slots=True)
class Decision:
    """Outcome of one evaluation: every triggered rule plus the actions that win."""

    matches: tuple[RuleMatch, ...] = ()
    actions: tuple[str, ...] = ()
    severity: Severity | None = None
    categories: frozenset[str] = frozenset()
    strategy: str = CONFLICT_PRIORITY

    @property
    def triggered(self) -> bool:
        return bool(self.matches)

    @property
    def winning(self) -> tuple[RuleMatch, ...]:
        return tuple(match for match in self.matches if not match.suppressed)

    @property
    def suppressed(self) -> tuple[RuleMatch, ...]:
        return tuple(match for match in self.matches if match.suppressed)

    @property
    def disposition(self) -> str | None:
        """The single enforcement action (quarantine or block), if any."""
        return next((a for a in self.actions if a in DISPOSITION_STRENGTH), None)
