"""Condition tree of a rule. Each node evaluates to a match flag plus the evidence types."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class EvalContext:
    """Facts a condition is evaluated against."""

    counts: Mapping[str, int]
    destinations: frozenset[str]


@dataclass(frozen=True, slots=True)
class Outcome:
    matched: bool
    types: frozenset[str] = frozenset()


NO_MATCH = Outcome(False)


class Condition(Protocol):
    def evaluate(self, ctx: EvalContext) -> Outcome: ...


@dataclass(frozen=True, slots=True)
class TypeMatcher:
    """Holds when a data type occurs at least ``min_count`` (and at most ``max_count``) times."""

    type: str
    min_count: int = 1
    max_count: int | None = None

    def satisfied(self, counts: Mapping[str, int]) -> bool:
        found = counts.get(self.type, 0)
        return found >= self.min_count and (self.max_count is None or found <= self.max_count)


@dataclass(frozen=True, slots=True)
class Contains:
    """``contains`` (any matcher holds) or ``contains_all`` (every matcher holds)."""

    matchers: tuple[TypeMatcher, ...]
    require_all: bool = False

    def evaluate(self, ctx: EvalContext) -> Outcome:
        satisfied = [m.type for m in self.matchers if m.satisfied(ctx.counts)]
        matched = len(satisfied) == len(self.matchers) if self.require_all else bool(satisfied)
        return Outcome(True, frozenset(satisfied)) if matched else NO_MATCH


@dataclass(frozen=True, slots=True)
class DestinationIn:
    """Holds when the destination belongs to at least one of the listed categories."""

    categories: frozenset[str]

    def evaluate(self, ctx: EvalContext) -> Outcome:
        return Outcome(True) if self.categories & ctx.destinations else NO_MATCH


@dataclass(frozen=True, slots=True)
class AllOf:
    children: Sequence[Condition]

    def evaluate(self, ctx: EvalContext) -> Outcome:
        types: set[str] = set()
        for child in self.children:
            outcome = child.evaluate(ctx)
            if not outcome.matched:
                return NO_MATCH
            types |= outcome.types
        return Outcome(True, frozenset(types))


@dataclass(frozen=True, slots=True)
class AnyOf:
    children: Sequence[Condition]

    def evaluate(self, ctx: EvalContext) -> Outcome:
        types: set[str] = set()
        matched = False
        for child in self.children:
            outcome = child.evaluate(ctx)
            if outcome.matched:
                matched = True
                types |= outcome.types
        return Outcome(True, frozenset(types)) if matched else NO_MATCH


@dataclass(frozen=True, slots=True)
class Not:
    child: Condition

    def evaluate(self, ctx: EvalContext) -> Outcome:
        return NO_MATCH if self.child.evaluate(ctx).matched else Outcome(True)
