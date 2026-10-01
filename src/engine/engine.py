"""PolicyEngine: matches detector findings and a destination against declarative rules."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from src.detectors.base import Finding
from src.detectors.scanner import count_by_type

from .conditions import EvalContext
from .destination import Destination
from .loader import load_policy_file, load_policy_text
from .models import (
    ACTION_ALERT,
    CONFLICT_MOST_RESTRICTIVE,
    DISPOSITION_STRENGTH,
    Decision,
    PolicyConfig,
    Rule,
    RuleMatch,
    Settings,
)

DestinationLike = Destination | str | Iterable[str]


class PolicyEngine:
    """Evaluates findings and a destination against the rules of a policy.

    ``match`` returns every rule that fired. ``evaluate`` also resolves conflicts between
    them and returns the actions that win:

    * ``priority`` (default): only the rules with the highest priority decide the actions;
      lower-priority matches are still reported, flagged as suppressed. This lets a
      high-priority rule act as an exception to broader rules.
    * ``most_restrictive``: the actions of all matching rules are combined.

    In both modes ``alert`` is additive, while quarantine and block are mutually exclusive
    dispositions and the stronger one (block) wins.
    """

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    @classmethod
    def from_file(cls, path: str | Path) -> PolicyEngine:
        return cls(load_policy_file(path))

    @classmethod
    def from_text(cls, text: str) -> PolicyEngine:
        return cls(load_policy_text(text))

    @property
    def rules(self) -> tuple[Rule, ...]:
        return self.config.rules

    @property
    def settings(self) -> Settings:
        return self.config.settings

    def categorize(self, destination: DestinationLike) -> frozenset[str]:
        """Risk categories of a destination, using the configured corporate/trusted domains."""
        if isinstance(destination, Destination):
            return destination.categories(
                self.settings.corporate_domains, self.settings.trusted_domains
            )
        if isinstance(destination, str):
            return frozenset({destination})
        return frozenset(destination)

    def match(self, findings: Iterable[Finding], destination: DestinationLike) -> list[RuleMatch]:
        """All rules triggered by the findings and destination, strongest rule first."""
        ctx = EvalContext(dict(count_by_type(findings)), self.categorize(destination))
        triggered: list[tuple[int, RuleMatch]] = []
        for order, rule in enumerate(self.rules):
            if not rule.enabled:
                continue
            outcome = rule.condition.evaluate(ctx)
            if outcome.matched:
                types = tuple(sorted(outcome.types))
                counts = {data_type: ctx.counts[data_type] for data_type in types}
                triggered.append((order, RuleMatch(rule, types, counts)))
        triggered.sort(key=lambda item: (-item[1].rule.priority, -item[1].rule.severity, item[0]))
        return [match for _, match in triggered]

    def evaluate(self, findings: Iterable[Finding], destination: DestinationLike) -> Decision:
        """Match the rules and resolve conflicts between the ones that fired."""
        categories = self.categorize(destination)
        matches = self.match(findings, categories)
        strategy = self.settings.conflict_resolution
        if not matches:
            return Decision(categories=categories, strategy=strategy)

        if strategy == CONFLICT_MOST_RESTRICTIVE:
            deciders = matches
        else:
            top = matches[0]
            deciders = [m for m in matches if m.rule.priority == top.rule.priority]
            matches = [
                m if m in deciders else RuleMatch(m.rule, m.matched_types, m.counts, top.rule.name)
                for m in matches
            ]

        return Decision(
            matches=tuple(matches),
            actions=_combine_actions(deciders),
            severity=max(m.rule.severity for m in deciders),
            categories=categories,
            strategy=strategy,
        )


def _combine_actions(deciders: Iterable[RuleMatch]) -> tuple[str, ...]:
    """Union of actions, keeping only the strongest disposition; the disposition runs first."""
    declared = {action for match in deciders for action in match.rule.actions}
    dispositions = [action for action in declared if action in DISPOSITION_STRENGTH]
    actions: list[str] = []
    if dispositions:
        actions.append(max(dispositions, key=DISPOSITION_STRENGTH.__getitem__))
    if ACTION_ALERT in declared:
        actions.append(ACTION_ALERT)
    return tuple(actions)
