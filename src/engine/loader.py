"""Loads and strictly validates declarative YAML policies.

Validation collects every problem it can find, so ``policy validate`` reports them all in
one run instead of one per attempt. Typos in keys, unknown data types, destination
categories or actions are errors, never silently ignored: a misspelled condition in a
security policy must not turn into a rule that never fires.
"""

from __future__ import annotations

import difflib
import re
from collections.abc import Collection, Mapping
from pathlib import Path
from typing import Any

import yaml

from src.detectors.scanner import KNOWN_DATA_TYPES

from .conditions import (
    AllOf,
    AnyOf,
    Condition,
    Contains,
    DestinationIn,
    Not,
    TypeMatcher,
)
from .destination import KNOWN_DESTINATIONS
from .models import (
    ACTION_BLOCK,
    ACTION_QUARANTINE,
    CONFLICT_PRIORITY,
    CONFLICT_STRATEGIES,
    KNOWN_ACTIONS,
    SEVERITY_LABELS,
    PolicyConfig,
    Rule,
    Settings,
    Severity,
)

SUPPORTED_VERSION = 1
MAX_CONDITION_DEPTH = 16
MAX_PRIORITY = 1000

_RULE_KEYS = ("rule", "description", "severity", "priority", "enabled", "condition", "action")
_CONDITION_KEYS = ("contains", "contains_all", "destination", "all_of", "any_of", "not")
_TOP_LEVEL_KEYS = ("version", "settings", "rules")
_SETTINGS_KEYS = ("corporate_domains", "trusted_domains", "conflict_resolution")
_MATCHER_KEYS = ("type", "min_count", "max_count")

_RULE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_DOMAIN = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")


class PolicyValidationError(ValueError):
    """Raised for an unreadable or invalid policy; ``errors`` lists every problem found."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of keeping the last one."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    f"duplicate key {key!r}",
                    key_node.start_mark,
                )
            seen.add(key)
        return super().construct_mapping(node, deep)


def load_policy_file(path: str | Path, **kwargs: Any) -> PolicyConfig:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        reason = exc.strerror or str(exc)
        raise PolicyValidationError([f"cannot read policy file {path}: {reason}"]) from exc
    return load_policy_text(text, **kwargs)


def load_policy_text(
    text: str,
    *,
    known_types: Collection[str] = KNOWN_DATA_TYPES,
    known_destinations: Collection[str] = KNOWN_DESTINATIONS,
) -> PolicyConfig:
    try:
        document = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (line {mark.line + 1}, column {mark.column + 1})" if mark else ""
        problem = getattr(exc, "problem", None) or str(exc)
        raise PolicyValidationError([f"invalid YAML{where}: {problem}"]) from exc

    parser = _Parser(set(known_types), set(known_destinations))
    config = parser.parse(document)
    if parser.errors:
        raise PolicyValidationError(parser.errors)
    return config


def _suggest(key: str, options: Collection[str]) -> str:
    close = difflib.get_close_matches(str(key), list(options), n=1)
    return f" (did you mean {close[0]!r}?)" if close else ""


class _Parser:
    def __init__(self, known_types: set[str], known_destinations: set[str]) -> None:
        self.known_types = known_types
        self.known_destinations = known_destinations
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def error(self, path: str, message: str) -> None:
        self.errors.append(f"{path}: {message}")

    # -- document ---------------------------------------------------------------------------

    def parse(self, document: Any) -> PolicyConfig:
        if not isinstance(document, Mapping):
            self.error("policy", "top level must be a mapping with a 'rules' list")
            return PolicyConfig(rules=())
        self._check_keys(document, _TOP_LEVEL_KEYS, "policy")

        version = document.get("version", SUPPORTED_VERSION)
        if version != SUPPORTED_VERSION or isinstance(version, bool):
            self.error("version", f"unsupported version {version!r}; expected {SUPPORTED_VERSION}")

        settings = self._parse_settings(document.get("settings") or {})
        rules = self._parse_rules(document.get("rules"))
        return PolicyConfig(rules=tuple(rules), settings=settings, warnings=tuple(self.warnings))

    def _check_keys(self, mapping: Mapping[Any, Any], allowed: Collection[str], path: str) -> None:
        for key in mapping:
            if key not in allowed:
                self.error(path, f"unknown key {key!r}{_suggest(key, allowed)}")

    # -- settings ---------------------------------------------------------------------------

    def _parse_settings(self, raw: Any) -> Settings:
        if not isinstance(raw, Mapping):
            self.error("settings", "must be a mapping")
            return Settings()
        self._check_keys(raw, _SETTINGS_KEYS, "settings")

        strategy = raw.get("conflict_resolution", CONFLICT_PRIORITY)
        if strategy not in CONFLICT_STRATEGIES:
            self.error(
                "settings.conflict_resolution",
                f"must be one of {', '.join(CONFLICT_STRATEGIES)}, got {strategy!r}",
            )
            strategy = CONFLICT_PRIORITY
        corporate = self._parse_domains(raw.get("corporate_domains"), "corporate_domains")
        trusted = self._parse_domains(raw.get("trusted_domains"), "trusted_domains")
        return Settings(corporate, trusted, strategy)

    def _parse_domains(self, raw: Any, name: str) -> tuple[str, ...]:
        path = f"settings.{name}"
        if raw is None:
            return ()
        if not isinstance(raw, list):
            self.error(path, "must be a list of domain names")
            return ()
        domains: list[str] = []
        for index, item in enumerate(raw):
            domain = item.strip().lower() if isinstance(item, str) else item
            if not isinstance(domain, str) or not _DOMAIN.match(domain):
                self.error(f"{path}[{index}]", f"{item!r} is not a valid domain name")
            elif domain not in domains:
                domains.append(domain)
        return tuple(domains)

    # -- rules ------------------------------------------------------------------------------

    def _parse_rules(self, raw: Any) -> list[Rule]:
        if not isinstance(raw, list) or not raw:
            self.error("rules", "must be a non-empty list")
            return []
        rules: list[Rule] = []
        names: set[str] = set()
        for index, item in enumerate(raw):
            rule = self._parse_rule(item, index, names)
            if rule is not None:
                rules.append(rule)
        return rules

    def _parse_rule(self, raw: Any, index: int, names: set[str]) -> Rule | None:
        path = f"rules[{index}]"
        if not isinstance(raw, Mapping):
            self.error(path, "must be a mapping")
            return None
        errors_before = len(self.errors)
        self._check_keys(raw, _RULE_KEYS, path)

        name = raw.get("rule")
        if not isinstance(name, str) or not _RULE_NAME.match(name):
            self.error(f"{path}.rule", self._bad_name_message(name))
            name = f"<unnamed rule #{index}>"
        elif name in names:
            self.error(f"{path}.rule", f"duplicate rule name {name!r}")
        names.add(name)
        path = f"{path} ({name})"

        severity = self._parse_severity(raw.get("severity"), path)
        priority = self._parse_priority(raw.get("priority"), severity, path)
        actions = self._parse_actions(raw.get("action"), path)

        description = raw.get("description", "")
        if not isinstance(description, str):
            self.error(f"{path}.description", "must be a string")
            description = ""
        enabled = raw.get("enabled", True)
        if not isinstance(enabled, bool):
            self.error(f"{path}.enabled", "must be true or false")
            enabled = True

        if "condition" not in raw:
            self.error(f"{path}.condition", "required")
            condition = None
        else:
            condition = self._parse_condition(raw["condition"], f"{path}.condition", depth=0)

        if len(self.errors) > errors_before or condition is None or severity is None:
            return None
        return Rule(
            name=name,
            severity=severity,
            priority=priority,
            actions=actions,
            condition=condition,
            description=description,
            enabled=enabled,
        )

    @staticmethod
    def _bad_name_message(name: Any) -> str:
        rules = "letters, digits, '_', '-', '.', starting with a letter, at most 64 characters"
        if name is None:
            return f"required; {rules}"
        if not isinstance(name, str):
            # YAML 1.1 reads unquoted yes/no/on/off as booleans and 123 as a number.
            return f"must be a string, got {name!r}; quote the name if it looks like a YAML literal"
        return f"{name!r} is not a valid rule name; use {rules}"

    def _parse_severity(self, raw: Any, path: str) -> Severity | None:
        if not isinstance(raw, str) or raw.strip().lower() not in SEVERITY_LABELS:
            self.error(f"{path}.severity", f"required; one of {', '.join(SEVERITY_LABELS)}")
            return None
        return Severity.parse(raw)

    def _parse_priority(self, raw: Any, severity: Severity | None, path: str) -> int:
        if raw is None:
            return severity.default_priority if severity else 0
        if isinstance(raw, bool) or not isinstance(raw, int) or not 0 <= raw <= MAX_PRIORITY:
            self.error(f"{path}.priority", f"must be an integer between 0 and {MAX_PRIORITY}")
            return 0
        return raw

    def _parse_actions(self, raw: Any, path: str) -> tuple[str, ...]:
        items = [raw] if isinstance(raw, str) else raw
        if not isinstance(items, list) or not items:
            self.error(f"{path}.action", f"required; a list of {', '.join(KNOWN_ACTIONS)}")
            return ()
        actions: list[str] = []
        for index, item in enumerate(items):
            if item not in KNOWN_ACTIONS:
                self.error(
                    f"{path}.action[{index}]",
                    f"unknown action {item!r}{_suggest(str(item), KNOWN_ACTIONS)}; "
                    f"expected one of {', '.join(KNOWN_ACTIONS)}",
                )
            elif item not in actions:
                actions.append(item)
        if ACTION_QUARANTINE in actions and ACTION_BLOCK in actions:
            self.warnings.append(
                f"{path}: lists both 'quarantine' and 'block'; only the stronger one, "
                "'block', is applied"
            )
        return tuple(actions)

    # -- conditions -------------------------------------------------------------------------

    def _parse_condition(self, raw: Any, path: str, depth: int) -> Condition | None:
        if depth > MAX_CONDITION_DEPTH:
            self.error(path, f"conditions are nested deeper than {MAX_CONDITION_DEPTH} levels")
            return None
        if not isinstance(raw, Mapping) or not raw:
            self.error(path, "must be a non-empty mapping of condition keys")
            return None
        self._check_keys(raw, _CONDITION_KEYS, path)

        parts: list[Condition] = []
        failed = any(key not in _CONDITION_KEYS for key in raw)
        for key in _CONDITION_KEYS:
            if key not in raw:
                continue
            node = self._parse_key(key, raw[key], f"{path}.{key}", depth)
            if node is None:
                failed = True
            else:
                parts.append(node)
        if failed:
            return None
        # Sibling keys in one mapping are combined with AND.
        return parts[0] if len(parts) == 1 else AllOf(tuple(parts))

    def _parse_key(self, key: str, raw: Any, path: str, depth: int) -> Condition | None:
        if key in {"contains", "contains_all"}:
            return self._parse_contains(raw, path, require_all=key == "contains_all")
        if key == "destination":
            return self._parse_destination(raw, path)
        if key == "not":
            child = self._parse_condition(raw, path, depth + 1)
            return Not(child) if child else None
        return self._parse_combinator(key, raw, path, depth)

    def _parse_combinator(self, key: str, raw: Any, path: str, depth: int) -> Condition | None:
        if not isinstance(raw, list) or not raw:
            self.error(path, "must be a non-empty list of conditions")
            return None
        children = [
            self._parse_condition(item, f"{path}[{index}]", depth + 1)
            for index, item in enumerate(raw)
        ]
        if any(child is None for child in children):
            return None
        nodes = tuple(child for child in children if child is not None)
        return AllOf(nodes) if key == "all_of" else AnyOf(nodes)

    def _parse_contains(self, raw: Any, path: str, require_all: bool) -> Condition | None:
        items = [raw] if isinstance(raw, (str, Mapping)) else raw
        if not isinstance(items, list) or not items:
            self.error(path, "must be a non-empty list of data types")
            return None
        matchers = [self._parse_matcher(item, f"{path}[{i}]") for i, item in enumerate(items)]
        if any(matcher is None for matcher in matchers):
            return None
        return Contains(tuple(m for m in matchers if m is not None), require_all=require_all)

    def _parse_matcher(self, raw: Any, path: str) -> TypeMatcher | None:
        if isinstance(raw, str):
            raw = {"type": raw}
        if not isinstance(raw, Mapping):
            self.error(path, "must be a data type name or a mapping with 'type'")
            return None
        errors_before = len(self.errors)
        self._check_keys(raw, _MATCHER_KEYS, path)

        data_type = raw.get("type")
        if not isinstance(data_type, str) or data_type not in self.known_types:
            self.error(
                f"{path}.type",
                f"unknown data type {data_type!r}{_suggest(str(data_type), self.known_types)}; "
                f"known types: {', '.join(sorted(self.known_types))}",
            )

        min_count = raw.get("min_count", 1)
        if isinstance(min_count, bool) or not isinstance(min_count, int) or min_count < 1:
            self.error(f"{path}.min_count", "must be an integer >= 1")
        max_count = raw.get("max_count")
        if max_count is not None and (
            isinstance(max_count, bool)
            or not isinstance(max_count, int)
            or (isinstance(min_count, int) and max_count < min_count)
        ):
            self.error(f"{path}.max_count", "must be an integer >= min_count")

        if len(self.errors) > errors_before:
            return None
        return TypeMatcher(type=data_type, min_count=min_count, max_count=max_count)

    def _parse_destination(self, raw: Any, path: str) -> Condition | None:
        items = [raw] if isinstance(raw, str) else raw
        if not isinstance(items, list) or not items:
            self.error(path, "must be a non-empty list of destination categories")
            return None
        categories: set[str] = set()
        valid = True
        for index, item in enumerate(items):
            if not isinstance(item, str) or item not in self.known_destinations:
                valid = False
                self.error(
                    f"{path}[{index}]",
                    f"unknown destination {item!r}{_suggest(str(item), self.known_destinations)}; "
                    f"known: {', '.join(sorted(self.known_destinations))}",
                )
            else:
                categories.add(item)
        return DestinationIn(frozenset(categories)) if valid else None
