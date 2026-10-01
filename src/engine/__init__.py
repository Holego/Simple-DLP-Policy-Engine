"""Declarative policy engine: rule loading, matching and conflict resolution."""

from .destination import KNOWN_DESTINATIONS, Destination
from .engine import PolicyEngine
from .loader import PolicyValidationError, load_policy_file, load_policy_text
from .models import (
    ACTION_ALERT,
    ACTION_BLOCK,
    ACTION_QUARANTINE,
    KNOWN_ACTIONS,
    Decision,
    PolicyConfig,
    Rule,
    RuleMatch,
    Settings,
    Severity,
)

__all__ = [
    "ACTION_ALERT",
    "ACTION_BLOCK",
    "ACTION_QUARANTINE",
    "KNOWN_ACTIONS",
    "KNOWN_DESTINATIONS",
    "Decision",
    "Destination",
    "PolicyConfig",
    "PolicyEngine",
    "PolicyValidationError",
    "Rule",
    "RuleMatch",
    "Settings",
    "Severity",
    "load_policy_file",
    "load_policy_text",
]
