import textwrap

import pytest
import yaml

from src.engine import PolicyValidationError, load_policy_file, load_policy_text
from tests.conftest import EXAMPLE_POLICY

VALID_RULE = """
  - rule: sample
    severity: high
    condition:
      contains: [credit_card]
    action: [alert]
"""


def doc(rules: str = VALID_RULE, header: str = "version: 1\n") -> str:
    return header + "rules:\n" + textwrap.dedent(rules).replace("\n  ", "\n  ")


def errors_for(text: str) -> list[str]:
    with pytest.raises(PolicyValidationError) as excinfo:
        load_policy_text(text)
    return excinfo.value.errors


REMOVE = object()


def one_rule_policy(**overrides) -> str:
    """YAML for a single valid rule; override fields, or pass REMOVE to drop one."""
    rule = {
        "rule": "r",
        "severity": "low",
        "condition": {"contains": ["ssn"]},
        "action": ["alert"],
    }
    rule.update(overrides)
    rule = {key: value for key, value in rule.items() if value is not REMOVE}
    return yaml.safe_dump({"rules": [rule]})


def test_example_policy_is_valid_and_warning_free():
    config = load_policy_file(EXAMPLE_POLICY)
    assert len(config.rules) >= 5
    assert config.warnings == ()


def test_minimal_policy_gets_defaults():
    config = load_policy_text("rules:\n" + VALID_RULE)
    (rule,) = config.rules
    assert rule.priority == 30  # derived from severity high
    assert rule.enabled and rule.description == ""
    assert config.settings.conflict_resolution == "priority"
    assert config.settings.corporate_domains == ()


def test_single_strings_are_accepted_for_list_fields():
    config = load_policy_text(
        "rules:\n"
        "  - rule: r\n    severity: LOW\n    action: alert\n"
        "    condition: {contains: ssn, destination: public_s3}\n"
    )
    assert config.rules[0].actions == ("alert",)
    assert config.rules[0].severity.label == "low"


def test_domains_are_normalised():
    config = load_policy_text(
        "settings: {corporate_domains: [' Corp.Example.com ', corp.example.com]}\n"
        "rules:\n" + VALID_RULE
    )
    assert config.settings.corporate_domains == ("corp.example.com",)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("severity", "urgent", "severity"),
        ("severity", 3, "severity"),
        ("severity", REMOVE, "severity"),
        ("priority", -1, "priority"),
        ("priority", 1001, "priority"),
        ("priority", "high", "priority"),
        ("priority", True, "priority"),
        ("enabled", "maybe", "enabled"),
        ("description", [1], "description"),
    ],
)
def test_invalid_scalar_fields_are_reported(field, value, message):
    errors = errors_for(one_rule_policy(**{field: value}))
    assert any(message in error for error in errors), errors


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        (
            "{contains: [credit_cards]}",
            "unknown data type 'credit_cards' (did you mean 'credit_card'?)",
        ),
        ("{contains: [passport]}", "unknown data type"),
        ("{destination: [extrenal_email]}", "did you mean 'external_email'"),
        ("{contain: [ssn]}", "unknown key 'contain' (did you mean 'contains'?)"),
        ("{}", "non-empty mapping"),
        ("[ssn]", "non-empty mapping"),
        ("{contains: []}", "non-empty list"),
        ("{destination: []}", "non-empty list"),
        ("{all_of: []}", "non-empty list"),
        ("{any_of: {contains: [ssn]}}", "non-empty list"),
        ("{contains: [{type: ssn, min_count: 0}]}", "min_count"),
        ("{contains: [{type: ssn, min_count: '3'}]}", "min_count"),
        ("{contains: [{type: ssn, min_count: 5, max_count: 2}]}", "max_count"),
        ("{contains: [{type: ssn, count: 5}]}", "unknown key 'count'"),
        ("{contains: [{min_count: 2}]}", "unknown data type"),
        ("{contains: [[ssn]]}", "data type name or a mapping"),
        ("{not: [ssn]}", "non-empty mapping"),
        ("{all_of: [{contains: [nope]}]}", "unknown data type"),
    ],
)
def test_invalid_conditions_are_reported_with_a_path(condition, expected):
    errors = errors_for(one_rule_policy(condition=yaml.safe_load(condition)))
    assert any(expected in error for error in errors), errors
    assert all(error.startswith("rules[0] (r)") for error in errors)


@pytest.mark.parametrize(
    ("action", "expected"),
    [
        ("[alrt]", "did you mean 'alert'"),
        ("[delete]", "unknown action"),
        ("[]", "required"),
        ("null", "required"),
    ],
)
def test_invalid_actions(action, expected):
    errors = errors_for(one_rule_policy(action=yaml.safe_load(action)))
    assert any(expected in error for error in errors)


def test_missing_required_fields_are_all_reported_together():
    errors = errors_for("rules:\n  - description: nothing else\n")
    joined = " | ".join(errors)
    for field in ("rule", "severity", "condition", "action"):
        assert f".{field}" in joined


def test_duplicate_rule_names_are_rejected():
    errors = errors_for("rules:\n" + VALID_RULE + VALID_RULE)
    assert any("duplicate rule name 'sample'" in error for error in errors)


def test_unquoted_yaml_booleans_as_rule_names_get_a_helpful_message():
    # YAML 1.1 parses "on"/"off"/"yes"/"no" as booleans, so `rule: off` is not a string.
    (error,) = errors_for(one_rule_policy(rule=False))
    assert "must be a string, got False" in error and "quote" in error


@pytest.mark.parametrize("name", ["", "1abc", "has space", "x" * 65, "a/b"])
def test_rule_names_are_restricted(name):
    assert errors_for(one_rule_policy(rule=name))


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("version: 2\n", "unsupported version"),
        ("version: true\n", "unsupported version"),
        ("settings: {conflict_resolution: random}\n", "conflict_resolution"),
        ("settings: {corporate_domains: corp}\n", "list of domain names"),
        ("settings: {corporate_domains: ['not a domain']}\n", "not a valid domain"),
        ("settings: [1]\n", "must be a mapping"),
        ("settings: {corporate_domain: [a.example.com]}\n", "did you mean 'corporate_domains'"),
        ("extra: 1\n", "unknown key 'extra'"),
    ],
)
def test_invalid_header_sections(header, expected):
    assert any(expected in error for error in errors_for(header + "rules:\n" + VALID_RULE))


@pytest.mark.parametrize("document", ["", "[]", "plain text", "rules: []", "rules: {}", "rules:"])
def test_documents_without_rules_are_rejected(document):
    assert errors_for(document)


def test_yaml_syntax_errors_are_reported_with_a_position():
    errors = errors_for("rules:\n  - rule: [unclosed\n")
    assert len(errors) == 1 and "invalid YAML" in errors[0] and "line" in errors[0]


def test_duplicate_yaml_keys_are_rejected():
    text = (
        "rules:\n  - rule: r\n    severity: low\n    action: [alert]\n"
        "    condition: {contains: [ssn]}\n"
        "    condition: {contains: [credit_card]}\n"
    )
    errors = errors_for(text)
    assert "duplicate key 'condition'" in errors[0]


def test_yaml_cannot_instantiate_python_objects():
    errors = errors_for("rules: !!python/object/apply:os.system ['echo hi']\n")
    assert "invalid YAML" in errors[0]


def test_recursive_yaml_anchors_do_not_crash_the_parser():
    text = (
        "rules:\n  - rule: r\n    severity: low\n    action: [alert]\n"
        "    condition: &loop\n      not: *loop\n"
    )
    errors = errors_for(text)
    assert any("nested deeper" in error for error in errors)


def test_deep_but_finite_nesting_is_rejected():
    condition = "{contains: [ssn]}"
    for _ in range(25):
        condition = "{not: " + condition + "}"
    text = (
        f"rules:\n  - rule: r\n    severity: low\n    action: [alert]\n    condition: {condition}\n"
    )
    assert any("nested deeper" in error for error in errors_for(text))


def test_quarantine_and_block_together_produce_a_warning():
    config = load_policy_text(
        "rules:\n  - rule: r\n    severity: low\n    condition: {contains: [ssn]}\n"
        "    action: [quarantine, block]\n"
    )
    assert len(config.warnings) == 1 and "'block'" in config.warnings[0]


def test_unreadable_file_is_a_validation_error(tmp_path):
    with pytest.raises(PolicyValidationError, match="cannot read policy file"):
        load_policy_file(tmp_path / "missing.yaml")


def test_loader_never_returns_a_partial_policy():
    text = "rules:\n" + VALID_RULE + "  - rule: broken\n    severity: low\n    action: [alert]\n"
    with pytest.raises(PolicyValidationError):
        load_policy_text(text)


def test_example_policy_is_plain_yaml():
    assert isinstance(yaml.safe_load(EXAMPLE_POLICY.read_text()), dict)
