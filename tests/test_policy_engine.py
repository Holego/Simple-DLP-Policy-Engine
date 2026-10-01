import textwrap

import pytest

from src.detectors import Finding
from src.engine import Destination, PolicyEngine
from tests.conftest import EXAMPLE_POLICY


def findings(**counts: int) -> list[Finding]:
    """Synthetic findings: ``findings(credit_card=2)`` -> two masked card findings."""
    return [
        Finding(type=data_type, masked="***", start=i * 20, end=i * 20 + 16)
        for data_type, count in counts.items()
        for i in range(count)
    ]


def engine(rules: str, settings: str = "") -> PolicyEngine:
    return PolicyEngine.from_text(
        "version: 1\n"
        + textwrap.dedent(settings)
        + "rules:\n"
        + textwrap.indent(textwrap.dedent(rules), "  ")
    )


def names(matches) -> list[str]:
    return [match.rule.name for match in matches]


class TestSimpleConditions:
    @pytest.fixture
    def policy(self) -> PolicyEngine:
        return engine(
            """
            - rule: card_data_to_external
              severity: high
              condition:
                contains: [credit_card, ssn]
                destination: [external_email, public_s3, non_corporate_domain]
              action: [alert, quarantine]
            """
        )

    def test_matches_when_data_and_destination_both_hold(self, policy):
        decision = policy.evaluate(findings(credit_card=1), "external_email")
        assert names(decision.matches) == ["card_data_to_external"]
        assert decision.actions == ("quarantine", "alert")
        assert decision.severity.label == "high"

    def test_contains_is_any_of_the_listed_types(self, policy):
        assert policy.match(findings(ssn=1), "public_s3")
        assert policy.match(findings(credit_card=1), "public_s3")

    def test_destination_is_any_of_the_listed_categories(self, policy):
        for category in ("external_email", "public_s3", "non_corporate_domain"):
            assert policy.match(findings(ssn=1), category), category

    def test_safe_destination_does_not_match(self, policy):
        assert policy.match(findings(credit_card=3), "internal_email") == []
        assert policy.match(findings(credit_card=3), "unknown") == []

    def test_data_without_sensitive_findings_does_not_match(self, policy):
        assert policy.match(findings(email=10), "external_email") == []
        assert policy.match([], "external_email") == []

    def test_match_reports_evidence(self, policy):
        (match,) = policy.match(findings(credit_card=2, ssn=1, email=9), "external_email")
        assert match.matched_types == ("credit_card", "ssn")
        assert dict(match.counts) == {"credit_card": 2, "ssn": 1}

    def test_no_match_returns_an_empty_decision(self, policy):
        decision = policy.evaluate(findings(email=1), "external_email")
        assert not decision.triggered
        assert decision.actions == () and decision.severity is None


class TestLogicalOperators:
    def test_siblings_in_one_mapping_are_anded(self):
        policy = engine(
            """
            - rule: r
              severity: low
              condition:
                contains: [ssn]
                destination: [public_s3]
              action: [alert]
            """
        )
        assert policy.match(findings(ssn=1), "public_s3")
        assert not policy.match(findings(ssn=1), "internal")
        assert not policy.match([], "public_s3")

    def test_contains_all_requires_every_type(self):
        policy = engine(
            """
            - rule: r
              severity: low
              condition:
                contains_all: [credit_card, ssn]
              action: [alert]
            """
        )
        assert policy.match(findings(credit_card=1, ssn=1), "unknown")
        assert not policy.match(findings(credit_card=5), "unknown")
        assert not policy.match(findings(ssn=5), "unknown")

    def test_any_of_is_an_or_between_whole_conditions(self):
        policy = engine(
            """
            - rule: r
              severity: low
              condition:
                any_of:
                  - contains: [credit_card]
                    destination: [public_s3]
                  - contains: [ssn]
                    destination: [external_email]
              action: [alert]
            """
        )
        assert policy.match(findings(credit_card=1), "public_s3")
        assert policy.match(findings(ssn=1), "external_email")
        # Each branch is evaluated as a whole: the data of one branch with the destination
        # of the other does not match.
        assert not policy.match(findings(credit_card=1), "external_email")
        assert not policy.match(findings(ssn=1), "public_s3")

    def test_all_of_requires_every_child(self):
        policy = engine(
            """
            - rule: r
              severity: low
              condition:
                all_of:
                  - contains: [credit_card]
                  - contains: [email]
                  - destination: [external_email]
              action: [alert]
            """
        )
        assert policy.match(findings(credit_card=1, email=1), "external_email")
        assert not policy.match(findings(credit_card=1), "external_email")

    def test_not_inverts_a_condition(self):
        policy = engine(
            """
            - rule: r
              severity: low
              condition:
                all_of:
                  - contains: [credit_card]
                  - not:
                      destination: [internal, internal_email]
              action: [alert]
            """
        )
        assert policy.match(findings(credit_card=1), "external_email")
        assert not policy.match(findings(credit_card=1), "internal")

    def test_nested_combinations(self):
        policy = engine(
            """
            - rule: r
              severity: low
              condition:
                all_of:
                  - any_of:
                      - contains: [credit_card]
                      - contains_all: [ssn, email]
                  - destination: [external_email]
              action: [alert]
            """
        )
        assert policy.match(findings(credit_card=1), "external_email")
        assert policy.match(findings(ssn=1, email=1), "external_email")
        assert not policy.match(findings(ssn=1), "external_email")
        assert not policy.match(findings(credit_card=1), "internal")

    def test_evidence_only_includes_types_of_satisfied_branches(self):
        policy = engine(
            """
            - rule: r
              severity: low
              condition:
                any_of:
                  - contains: [credit_card]
                  - contains: [ssn]
              action: [alert]
            """
        )
        (match,) = policy.match(findings(credit_card=1, ssn=1, email=4), "unknown")
        assert match.matched_types == ("credit_card", "ssn")
        (match,) = policy.match(findings(ssn=1, email=4), "unknown")
        assert match.matched_types == ("ssn",)


class TestThresholds:
    @pytest.fixture
    def policy(self) -> PolicyEngine:
        return engine(
            """
            - rule: more_than_three_cards
              severity: high
              condition:
                contains:
                  - type: credit_card
                    min_count: 4
              action: [alert]
            - rule: between_two_and_four_ssns
              severity: low
              condition:
                contains:
                  - type: ssn
                    min_count: 2
                    max_count: 4
              action: [alert]
            """
        )

    @pytest.mark.parametrize(("count", "expected"), [(0, False), (3, False), (4, True), (50, True)])
    def test_min_count_boundary(self, policy, count, expected):
        matched = "more_than_three_cards" in names(policy.match(findings(credit_card=count), "x"))
        assert matched is expected

    @pytest.mark.parametrize(("count", "expected"), [(1, False), (2, True), (4, True), (5, False)])
    def test_min_and_max_count_window(self, policy, count, expected):
        matched = "between_two_and_four_ssns" in names(policy.match(findings(ssn=count), "x"))
        assert matched is expected

    def test_thresholds_apply_per_type_in_an_any_list(self):
        policy = engine(
            """
            - rule: r
              severity: low
              condition:
                contains:
                  - credit_card
                  - type: email
                    min_count: 10
              action: [alert]
            """
        )
        assert policy.match(findings(credit_card=1, email=2), "x")
        assert policy.match(findings(email=10), "x")
        assert not policy.match(findings(email=9), "x")


class TestDisabledRules:
    def test_disabled_rules_never_fire(self):
        policy = engine(
            """
            - rule: disabled_rule
              severity: high
              enabled: false
              condition: {contains: [credit_card]}
              action: [block]
            - rule: enabled_rule
              severity: low
              condition: {contains: [credit_card]}
              action: [alert]
            """
        )
        decision = policy.evaluate(findings(credit_card=1), "x")
        assert names(decision.matches) == ["enabled_rule"]
        assert decision.actions == ("alert",)


class TestDestinationCategories:
    corporate = ("corp.example.com",)
    trusted = ("partner.example.net",)

    def categories(self, **kwargs) -> frozenset[str]:
        return Destination(**kwargs).categories(self.corporate, self.trusted)

    def test_email_to_external_recipient(self):
        found = self.categories(channel="email", recipient="jane@gmail.example")
        assert found == {"external_email", "non_corporate_domain"}

    def test_email_to_corporate_recipient_including_subdomains(self):
        for recipient in ("a@corp.example.com", "a@eu.corp.example.com", "A@CORP.EXAMPLE.COM"):
            found = self.categories(channel="email", recipient=recipient)
            assert found == {"internal_email", "corporate_domain"}, recipient

    def test_lookalike_domain_is_not_corporate(self):
        found = self.categories(channel="email", recipient="a@evilcorp.example.com")
        assert "external_email" in found and "internal_email" not in found

    def test_trusted_partner_is_still_external(self):
        found = self.categories(channel="email", recipient="a@partner.example.net")
        assert found == {"external_email", "non_corporate_domain", "trusted_domain"}

    def test_s3_exposure(self):
        assert self.categories(channel="s3", public=True) == {"public_s3"}
        assert self.categories(channel="s3", public=False) == {"private_s3"}

    def test_declared_categories_are_added(self):
        found = self.categories(channel="s3", public=False, declared=("external_email",))
        assert found == {"private_s3", "external_email"}

    @pytest.mark.parametrize("channel", ["cloud_storage", "removable_media", "internal"])
    def test_channel_categories(self, channel):
        assert self.categories(channel=channel) == {channel}

    def test_unknown_when_nothing_is_known(self):
        assert self.categories() == {"unknown"}
        assert self.categories(channel="email") == {"unknown"}
        assert self.categories(channel="s3") == {"unknown"}

    def test_log_view_masks_the_recipient(self):
        view = Destination(channel="email", recipient="jane.doe@partner.example.net").to_dict()
        assert view["recipient"] == "j***@partner.example.net"
        assert view["domain"] == "partner.example.net"

    def test_engine_uses_configured_domains(self):
        policy = engine(
            """
            - rule: r
              severity: low
              condition: {contains: [ssn], destination: [external_email]}
              action: [alert]
            """,
            settings="settings: {corporate_domains: [corp.example.com]}\n",
        )
        external = Destination(channel="email", recipient="x@other.example.org")
        internal = Destination(channel="email", recipient="x@corp.example.com")
        assert policy.match(findings(ssn=1), external)
        assert not policy.match(findings(ssn=1), internal)


CONFLICTING_RULES = """
    - rule: low_alert
      severity: low
      condition: {contains: [credit_card]}
      action: [alert]
    - rule: medium_quarantine
      severity: medium
      condition: {contains: [credit_card]}
      action: [alert, quarantine]
    - rule: high_block
      severity: high
      condition: {contains: [credit_card]}
      action: [block]
"""


class TestConflictResolution:
    def test_matches_are_ordered_by_priority_then_severity_then_file_order(self):
        policy = engine(
            """
            - rule: first_low
              severity: low
              condition: {contains: [ssn]}
              action: [alert]
            - rule: second_low
              severity: low
              condition: {contains: [ssn]}
              action: [alert]
            - rule: high_default
              severity: high
              condition: {contains: [ssn]}
              action: [alert]
            - rule: low_boosted
              severity: low
              priority: 500
              condition: {contains: [ssn]}
              action: [alert]
            """
        )
        assert names(policy.match(findings(ssn=1), "x")) == [
            "low_boosted",
            "high_default",
            "first_low",
            "second_low",
        ]

    def test_priority_mode_highest_priority_decides(self):
        decision = engine(CONFLICTING_RULES).evaluate(findings(credit_card=1), "x")
        assert decision.actions == ("block",)
        assert decision.severity.label == "high"
        assert names(decision.winning) == ["high_block"]

    def test_priority_mode_reports_lower_priority_matches_as_suppressed(self):
        decision = engine(CONFLICTING_RULES).evaluate(findings(credit_card=1), "x")
        assert names(decision.matches) == ["high_block", "medium_quarantine", "low_alert"]
        assert names(decision.suppressed) == ["medium_quarantine", "low_alert"]
        assert {m.suppressed_by for m in decision.suppressed} == {"high_block"}

    def test_explicit_priority_overrides_severity(self):
        policy = engine(
            """
            - rule: broad_quarantine
              severity: high
              condition: {contains: [credit_card]}
              action: [alert, quarantine]
            - rule: approved_exception
              severity: low
              priority: 500
              condition: {contains: [credit_card]}
              action: [alert]
            """
        )
        decision = policy.evaluate(findings(credit_card=1), "x")
        assert decision.actions == ("alert",)
        assert names(decision.suppressed) == ["broad_quarantine"]
        assert decision.severity.label == "low"

    def test_rules_with_equal_priority_decide_together(self):
        policy = engine(
            """
            - rule: a
              severity: high
              condition: {contains: [credit_card]}
              action: [alert]
            - rule: b
              severity: high
              condition: {contains: [credit_card]}
              action: [quarantine]
            """
        )
        decision = policy.evaluate(findings(credit_card=1), "x")
        assert decision.actions == ("quarantine", "alert")
        assert decision.suppressed == ()

    def test_most_restrictive_mode_combines_all_matching_rules(self):
        policy = engine(
            CONFLICTING_RULES, settings="settings: {conflict_resolution: most_restrictive}\n"
        )
        decision = policy.evaluate(findings(credit_card=1), "x")
        assert decision.actions == ("block", "alert")
        assert decision.suppressed == ()

    def test_most_restrictive_ignores_priority(self):
        policy = engine(
            """
            - rule: exception
              severity: low
              priority: 900
              condition: {contains: [credit_card]}
              action: [alert]
            - rule: strict
              severity: low
              condition: {contains: [credit_card]}
              action: [quarantine]
            """,
            settings="settings: {conflict_resolution: most_restrictive}\n",
        )
        # The high-priority alert-only rule does not suppress the quarantine of the other.
        assert policy.evaluate(findings(credit_card=1), "x").actions == ("quarantine", "alert")

    def test_block_beats_quarantine_within_one_rule(self):
        policy = engine(
            """
            - rule: r
              severity: low
              condition: {contains: [ssn]}
              action: [quarantine, block, alert]
            """
        )
        assert policy.evaluate(findings(ssn=1), "x").actions == ("block", "alert")

    def test_disposition_comes_before_alert(self):
        policy = engine(
            """
            - rule: r
              severity: low
              condition: {contains: [ssn]}
              action: [alert, quarantine]
            """
        )
        decision = policy.evaluate(findings(ssn=1), "x")
        assert decision.actions == ("quarantine", "alert")
        assert decision.disposition == "quarantine"

    def test_alert_only_decision_has_no_disposition(self):
        policy = engine(
            """
            - rule: r
              severity: low
              condition: {contains: [ssn]}
              action: [alert]
            """
        )
        assert policy.evaluate(findings(ssn=1), "x").disposition is None


class TestExamplePolicy:
    """The shipped example behaves the way its comments say."""

    @pytest.fixture
    def policy(self) -> PolicyEngine:
        return PolicyEngine.from_file(EXAMPLE_POLICY)

    def email_to(self, recipient: str) -> Destination:
        return Destination(channel="email", recipient=recipient)

    def test_single_card_to_external_email_is_quarantined(self, policy):
        decision = policy.evaluate(findings(credit_card=1), self.email_to("a@other.example.org"))
        assert names(decision.winning) == ["card_data_to_external"]
        assert decision.actions == ("quarantine", "alert")

    def test_bulk_cards_are_blocked_and_override_the_quarantine_rule(self, policy):
        decision = policy.evaluate(findings(credit_card=4), self.email_to("a@other.example.org"))
        assert decision.actions == ("block", "alert")
        assert names(decision.winning) == ["bulk_card_data_to_risky_destination"]
        assert names(decision.suppressed) == ["card_data_to_external"]

    def test_three_cards_stay_below_the_bulk_threshold(self, policy):
        decision = policy.evaluate(findings(credit_card=3), self.email_to("a@other.example.org"))
        assert decision.actions == ("quarantine", "alert")

    def test_internal_recipient_is_allowed(self, policy):
        decision = policy.evaluate(findings(credit_card=9), self.email_to("a@corp.example.com"))
        assert not decision.triggered

    def test_trusted_partner_exception_only_alerts(self, policy):
        decision = policy.evaluate(findings(credit_card=2), self.email_to("a@partner.example.net"))
        assert decision.actions == ("alert",)
        assert names(decision.winning) == ["trusted_partner_small_transfer"]
        assert "card_data_to_external" in names(decision.suppressed)

    def test_trusted_partner_exception_does_not_cover_bulk(self, policy):
        decision = policy.evaluate(findings(credit_card=5), self.email_to("a@partner.example.net"))
        assert decision.actions == ("block", "alert")

    def test_unknown_destination_with_card_and_ssn_alerts(self, policy):
        decision = policy.evaluate(findings(credit_card=1, ssn=1), Destination())
        assert names(decision.matches) == ["identity_bundle_unknown_destination"]
        assert decision.actions == ("alert",)

    def test_ssn_to_removable_media_is_quarantined(self, policy):
        decision = policy.evaluate(findings(ssn=1), Destination(channel="removable_media"))
        assert names(decision.matches) == ["ssn_to_cloud_or_removable_media"]

    def test_email_list_threshold(self, policy):
        destination = self.email_to("a@other.example.org")
        assert not policy.evaluate(findings(email=49), destination).triggered
        assert policy.evaluate(findings(email=50), destination).triggered

    def test_public_bucket_with_cards_is_quarantined(self, policy):
        decision = policy.evaluate(findings(credit_card=1), Destination(channel="s3", public=True))
        assert decision.actions == ("quarantine", "alert")
