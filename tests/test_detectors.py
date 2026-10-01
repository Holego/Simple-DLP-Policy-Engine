import pytest

from src.detectors import (
    CreditCardDetector,
    EmailDetector,
    Finding,
    Scanner,
    SsnDetector,
    decode_bytes,
    identify_brand,
    luhn_valid,
    read_limited,
    summarize,
)
from tests.conftest import SUPPORTED_CARD_TYPES, break_luhn


class TestLuhn:
    def test_accepts_generated_numbers(self, card_numbers):
        assert all(luhn_valid(number) for number in card_numbers(20))

    def test_rejects_wrong_check_digit(self, card_numbers):
        assert not any(luhn_valid(break_luhn(number)) for number in card_numbers(20))

    @pytest.mark.parametrize("value", ["", "abc", "12 34", "١٢٣٤"])
    def test_rejects_non_ascii_digit_input(self, value):
        assert not luhn_valid(value)


class TestCreditCardDetector:
    detector = CreditCardDetector()

    @pytest.mark.parametrize("card_type", SUPPORTED_CARD_TYPES)
    def test_detects_every_supported_brand(self, fake, card_type):
        for _ in range(50):
            number = fake.credit_card_number(card_type=card_type)
            found = self.detector.detect(f"payment: {number}.")
            assert len(found) == 1, number
            assert found[0].type == "credit_card"

    def test_detects_common_separators(self, card_numbers):
        number = card_numbers(1)[0]
        grouped = " ".join(number[i : i + 4] for i in range(0, len(number), 4))
        dashed = "-".join(number[i : i + 4] for i in range(0, len(number), 4))
        for text in (number, grouped, dashed):
            assert len(self.detector.detect(f"card={text};")) == 1, text

    def test_amex_4_6_5_grouping(self, fake):
        number = fake.credit_card_number(card_type="amex")
        text = f"{number[:4]} {number[4:10]} {number[10:]}"
        assert len(self.detector.detect(text)) == 1

    def test_rejects_failed_checksum(self, invalid_card_number):
        assert self.detector.detect(invalid_card_number) == []

    def test_rejects_unknown_issuer_prefix(self):
        # Luhn-valid, but no card network issues numbers starting with 0.
        assert self.detector.detect("0000000000000000") == []
        assert self.detector.detect("1111111111111117") == []

    def test_ignores_numbers_inside_identifiers(self, card_numbers):
        number = card_numbers(1)[0]
        assert self.detector.detect(f"trace-id a{number}b") == []
        assert self.detector.detect(f"order_{number}") == []

    def test_digits_spread_over_tiny_or_huge_groups_are_not_a_card(self, card_numbers):
        number = card_numbers(1)[0]
        assert self.detector.detect(" ".join(number)) == []  # one digit per group
        assert self.detector.detect(f"{number[:2]}-{number[2:]}") == []  # 2 + 14 digits

    def test_card_next_to_a_date_is_still_found(self, card_numbers):
        number = card_numbers(1)[0]
        found = self.detector.detect(f"2024-01-01 {number}")
        assert len(found) == 1
        assert found[0].start == len("2024-01-01 ")

    def test_adjacent_cards_are_found_separately(self, card_numbers):
        first, second = card_numbers(2)
        found = self.detector.detect(f"{first} {second}")
        assert len(found) == 2

    def test_too_short_and_too_long_sequences_are_ignored(self):
        assert self.detector.detect("4" * 12) == []
        assert self.detector.detect("4" * 25) == []

    def test_positions_point_at_the_full_number(self, card_numbers):
        number = card_numbers(1)[0]
        text = f"x {number} y"
        (finding,) = self.detector.detect(text)
        assert text[finding.start : finding.end] == number

    def test_mask_keeps_only_last_four_digits(self, card_numbers):
        number = card_numbers(1)[0]
        (finding,) = self.detector.detect(number)
        assert finding.masked == f"****-****-****-{number[-4:]}"
        assert number[:-4] not in finding.masked

    @pytest.mark.parametrize(
        ("digits", "brand"),
        [("4" + "0" * 15, "visa"), ("34" + "0" * 13, "amex"), ("51" + "0" * 14, "mastercard")],
    )
    def test_brand_identification(self, digits, brand):
        assert identify_brand(digits) == brand

    def test_brand_requires_matching_length(self):
        assert identify_brand("34" + "0" * 14) is None  # amex has 15 digits


class TestSsnDetector:
    detector = SsnDetector()

    def test_detects_generated_values(self, fake):
        for _ in range(200):
            value = fake.ssn()
            found = self.detector.detect(f"SSN: {value}")
            assert len(found) == 1, value

    def test_accepts_space_separator(self):
        assert len(self.detector.detect("123 45 6789")) == 1

    @pytest.mark.parametrize(
        "value",
        ["000-12-3456", "666-12-3456", "900-12-3456", "999-12-3456", "123-00-4567", "123-45-0000"],
    )
    def test_rejects_structurally_invalid_numbers(self, value):
        assert self.detector.detect(value) == []

    def test_mixed_separators_are_not_an_ssn(self):
        assert self.detector.detect("123-45 6789") == []

    def test_does_not_match_inside_longer_tokens(self):
        assert self.detector.detect("ref 1123-45-67890") == []
        assert self.detector.detect("id-123-45-6789") == []

    def test_bare_digits_need_context(self):
        assert self.detector.detect("order 123456789") == []
        assert len(self.detector.detect("ssn 123456789")) == 1
        assert len(self.detector.detect("Social Security Number: 123456789")) == 1

    def test_context_must_be_on_the_same_line(self):
        assert self.detector.detect("ssn\n123456789") == []

    def test_mask_keeps_only_last_four_digits(self):
        (finding,) = self.detector.detect("123-45-6789")
        assert finding.masked == "***-**-6789"


class TestEmailDetector:
    detector = EmailDetector()

    def test_detects_generated_addresses(self, fake):
        for _ in range(100):
            address = fake.email()
            found = self.detector.detect(f"contact <{address}>, thanks")
            assert len(found) == 1, address

    def test_mask_hides_local_part_but_keeps_domain(self):
        (finding,) = self.detector.detect("jane.doe@example.com")
        assert finding.masked == "j***@example.com"

    def test_ignores_text_without_a_real_domain(self):
        assert self.detector.detect("user@localhost and @mention and a@b") == []

    def test_trailing_punctuation_is_not_part_of_the_address(self):
        text = "write to jane@example.com."
        (finding,) = self.detector.detect(text)
        assert text[finding.start : finding.end] == "jane@example.com"


class TestScanner:
    def test_combines_detectors_in_text_order(self, card_numbers, fake):
        number = card_numbers(1)[0]
        text = f"{fake.email()} paid with {number}, ssn {fake.ssn()}"
        findings = Scanner().scan_text(text)
        assert [finding.type for finding in findings] == ["email", "credit_card", "ssn"]
        assert findings == sorted(findings, key=lambda finding: finding.start)

    def test_findings_do_not_expose_raw_values(self, card_numbers):
        number = card_numbers(1)[0]
        (finding,) = Scanner().scan_text(number)
        assert isinstance(finding, Finding)
        assert number not in repr(finding)
        assert not hasattr(finding, "value")

    def test_clean_text_has_no_findings(self, fake):
        assert Scanner().scan_text(fake.paragraph(nb_sentences=50)) == []

    def test_summarize_counts_and_limits_samples(self, card_numbers):
        findings = Scanner().scan_text("\n".join(card_numbers(5)))
        summary = summarize(findings, max_samples=2)
        assert summary["credit_card"].count == 5
        assert len(summary["credit_card"].samples) == 2
        assert all(sample.startswith("****-") for sample in summary["credit_card"].samples)

    def test_scan_file_reports_truncation(self, tmp_path, card_numbers):
        number = card_numbers(1)[0]
        path = tmp_path / "big.txt"
        path.write_text("x" * 100 + " " + number)
        findings, truncated = Scanner().scan_file(path, max_bytes=50)
        assert findings == [] and truncated
        findings, truncated = Scanner().scan_file(path, max_bytes=10_000)
        assert len(findings) == 1 and not truncated

    def test_read_limited_returns_at_most_the_limit(self, tmp_path):
        path = tmp_path / "f.bin"
        path.write_bytes(b"a" * 10)
        assert read_limited(path, 4) == (b"aaaa", True)
        assert read_limited(path, 10) == (b"a" * 10, False)

    def test_binary_content_never_raises(self, rng):
        blob = bytes(rng.randrange(256) for _ in range(5000))
        Scanner().scan_bytes(blob)

    def test_utf16_with_bom_is_decoded(self, card_numbers):
        number = card_numbers(1)[0]
        data = f"card {number}".encode("utf-16")
        assert "card" in decode_bytes(data)
        assert len(Scanner().scan_bytes(data)) == 1
