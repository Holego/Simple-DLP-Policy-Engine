"""Payment card number detection: digit-run grouping, issuer prefix check, Luhn checksum."""

from __future__ import annotations

import re
from collections.abc import Iterator

from .base import Finding, mask_keep_last

MIN_DIGITS = 13
MAX_DIGITS = 19

# A digit run that is not glued to letters, digits or underscores on either side.
# Hex identifiers such as "a4111...b" therefore never produce candidates.
_RUN = re.compile(r"(?<![A-Za-z0-9_])[0-9]+(?![A-Za-z0-9_])")

# Runs belonging to one number may be separated by exactly one space or dash.
_JOINERS = frozenset(" -")

# When a number spans several runs, each run has the size of a card group.
_MIN_GROUP = 3
_MAX_GROUP = 8

# (brand, allowed lengths, issuer prefix pattern)
_BRANDS: tuple[tuple[str, frozenset[int], re.Pattern[str]], ...] = (
    ("visa", frozenset({13, 16, 19}), re.compile(r"4")),
    (
        "mastercard",
        frozenset({16}),
        re.compile(r"5[1-5]|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720"),
    ),
    ("amex", frozenset({15}), re.compile(r"3[47]")),
    (
        "discover",
        frozenset({16, 17, 18, 19}),
        re.compile(r"6011|65|64[4-9]|622(?:12[6-9]|1[3-9][0-9]|[2-8][0-9]{2}|9[01][0-9]|92[0-5])"),
    ),
    ("diners", frozenset({14, 15, 16, 17, 18, 19}), re.compile(r"30[0-5]|3[689]")),
    ("jcb", frozenset({16, 17, 18, 19}), re.compile(r"35(?:2[89]|[3-8][0-9])")),
    ("unionpay", frozenset({16, 17, 18, 19}), re.compile(r"62")),
    ("maestro", frozenset({13, 14, 15, 16, 17, 18, 19}), re.compile(r"50|5[6-8]|63|67")),
)


def luhn_valid(number: str) -> bool:
    """Return True if ``number`` (ASCII digits only) passes the Luhn checksum."""
    if not number or not number.isascii() or not number.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(number)):
        digit = ord(char) - 48
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def identify_brand(digits: str) -> str | None:
    """Return the issuer brand if ``digits`` has a known prefix and a valid length."""
    for brand, lengths, prefix in _BRANDS:
        if len(digits) in lengths and prefix.match(digits):
            return brand
    return None


def is_valid_card_number(digits: str) -> bool:
    """Plausible length, Luhn checksum and a known issuer prefix for that length."""
    if not MIN_DIGITS <= len(digits) <= MAX_DIGITS:
        return False
    return luhn_valid(digits) and identify_brand(digits) is not None


def _run_groups(text: str) -> Iterator[list[re.Match[str]]]:
    """Yield lists of digit runs that are chained by single space/dash joiners."""
    group: list[re.Match[str]] = []
    for match in _RUN.finditer(text):
        if group and match.start() == group[-1].end() + 1 and text[group[-1].end()] in _JOINERS:
            group.append(match)
        else:
            if group:
                yield group
            group = [match]
    if group:
        yield group


def _looks_like_card_groups(runs: list[re.Match[str]]) -> bool:
    return all(_MIN_GROUP <= len(run.group()) <= _MAX_GROUP for run in runs)


def _longest_valid_from(group: list[re.Match[str]], first: int) -> int | None:
    """Index of the last run of the longest valid card number starting at run ``first``."""
    digits = ""
    best: int | None = None
    for last in range(first, len(group)):
        digits += group[last].group()
        if len(digits) > MAX_DIGITS:
            break
        # A number spanning several runs must look like card groups (4-4-4-4, 4-6-5, ...).
        # Every longer candidate contains the same runs, so stop at the first violation.
        if last > first and not _looks_like_card_groups(group[first : last + 1]):
            break
        if is_valid_card_number(digits):
            best = last
    return best


class CreditCardDetector:
    """Finds payment card numbers; validated, so random digit strings rarely match."""

    type = "credit_card"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for group in _run_groups(text):
            index = 0
            while index < len(group):
                last = _longest_valid_from(group, index)
                if last is None:
                    index += 1
                    continue
                digits = "".join(run.group() for run in group[index : last + 1])
                findings.append(
                    Finding(
                        type=self.type,
                        masked=mask_keep_last(digits),
                        start=group[index].start(),
                        end=group[last].end(),
                    )
                )
                index = last + 1
        return findings
