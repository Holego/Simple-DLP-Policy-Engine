"""US Social Security Number detection with structural validation."""

from __future__ import annotations

import re

from .base import Finding

# 123-45-6789 or 123 45 6789 (the same separator twice), not glued to other tokens.
_SEPARATED = re.compile(
    r"(?<![A-Za-z0-9_-])([0-9]{3})([- ])([0-9]{2})\2([0-9]{4})(?![A-Za-z0-9_-])"
)

# Nine bare digits are far too common (order ids, phone numbers without separators),
# so they only count when a keyword right before them says "this is an SSN".
_BARE = re.compile(r"(?<![A-Za-z0-9_-])[0-9]{9}(?![A-Za-z0-9_-])")
_CONTEXT = re.compile(r"\b(?:ssn|social[ _-]?security(?:[ _-]?(?:number|no\.?|#))?)\b", re.I)
_CONTEXT_WINDOW = 40


def is_valid_ssn(area: str, group: str, serial: str) -> bool:
    """Structural rules published by the SSA: no 000/666/9xx area, no 00 group, no 0000 serial."""
    area_number = int(area)
    if area_number == 0 or area_number == 666 or area_number >= 900:
        return False
    return int(group) != 0 and int(serial) != 0


def _mask(serial: str) -> str:
    return f"***-**-{serial}"


def _has_context(text: str, start: int) -> bool:
    window = text[max(0, start - _CONTEXT_WINDOW) : start]
    line_start = window.rfind("\n") + 1
    return _CONTEXT.search(window[line_start:]) is not None


class SsnDetector:
    """Finds US SSNs written with separators, or bare nine-digit values next to an SSN keyword."""

    type = "ssn"

    def detect(self, text: str) -> list[Finding]:
        findings: list[Finding] = []
        for match in _SEPARATED.finditer(text):
            area, _, group, serial = match.groups()
            if is_valid_ssn(area, group, serial):
                findings.append(Finding(self.type, _mask(serial), match.start(), match.end()))
        for match in _BARE.finditer(text):
            digits = match.group()
            if is_valid_ssn(digits[:3], digits[3:5], digits[5:]) and _has_context(
                text, match.start()
            ):
                findings.append(Finding(self.type, _mask(digits[5:]), match.start(), match.end()))
        findings.sort(key=lambda finding: finding.start)
        return findings
