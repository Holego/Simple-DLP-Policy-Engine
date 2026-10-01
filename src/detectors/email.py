"""Email address detection."""

from __future__ import annotations

import re

from .base import Finding

_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"[A-Za-z0-9._%+-]{1,64}@"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}"
    r"(?![A-Za-z0-9-])"
)


def mask_email(address: str) -> str:
    """Keep the first character of the local part and the domain: ``j***@example.com``."""
    local, _, domain = address.rpartition("@")
    return f"{local[:1]}***@{domain}"


class EmailDetector:
    """Finds email addresses. Mostly useful for volume rules (customer lists, exports)."""

    type = "email"

    def detect(self, text: str) -> list[Finding]:
        return [
            Finding(self.type, mask_email(match.group()), match.start(), match.end())
            for match in _EMAIL.finditer(text)
        ]
