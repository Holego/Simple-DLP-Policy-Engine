"""Shared types for data detectors."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class Finding:
    """One detected sensitive item.

    The raw value is deliberately not part of this type: a detector masks the
    value at detection time, so nothing downstream (policy engine, logs,
    incident store, alerts) can leak it by accident.
    """

    type: str
    masked: str
    start: int
    end: int


class Detector(Protocol):
    """A detector turns text into findings of a single data type."""

    type: str

    def detect(self, text: str) -> list[Finding]: ...


def mask_keep_last(digits: str, keep: int = 4, sep: str = "-", group: int = 4) -> str:
    """Mask all but the last ``keep`` characters, hiding the original length.

    >>> mask_keep_last("0000000000001234")
    '****-****-****-1234'
    """
    tail = digits[-keep:]
    return sep.join(["*" * group] * 3 + [tail])
