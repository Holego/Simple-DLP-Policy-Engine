"""Runs detectors over text, bytes and files, and summarises findings for reporting."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .base import Detector, Finding
from .credit_card import CreditCardDetector
from .email import EmailDetector
from .ssn import SsnDetector

DEFAULT_MAX_SCAN_BYTES = 10 * 1024 * 1024
DEFAULT_MAX_SAMPLES = 3


def default_detectors() -> tuple[Detector, ...]:
    return (CreditCardDetector(), SsnDetector(), EmailDetector())


# Data types a policy may refer to in ``contains``.
KNOWN_DATA_TYPES: frozenset[str] = frozenset(detector.type for detector in default_detectors())


@dataclass(frozen=True, slots=True)
class FindingSummary:
    """Per-type aggregate that is safe to log: a count and a few masked samples."""

    type: str
    count: int
    samples: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {"type": self.type, "count": self.count, "samples": list(self.samples)}


def decode_bytes(data: bytes) -> str:
    """Decode file content for scanning without ever raising on binary or mixed encodings."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


def read_limited(path: Path, max_bytes: int) -> tuple[bytes, bool]:
    """Read at most ``max_bytes`` of a file; the flag tells whether the file was longer."""
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    return data[:max_bytes], len(data) > max_bytes


def summarize(
    findings: Iterable[Finding], max_samples: int = DEFAULT_MAX_SAMPLES
) -> dict[str, FindingSummary]:
    """Group findings by type, keeping the count and the first few masked values."""
    counts: Counter[str] = Counter()
    samples: dict[str, list[str]] = {}
    for finding in findings:
        counts[finding.type] += 1
        bucket = samples.setdefault(finding.type, [])
        if len(bucket) < max_samples:
            bucket.append(finding.masked)
    return {
        data_type: FindingSummary(data_type, counts[data_type], tuple(samples[data_type]))
        for data_type in sorted(counts)
    }


class Scanner:
    """Applies a set of detectors and returns findings ordered by position."""

    def __init__(self, detectors: Sequence[Detector] | None = None) -> None:
        self.detectors: tuple[Detector, ...] = tuple(detectors or default_detectors())

    def scan_text(self, text: str) -> list[Finding]:
        findings = [finding for detector in self.detectors for finding in detector.detect(text)]
        findings.sort(key=lambda finding: (finding.start, finding.type))
        return findings

    def scan_bytes(self, data: bytes) -> list[Finding]:
        return self.scan_text(decode_bytes(data))

    def scan_file(
        self, path: Path, max_bytes: int = DEFAULT_MAX_SCAN_BYTES
    ) -> tuple[list[Finding], bool]:
        """Scan up to ``max_bytes`` of a file. Returns the findings and a truncation flag."""
        data, truncated = read_limited(path, max_bytes)
        return self.scan_bytes(data), truncated


def count_by_type(findings: Iterable[Finding]) -> Mapping[str, int]:
    return Counter(finding.type for finding in findings)
