"""Where is the data going? A simulated send context, reduced to risk categories.

Real DLP agents see the actual SMTP envelope, upload target or device. This project has
no traffic to inspect, so every event source describes the destination with metadata
(a manifest next to the file, a folder name, S3 object tags, the bucket exposure) and
this module turns that description into the categories policies match against.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass

from src.detectors.email import mask_email

KNOWN_CHANNELS = frozenset(
    {"email", "s3", "cloud_storage", "removable_media", "internal", "unknown"}
)

KNOWN_DESTINATIONS = frozenset(
    {
        "external_email",  # email to a recipient outside the corporate domains
        "internal_email",  # email to a corporate recipient
        "public_s3",  # S3 bucket that is readable by the public
        "private_s3",  # S3 bucket that is not public
        "cloud_storage",  # consumer or third-party cloud storage
        "removable_media",  # USB drive and similar
        "non_corporate_domain",  # any destination whose domain is not corporate
        "corporate_domain",  # any destination whose domain is corporate
        "trusted_domain",  # destination domain on the trusted-partner list
        "internal",  # internal share or system
        "unknown",  # the source could not say where the data goes
    }
)


def domain_of(address: str | None) -> str | None:
    """Domain part of an email address, lowercased; None if there is no usable domain."""
    if not address or "@" not in address:
        return None
    domain = address.rpartition("@")[2].strip().lower().rstrip(".")
    return domain or None


def domain_matches(domain: str, candidates: Collection[str]) -> bool:
    """True if ``domain`` equals one of ``candidates`` or is a subdomain of one."""
    return any(domain == item or domain.endswith("." + item) for item in candidates)


@dataclass(frozen=True, slots=True)
class Destination:
    """Description of where a file is headed, as reported by the event source."""

    channel: str = "unknown"
    recipient: str | None = None
    domain: str | None = None
    public: bool | None = None
    declared: tuple[str, ...] = ()

    @property
    def effective_domain(self) -> str | None:
        return (self.domain.lower() if self.domain else None) or domain_of(self.recipient)

    def categories(
        self,
        corporate_domains: Collection[str] = (),
        trusted_domains: Collection[str] = (),
    ) -> frozenset[str]:
        """Risk categories for this destination; ``unknown`` when nothing could be derived."""
        found: set[str] = set(self.declared)
        domain = self.effective_domain
        corporate = domain is not None and domain_matches(domain, corporate_domains)
        if domain is not None:
            found.add("corporate_domain" if corporate else "non_corporate_domain")
            if domain_matches(domain, trusted_domains):
                found.add("trusted_domain")

        if self.channel == "email" and domain is not None:
            found.add("internal_email" if corporate else "external_email")
        elif self.channel == "s3" and self.public is not None:
            found.add("public_s3" if self.public else "private_s3")
        elif self.channel in {"cloud_storage", "removable_media", "internal"}:
            found.add(self.channel)

        return frozenset(found or {"unknown"})

    def to_dict(self) -> dict[str, object]:
        """Log-safe description; the recipient address is masked, the domain is kept."""
        return {
            "channel": self.channel,
            "domain": self.effective_domain,
            "recipient": mask_email(self.recipient) if self.recipient else None,
            "public": self.public,
        }
