"""Structured evidence and stable result schema."""

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

CVES = ("CVE-2026-109618", "CVE-2026-109619")
REFERENCES = (
    "https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w",
    "https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp",
)


class Status(StrEnum):
    NOT_VULNERABLE = "NOT_VULNERABLE"
    VULNERABLE = "VULNERABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    ERROR = "ERROR"


EXIT_CODES = {
    Status.NOT_VULNERABLE: 0,
    Status.VULNERABLE: 1,
    Status.INCONCLUSIVE: 2,
    Status.ERROR: 3,
}


@dataclass(frozen=True)
class Finding:
    cve: str
    status: Status
    evidence_summary: str
    confidence: str
    reference: str


@dataclass(frozen=True)
class Report:
    target: str
    scope: str
    status: Status
    verification_method: str
    observations: dict[str, Any]
    findings: tuple[Finding, ...]
    limitations: tuple[str, ...]
    timestamp: str
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def report(
    target: str,
    scope: str,
    status: Status,
    method: str,
    summary: str,
    observations: dict[str, Any],
    limitations: tuple[str, ...],
) -> Report:
    confidence = (
        "High: exact archive identity and vendor advisory; artifact scope only."
        if status in (Status.VULNERABLE, Status.NOT_VULNERABLE)
        else "Insufficient evidence for a vulnerability conclusion."
    )
    return Report(
        target,
        scope,
        status,
        method,
        observations,
        tuple(
            Finding(cve, status, summary, confidence, ref)
            for cve, ref in zip(CVES, REFERENCES, strict=True)
        ),
        limitations,
        datetime.now(UTC).isoformat(),
    )
