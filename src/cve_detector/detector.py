"""CVE-specific decision rules with explicit evidence scope."""

import logging
from dataclasses import asdict
from pathlib import Path

from .exceptions import DetectionError
from .models import Report, Status, report
from .network import observe
from .targets import validate_target
from .verification import hash_archive, load_catalog

LOG = logging.getLogger(__name__)
ARCHIVE_LIMITS = (
    "Conclusion applies only to the scanned source archive, not any deployed PHP worker.",
    "Catalog covers 24 exact archives; custom, backported and other releases are inconclusive.",
    "Trusted catalog and SHA-256 identity are assumed; no archive code is executed.",
    "Only the two named CVEs are assessed; later vulnerabilities are outside scope.",
)
HTTP_LIMITS = (
    "HTTP headers cannot establish deployed patch state or exploitation prerequisites.",
    "A HEAD request covers one route and may reach a proxy, WAF or a single backend.",
    "No memory exhaustion, multipart upload, code execution or sensitive-data probe is used.",
    "Socket timeouts do not impose an absolute DNS or total wall-clock deadline.",
)


def error_report(message: str, target: str = "[unvalidated]", scope: str = "unknown") -> Report:
    return report(
        target,
        scope,
        Status.ERROR,
        "assessment_failed",
        message,
        {},
        ("An operational failure establishes neither vulnerability nor safety.",),
    )


def detect(target: str, timeout: float = 5.0, retries: int = 0) -> Report:
    display, scope = "[unvalidated]", "unknown"
    try:
        validated = validate_target(target)
        display, scope = validated.display, validated.scope
        LOG.info("Validated target; assessment scope: %s", scope)
        if scope == "http_endpoint":
            observation = observe(validated.value, timeout, retries)
            return report(
                display,
                scope,
                Status.INCONCLUSIVE,
                "http_head_observation",
                "A response was observed; deployed patch state is unverified.",
                asdict(observation),
                HTTP_LIMITS,
            )
        digest = hash_archive(Path(validated.value))
        release = load_catalog().get(digest)
        observations: dict[str, object] = {"sha256": digest}
        if release is None:
            return report(
                display,
                scope,
                Status.INCONCLUSIVE,
                "official_archive_sha256",
                "Archive digest is absent from the reviewed catalog.",
                observations,
                ARCHIVE_LIMITS,
            )
        observations.update(
            {
                "release": release.version,
                "official_filename": release.filename,
                "release_reference": release.reference,
                "catalog_reviewed_on": "2026-11-01",
            }
        )
        summary = (
            "Exact official source archive contains code affected by both CVEs. "
            "Runtime exploitability is not tested."
            if release.status == Status.VULNERABLE
            else "Exact official source archive is a vendor-fixed release for both named CVEs."
        )
        return report(
            display,
            scope,
            release.status,
            "official_archive_sha256",
            summary,
            observations,
            ARCHIVE_LIMITS,
        )
    except DetectionError as exc:
        return error_report(str(exc), display, scope)
    except OSError:
        return error_report("Filesystem operation failed; check target access.", display, scope)
