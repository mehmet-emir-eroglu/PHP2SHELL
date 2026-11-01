"""Exact upstream archive identification, without parsing or executing archive contents."""

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from .exceptions import DetectionError
from .models import Status

MAX_ARCHIVE_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True)
class Release:
    version: str
    filename: str
    sha256: str
    status: Status
    reference: str


def load_catalog() -> dict[str, Release]:
    try:
        raw = json.loads(files("cve_detector").joinpath("data/releases.json").read_text("utf-8"))
        if raw["schema_version"] != 1 or raw["reviewed_on"] != "2026-11-01":
            raise ValueError
        catalog: dict[str, Release] = {}
        for entry in raw["releases"]:
            release = Release(**entry)
            status = Status(release.status)
            if status not in (Status.VULNERABLE, Status.NOT_VULNERABLE):
                raise ValueError
            if not re.fullmatch(r"[a-f0-9]{64}", release.sha256):
                raise ValueError
            if release.sha256 in catalog:
                raise ValueError
            if not re.fullmatch(r"8\.[2-5]\.\d+", release.version):
                raise ValueError
            if release.reference != (
                "https://www.php.net/releases/index.php?json&version=" + release.version
            ):
                raise ValueError
            catalog[release.sha256] = Release(
                release.version, release.filename, release.sha256, status, release.reference
            )
        if len(catalog) != 24:
            raise ValueError
        return catalog
    except (OSError, ValueError, TypeError, KeyError):
        raise DetectionError("Bundled release catalog is invalid; reinstall the package.") from None


def hash_archive(path: Path) -> str:
    try:
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_ARCHIVE_BYTES:
                raise DetectionError("Archive must be a regular file no larger than 128 MiB.")
            digest = hashlib.sha256()
            count = 0
            while chunk := stream.read(1024 * 1024):
                count += len(chunk)
                if count > MAX_ARCHIVE_BYTES:
                    raise DetectionError("Archive exceeds the 128 MiB read limit.")
                digest.update(chunk)
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise DetectionError("Archive changed during hashing; use an immutable copy.")
            return digest.hexdigest()
    except OSError:
        raise DetectionError("Cannot read the archive; check local file permissions.") from None
