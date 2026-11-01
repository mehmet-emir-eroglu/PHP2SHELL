import hashlib
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from cve_detector.exceptions import DetectionError
from cve_detector.models import Status
from cve_detector.verification import MAX_ARCHIVE_BYTES, hash_archive, load_catalog


def test_catalog_matches_official_snapshots():
    catalog = load_catalog()
    fixed = {"8.2.35", "8.3.36", "8.4.27", "8.5.12"}
    affected = {"8.2.34", "8.3.35", "8.4.26", "8.5.11"}
    snapshots = Path(__file__).parents[1] / "docs/release-metadata"
    for path in snapshots.glob("*.json"):
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        for source in raw["source"]:
            match = catalog[source["sha256"]]
            assert match.version == raw["version"]
            assert match.filename == source["filename"]
            assert match.version in fixed | affected
            expected = Status.NOT_VULNERABLE if match.version in fixed else Status.VULNERABLE
            assert match.status == expected
    assert len(catalog) == 24
    assert sum(x.status == Status.VULNERABLE for x in catalog.values()) == 12


def test_known_digest_and_streaming(tmp_path):
    path = tmp_path / "data"
    content = b"x" * (1024 * 1024 + 17)
    path.write_bytes(content)
    assert hash_archive(path) == hashlib.sha256(content).hexdigest()


def test_missing_file(tmp_path):
    with pytest.raises(DetectionError, match="Cannot read"):
        hash_archive(tmp_path / "missing")


def test_oversized_archive(tmp_path):
    path = tmp_path / "large"
    with path.open("wb") as stream:
        stream.truncate(MAX_ARCHIVE_BYTES + 1)
    with pytest.raises(DetectionError, match="128 MiB"):
        hash_archive(path)


def test_archive_change_detected(tmp_path):
    path = tmp_path / "changing"
    path.write_bytes(b"abc")
    before = path.stat()
    from types import SimpleNamespace

    after = SimpleNamespace(st_size=4, st_mtime_ns=before.st_mtime_ns)
    with patch("cve_detector.verification.os.fstat", side_effect=[before, after]):
        with pytest.raises(DetectionError, match="changed"):
            hash_archive(path)


@pytest.mark.parametrize(
    "payload",
    [
        "{}",
        "{bad",
        '{"schema_version": 2}',
        '{"schema_version": 1, "reviewed_on": "2026-11-01", "releases": []}',
    ],
)
def test_broken_catalog_fails_closed(payload):
    with patch("cve_detector.verification.files") as resource:
        resource.return_value.joinpath.return_value.read_text.return_value = payload
        with pytest.raises(DetectionError, match="catalog"):
            load_catalog()
