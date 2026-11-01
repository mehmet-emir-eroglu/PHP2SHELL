from unittest.mock import patch

import pytest

from cve_detector.detector import detect
from cve_detector.models import CVES, Status
from cve_detector.network import Observation
from cve_detector.verification import load_catalog


@pytest.mark.parametrize("release", list(load_catalog().values()))
def test_every_catalog_decision(release, tmp_path):
    path = tmp_path / "renamed-archive"
    path.write_bytes(b"synthetic fixture; hashing mocked explicitly")
    with patch("cve_detector.detector.hash_archive", return_value=release.sha256):
        result = detect(str(path))
    assert result.status == release.status
    assert result.scope == "source_archive"
    assert tuple(x.cve for x in result.findings) == CVES
    assert all(x.status == release.status for x in result.findings)
    assert "deployed" in result.limitations[0]


@pytest.mark.parametrize("filename", ["php-8.4.27.tar.gz", "php-8.4.26-backported.tar.gz"])
def test_filename_or_custom_patch_cannot_prove_status(filename, tmp_path):
    path = tmp_path / filename
    path.write_bytes(b"PHP/8.4.27 patched!")
    assert detect(str(path)).status == Status.INCONCLUSIVE


@pytest.mark.parametrize(
    "versions",
    [(), ("8.4.26",), ("8.4.27",), ("8.4.26", "8.4.27"), ("8.4.26-ubuntu1",), ("99.1.0",)],
)
def test_banners_and_conflicting_versions_never_prove_status(versions):
    with patch("cve_detector.detector.observe", return_value=Observation(200, versions, 1)):
        result = detect("https://example.com/")
    assert result.status == Status.INCONCLUSIVE


def test_unreachable_is_error():
    from cve_detector.exceptions import DetectionError

    with patch("cve_detector.detector.observe", side_effect=DetectionError("Connection failed")):
        assert detect("https://example.com").status == Status.ERROR


def test_invalid_target_does_not_leak_credentials():
    result = detect("https://alice:secret@example.com/")
    assert result.status == Status.ERROR
    assert "secret" not in str(result.to_dict())
