import pytest

from cve_detector.exceptions import DetectionError
from cve_detector.targets import validate_target


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "http://localhost:8080/a.php",
        "https://[::1]/",
        "https://xn--bcher-kva.example/",
        "https://example.com/a%20b",
    ],
)
def test_valid_urls(url):
    assert validate_target(url).scope == "http_endpoint"


@pytest.mark.parametrize(
    "url",
    [
        "",
        "ftp://example.com",
        "https://user:secret@example.com/",
        "https://example.com/?token=secret",
        "https://example.com/#secret",
        "https://example.com:0",
        "https://example.com:65536",
        "https://example.com:x",
        "https://example.com:",
        "https://-bad.example/",
        "https://a..b/",
        "https://999.999.999.999/",
        "https://[not-ip]/",
        "https://example.com/\n",
        "https://example.com/%0d%0aX:",
        "https://example.com\\@evil.example/",
        "https://example.com/a b",
        "https://exa_mple.com/",
        "https:///",
        "\\\\server\\share\\php.tar.gz",
        "//server/share/php.tar.gz",
    ],
)
def test_invalid_urls(url):
    with pytest.raises(DetectionError):
        validate_target(url)


def test_path_redaction():
    target = validate_target("https://example.com/private-secret")
    assert "private-secret" not in target.display
    assert target.value.endswith("/private-secret")


def test_local_file(tmp_path):
    path = tmp_path / "php archive.gz"
    path.write_bytes(b"not an official archive")
    assert validate_target(str(path)).scope == "source_archive"


def test_directory_rejected(tmp_path):
    with pytest.raises(DetectionError):
        validate_target(str(tmp_path))
