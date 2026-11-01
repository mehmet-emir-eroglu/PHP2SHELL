import http.client
import socket
import ssl
from email.message import Message
from io import BytesIO
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from cve_detector.exceptions import DetectionError
from cve_detector.network import NoRedirect, observe


def response(code=200, headers=None):
    obj = MagicMock()
    obj.__enter__.return_value = obj
    obj.code = code
    obj.headers = Message()
    for name, value in headers or []:
        obj.headers[name] = value
    return obj


def test_head_no_body_no_proxy_and_resource_cleanup():
    res = response(headers=[("X-Powered-By", "PHP/8.4.26"), ("Server", "PHP/8.4.27")])
    with patch("cve_detector.network.build_opener") as build:
        build.return_value.open.return_value = res
        observation = observe("https://example.com/")
        request = build.return_value.open.call_args.args[0]
        assert request.get_method() == "HEAD"
        assert request.data is None
        assert build.call_args.args[0].proxies == {}
        context = build.call_args.args[2]._context
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname
    assert observation.php_versions == ("8.4.26", "8.4.27")
    res.read.assert_not_called()
    res.__exit__.assert_called_once()


@pytest.mark.parametrize("code", [301, 302, 307, 308, 401, 403, 404, 405, 429, 500, 503])
def test_http_status_is_observation_and_no_redirect(code):
    headers = Message()
    headers["Location"] = "https://outside-scope.invalid/secret"
    error = HTTPError("https://example.com/", code, "status", headers, BytesIO())
    with patch("cve_detector.network.build_opener") as build:
        build.return_value.open.side_effect = error
        assert observe("https://example.com/").status_code == code
        assert build.return_value.open.call_count == 1
    assert error.closed
    assert (
        NoRedirect().redirect_request(
            Request("https://example.com"), None, code, "", headers, "https://elsewhere.invalid"
        )
        is None
    )


@pytest.mark.parametrize(
    "failure",
    [
        URLError(socket.gaierror()),
        URLError(ConnectionRefusedError()),
        TimeoutError(),
        http.client.BadStatusLine("bad"),
        http.client.RemoteDisconnected(),
    ],
)
def test_failures_bounded_retries(failure):
    with (
        patch("cve_detector.network.build_opener") as build,
        patch("cve_detector.network.time.sleep"),
    ):
        build.return_value.open.side_effect = failure
        with pytest.raises(DetectionError):
            observe("https://example.com/", retries=2)
        assert build.return_value.open.call_count == 3


def test_tls_failure_not_retried():
    with patch("cve_detector.network.build_opener") as build:
        build.return_value.open.side_effect = URLError(ssl.SSLCertVerificationError())
        with pytest.raises(DetectionError, match="TLS"):
            observe("https://example.com/", retries=2)
        assert build.return_value.open.call_count == 1


def test_retry_success():
    with (
        patch("cve_detector.network.build_opener") as build,
        patch("cve_detector.network.time.sleep"),
    ):
        build.return_value.open.side_effect = [TimeoutError(), response()]
        assert observe("https://example.com/", retries=1).attempts == 2


@pytest.mark.parametrize("code", [0, 600, "200", None])
def test_malformed_status(code):
    with patch("cve_detector.network.build_opener") as build:
        build.return_value.open.return_value = response(code)
        with pytest.raises(DetectionError):
            observe("https://example.com/")


@pytest.mark.parametrize("timeout,retries", [(0, 0), (31, 0), (float("nan"), 0), (1, -1), (1, 3)])
def test_invalid_bounds(timeout, retries):
    with pytest.raises(DetectionError):
        observe("https://example.com/", timeout, retries)
