"""Loopback-only tests exercise actual urllib behavior without public targets."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from cve_detector.detector import detect
from cve_detector.models import Status


@pytest.mark.parametrize("code", [200, 302, 403, 405, 503])
def test_real_http_status_and_redirect_boundary(code):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            requests.append((self.command, self.path))
            self.send_response(code)
            self.send_header("X-Powered-By", "PHP/8.4.27")
            self.send_header("Location", "/must-not-follow")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = detect(f"http://127.0.0.1:{server.server_port}/secret-path")
        assert result.status == Status.INCONCLUSIVE
        assert result.observations["status_code"] == code
        assert result.observations["php_versions"] == ("8.4.27",)
        assert requests == [("HEAD", "/secret-path")]
        assert "secret-path" not in str(result.to_dict())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
