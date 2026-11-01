"""One bounded HEAD request; no redirects, proxy inheritance, cookies or body reads."""

import http.client
import re
import ssl
import time
from dataclasses import dataclass
from email.message import Message
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from .exceptions import DetectionError


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Message, newurl: str
    ) -> None:
        return None


@dataclass(frozen=True)
class Observation:
    status_code: int
    php_versions: tuple[str, ...]
    attempts: int


def observe(url: str, timeout: float = 5.0, retries: int = 0) -> Observation:
    if not 0.1 <= timeout <= 30 or not 0 <= retries <= 2:
        raise DetectionError("Timeout must be 0.1..30 seconds and retries 0..2.")
    opener = build_opener(
        ProxyHandler({}), NoRedirect(), HTTPSHandler(context=ssl.create_default_context())
    )
    request = Request(url, method="HEAD", headers={"User-Agent": "php2shell-detector/1.0"})
    for attempt in range(retries + 1):
        try:
            try:
                response = opener.open(request, timeout=timeout)
            except HTTPError as response_error:
                # Redirects and access restrictions are observations, never proof of safety.
                response = response_error
            with response:
                code = response.code
                if not isinstance(code, int) or not 100 <= code <= 599:
                    raise DetectionError("Server returned an invalid HTTP status.")
                versions = set()
                for header in ("X-Powered-By", "Server"):
                    for value in response.headers.get_all(header, []):
                        versions.update(
                            re.findall(
                                r"\bPHP/(\d{1,2}\.\d{1,2}\.\d{1,3}(?:[-+][A-Za-z0-9.-]{1,40})?)",
                                value[:8192],
                                re.IGNORECASE,
                            )
                        )
                return Observation(code, tuple(sorted(versions)), attempt + 1)
        except (URLError, OSError, http.client.HTTPException) as exc:
            reason = exc.reason if isinstance(exc, URLError) else exc
            if isinstance(reason, ssl.SSLError):
                raise DetectionError(
                    "TLS verification or negotiation failed; check certificates."
                ) from None
            if attempt == retries:
                raise DetectionError(
                    "HTTP observation failed (DNS, timeout, connection, or malformed response); "
                    "check reachability and retry."
                ) from None
            time.sleep(0.25 * (attempt + 1))
    raise DetectionError("HTTP observation did not complete.")
