"""Strict URL and local-file validation."""

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

from .exceptions import DetectionError


@dataclass(frozen=True)
class Target:
    value: str
    display: str
    scope: str


def validate_target(value: str) -> Target:
    if not value or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise DetectionError("Target is empty, too long, or contains control characters.")
    if "://" not in value:
        if value.startswith(("//", "\\\\")):
            raise DetectionError("Network share paths are unsupported; use a local regular file.")
        path = Path(value).expanduser()
        if not path.is_file():
            raise DetectionError("Archive target must be an existing local regular file.")
        return Target(str(path.resolve()), str(path.resolve()), "source_archive")
    try:
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https"):
            raise ValueError
        if parts.username is not None or parts.password is not None or not parts.hostname:
            raise ValueError
        if parts.query or parts.fragment or "?" in value or "#" in value:
            raise ValueError
        if "\\" in value or any(c.isspace() for c in value):
            raise ValueError
        if any(ord(c) < 32 or ord(c) == 127 for c in unquote(parts.path)):
            raise ValueError
        hostname = parts.hostname.encode("idna").decode("ascii").lower()
        if "%" in hostname or len(hostname) > 253:
            raise ValueError
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            if ":" in hostname or re.fullmatch(r"[0-9.]+", hostname):
                raise ValueError from None
            labels = hostname.rstrip(".").split(".")
            if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
                raise ValueError from None
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
        if parts.netloc.endswith(":"):
            raise ValueError
        host = f"[{hostname}]" if ":" in hostname else hostname
        authority = host + (f":{port}" if port is not None else "")
        path_text = parts.path or "/"
        path_text.encode("ascii")
        url = urlunsplit((parts.scheme, authority, path_text, "", ""))
        # Paths may contain application secrets. Keep them out of reports and logs.
        display_path = "/" if path_text == "/" else "/[path-redacted]"
        display = urlunsplit((parts.scheme, authority, display_path, "", ""))
        return Target(url, display, "http_endpoint")
    except (ValueError, UnicodeError):
        raise DetectionError(
            "Use an HTTP(S) URL with a valid host/port, no credentials, query, or fragment; "
            "percent-encode non-ASCII paths."
        ) from None
