"""Basic allow checks for configured public HTTPS endpoints.

These checks reject obvious credential, local-hostname, and literal private-IP
targets. They do not resolve DNS names and are not an SSRF boundary for
untrusted configuration; source configuration must remain operator-controlled.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


def is_public_web_url(value: str, *, schemes: tuple[str, ...] = ("http", "https")) -> bool:
    try:
        parsed = urlparse(value)
        host = (parsed.hostname or "").rstrip(".").lower()
        if parsed.scheme.lower() not in schemes or not host or parsed.username or parsed.password:
            return False
        _ = parsed.port  # Raises ValueError for malformed ports.
        if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
            return False
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        return address is None or address.is_global
    except (TypeError, ValueError):
        return False


def is_public_https_url(value: str) -> bool:
    return is_public_web_url(value, schemes=("https",))
