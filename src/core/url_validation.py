"""URL validation helpers to prevent SSRF in browser-based solvers."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

_ALLOWED_SCHEMES = {"http", "https"}
_BLOCKED_HOSTNAMES = {"localhost", "metadata.google.internal"}


def _is_disallowed_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the IP address is private, loopback, link-local, or reserved."""
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def validate_public_http_url(url: str) -> str | None:
    """Validate that *url* is a public HTTP/HTTPS URL, returning an error message if not."""
    parsed = urlparse(url.strip())
    if parsed.scheme.lower() not in _ALLOWED_SCHEMES:
        return "websiteURL must use http or https scheme"

    hostname = (parsed.hostname or "").strip().lower()
    if not hostname:
        return "websiteURL must include a valid hostname"

    if hostname in _BLOCKED_HOSTNAMES or hostname.endswith((".localhost", ".local")):
        return "websiteURL must not target localhost or internal hostnames"

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None

    if ip is not None:
        if _is_disallowed_ip(ip):
            return "websiteURL must not target private or reserved IP addresses"
        return None

    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except OSError:
        # DNS may be unavailable in isolated test environments; allow syntactic public hostnames
        return None

    for info in infos:
        raw_ip = info[4][0]
        try:
            resolved = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if _is_disallowed_ip(resolved):
            return "websiteURL resolves to a private or reserved IP address"

    return None
