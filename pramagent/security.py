"""Security helpers shared by network-facing components."""
from __future__ import annotations

import ipaddress
import socket
import unicodedata
from urllib.parse import unquote, urlparse


class UnsafeURLError(ValueError):
    """Raised when a configured outbound URL is not safe to call."""


_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff"), None)
_METADATA_HOSTS = {"metadata.google.internal"}


# Published placeholder secrets are known values and must be rejected.
WEAK_SECRET_DENYLIST = frozenset({
    "change-me-in-production",
    "change_me_in_production",
    "changeme",
    "change-me",
    "secret",
    "password",
    "default",
    "ci-jwt-secret-change-me",
})


def assert_strong_secret(name: str, value: str, *, min_len: int = 16) -> None:
    """Refuse startup when a secret is unset, published, or too short.

    Shared by the API factory and the dashboard so every spelling of the
    repo's placeholder secrets is rejected by both services.
    """
    if not value or value.lower() in WEAK_SECRET_DENYLIST or len(value) < min_len:
        raise RuntimeError(
            f"{name} is unset, a published default, or shorter than {min_len} "
            f"chars; generate one with: python -c "
            f"\"import secrets; print(secrets.token_urlsafe(32))\""
        )


def normalize_security_text(text: str, *, decode_rounds: int = 3) -> str:
    """Canonicalize text before security matching.

    Repeated decoding is bounded so nested percent-encoding is visible without
    turning malformed input into an unbounded normalization loop.
    """
    normalized = unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH)
    for _ in range(max(0, decode_rounds)):
        decoded = unquote(normalized)
        if decoded == normalized:
            break
        normalized = decoded
    return normalized


def security_text_variants(text: str) -> tuple[str, ...]:
    """Return raw and canonical forms, without duplicates."""
    canonical = normalize_security_text(text)
    return (text,) if canonical == text else (text, canonical)


def _number_component(value: str) -> int:
    lowered = value.lower()
    if lowered.startswith("0x"):
        return int(lowered[2:], 16)
    if len(lowered) > 1 and lowered.startswith("0"):
        return int(lowered[1:], 8)
    return int(lowered, 10)


def _legacy_ipv4(hostname: str) -> ipaddress.IPv4Address | None:
    """Parse the one-to-four-component IPv4 forms accepted by many runtimes."""
    try:
        parts = hostname.split(".")
        values = [_number_component(part) for part in parts]
        if len(values) == 1 and values[0] <= 0xFFFFFFFF:
            number = values[0]
        elif len(values) == 2 and values[0] <= 0xFF and values[1] <= 0xFFFFFF:
            number = (values[0] << 24) | values[1]
        elif (
            len(values) == 3
            and values[0] <= 0xFF
            and values[1] <= 0xFF
            and values[2] <= 0xFFFF
        ):
            number = (values[0] << 24) | (values[1] << 16) | values[2]
        elif len(values) == 4 and all(value <= 0xFF for value in values):
            number = sum(value << (24 - index * 8) for index, value in enumerate(values))
        else:
            return None
        return ipaddress.IPv4Address(number)
    except (ValueError, OverflowError):
        return None


def _literal_ip(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    hostname = hostname.strip().strip("[]").rstrip(".")
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return _legacy_ipv4(hostname)


def _unsafe_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return bool(
        ip.is_private
        or ip.is_link_local
        or ip.is_loopback
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def unsafe_url_host(url: str, *, resolve_dns: bool = False) -> str | None:
    """Return an unsafe URL host, including non-canonical IP spellings."""
    parsed = urlparse(normalize_security_text(url))
    if not parsed.hostname:
        return None
    host = parsed.hostname.strip("[]").rstrip(".")
    if host.lower() in _METADATA_HOSTS or _is_localhost_name(host):
        return host
    literal = _literal_ip(host)
    if literal is not None:
        return host if _unsafe_ip(literal) else None
    if not resolve_dns:
        return None
    try:
        resolved = {
            item[4][0]
            for item in socket.getaddrinfo(host, parsed.port, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError) as exc:
        raise UnsafeURLError(f"URL hostname could not be resolved: {host}") from exc
    for address in resolved:
        literal = _literal_ip(address)
        if literal is not None and _unsafe_ip(literal):
            return host
    return None


def _is_localhost_name(hostname: str) -> bool:
    return hostname.lower().rstrip(".") == "localhost"


def _is_loopback_host(hostname: str) -> bool:
    ip = _literal_ip(hostname)
    return bool(ip and ip.is_loopback) or _is_localhost_name(hostname)


def validate_http_url(
    url: str,
    *,
    allow_http: bool = False,
    allow_http_localhost: bool = False,
    allow_private: bool = False,
    context: str = "URL",
) -> str:
    """Validate an outbound HTTP(S) URL before urllib/http clients use it.

    Defaults are intentionally strict: HTTPS only, no literal private/link-local
    IP targets. Local development can opt into loopback HTTP without permitting
    arbitrary private-network or metadata-service access.
    """

    raw = (url or "").strip()
    parsed = urlparse(raw)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise UnsafeURLError(f"{context} must use http or https")
    if not parsed.hostname:
        raise UnsafeURLError(f"{context} must include a hostname")

    host = parsed.hostname.strip("[]")
    is_loopback = _is_loopback_host(host)
    ip = _literal_ip(host)
    if scheme == "http" and not (allow_http or (allow_http_localhost and is_loopback)):
        raise UnsafeURLError(f"{context} must use https outside localhost")
    if not allow_private and not (allow_http_localhost and is_loopback):
        unsafe_host = unsafe_url_host(raw, resolve_dns=True)
        if unsafe_host:
            raise UnsafeURLError(f"{context} may not target private or local hosts")
    if _is_localhost_name(host) and not allow_http_localhost:
        raise UnsafeURLError(f"{context} may not target localhost")

    return raw


def validate_urllib_request(req, **kwargs) -> None:
    """Validate a urllib Request or URL string before opening it."""

    url = getattr(req, "full_url", req)
    validate_http_url(str(url), **kwargs)
