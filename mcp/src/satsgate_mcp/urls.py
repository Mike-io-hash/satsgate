"""http and https only, with an optional host allowlist."""

from __future__ import annotations

from urllib.parse import urlsplit

from satsgate_mcp.redact import scrub


class UrlError(ValueError):
    pass


def _host_allowed(host: str, allowlist: tuple[str, ...]) -> bool:
    lowered = host.lower().rstrip(".")
    for rule in allowlist:
        item = rule.lower().rstrip(".")
        if item.startswith("*."):
            parent = item[2:]
            if lowered == parent or lowered.endswith("." + parent):
                return True
        elif lowered == item:
            return True
    return False


def validate_url(url: str, allowlist: tuple[str, ...] = ()) -> str:
    """Return the URL when it is safe to request. Rejects userinfo and non-HTTP schemes."""
    raw = str(url).strip()
    if not raw or any(char in raw for char in "\r\n\x00 \t"):
        raise UrlError("The URL is empty or contains whitespace.")
    parts = urlsplit(raw)
    if parts.scheme not in {"http", "https"}:
        raise UrlError("Only http and https URLs are allowed.")
    if parts.username is not None or parts.password is not None:
        raise UrlError("URLs with a username or password are not allowed.")
    host = parts.hostname
    if not host:
        raise UrlError("The URL has no host.")
    if allowlist and not _host_allowed(host, allowlist):
        raise UrlError(f"{host} is not in SATSGATE_MCP_URL_ALLOWLIST.")
    if parts.fragment:
        raw = raw.split("#", 1)[0]
    return raw


def public_url_error(exc: Exception) -> str:
    return scrub(str(exc))
