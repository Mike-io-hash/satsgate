"""Header filtering between the buyer and the origin.

The request rules match satsgate-proxy 0.8.0. Responses also drop caching
headers. The gate sets ``Cache-Control: no-store`` itself so a paid body is
not stored by a browser or a shared cache.
"""

from __future__ import annotations

HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
    }
)

# PAYMENT-* is the buyer's x402 credential. The origin must not see it.
# The gate adds PAYMENT-RESPONSE itself after settle, never from the origin.
_PAYMENT = frozenset({"payment-signature", "payment-required", "payment-response"})

_REQUEST_DROP = HOP_BY_HOP | {"host", "content-length"} | _PAYMENT

_RESPONSE_DROP = HOP_BY_HOP | {
    "server",
    "via",
    "x-powered-by",
    "content-encoding",
    "content-length",
    "location",
    "cache-control",
    "expires",
    "pragma",
    "etag",
} | _PAYMENT


def _connection_names(raw: list[tuple[bytes, bytes]]) -> set[str]:
    names: set[str] = set()
    for key, value in raw:
        if key.lower() != b"connection":
            continue
        for part in value.decode("latin-1").split(","):
            item = part.strip().lower()
            if item:
                names.add(item)
    return names


def _safe_text(value: str) -> bool:
    return not any(char in value for char in "\r\n\0")


def filter_request_headers(
    raw: list[tuple[bytes, bytes]],
    *,
    inject: tuple[tuple[str, str], ...] = (),
) -> list[tuple[str, str]]:
    """Drop hop-by-hop, client X-Satsgate-*, L402/LSAT Authorization, and PAYMENT-*."""
    blocked = _REQUEST_DROP | _connection_names(raw)
    kept: list[tuple[str, str]] = []
    for key, value in raw:
        name = key.decode("latin-1")
        lower = name.lower()
        if lower in blocked or lower.startswith("x-satsgate-"):
            continue
        text = value.decode("latin-1")
        if not _safe_text(text):
            continue
        if lower == "authorization":
            scheme = text.split(None, 1)[0].lower() if text.strip() else ""
            if scheme in {"l402", "lsat"}:
                continue
        if lower == "accept-encoding":
            continue
        kept.append((name, text))
    kept.append(("Accept-Encoding", "identity"))
    inject_names = {name.lower() for name, _value in inject}
    if inject_names:
        kept = [(name, value) for name, value in kept if name.lower() not in inject_names]
        for name, value in inject:
            if _safe_text(name) and _safe_text(value):
                kept.append((name, value))
    return kept


def filter_response_headers(items: list[tuple[str, str]]) -> list[tuple[bytes, bytes]]:
    raw = [(name.encode("latin-1"), value.encode("latin-1")) for name, value in items]
    blocked = _RESPONSE_DROP | _connection_names(raw)
    out: list[tuple[bytes, bytes]] = []
    for name, value in items:
        if name.lower() in blocked:
            continue
        if not _safe_text(name) or not _safe_text(value):
            continue
        try:
            out.append((name.encode("latin-1"), value.encode("latin-1")))
        except UnicodeEncodeError:
            continue
    return out
