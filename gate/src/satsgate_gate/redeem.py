"""Redeem URL. The gate does not call it."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def origin_target(origin_url: str, route_path: str, query: str = "") -> str:
    del query
    parts = urlsplit(origin_url)
    base = (parts.path or "").rstrip("/")
    extra = "" if route_path == "/" else route_path
    path = base + extra
    if not path.startswith("/"):
        path = "/" + path
    if ".." in path or "\\" in path or "//" in path:
        raise ValueError("destination_rejected")
    return urlunsplit(("https", parts.netloc, path, "", ""))


def seller_host(origin_url: str) -> str:
    return urlsplit(origin_url).hostname or ""
