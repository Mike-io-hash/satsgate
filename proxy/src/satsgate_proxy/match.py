"""Route and free-path matching. First match wins. Unknown paths fail closed."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import unquote_to_bytes


class MatchError(ValueError):
    pass


def compile_glob(pattern: str) -> re.Pattern[str]:
    """Compile a path glob.

    ``*`` is one segment. A trailing ``/**`` matches that prefix and anything
    under it, including the prefix itself. ``**`` anywhere else is rejected.
    """
    if not isinstance(pattern, str) or not pattern.startswith("/"):
        raise MatchError(f"path must start with /: {pattern!r}")
    if pattern == "/":
        return re.compile("^/$")
    if pattern == "/**":
        return re.compile("^/.*$")
    parts = pattern.split("/")
    if any(part == "" for part in parts[1:]):
        raise MatchError(f"empty path segment: {pattern}")
    body = ["^"]
    for index, part in enumerate(parts[1:], start=1):
        last = index == len(parts) - 1
        if part == "**":
            if not last:
                raise MatchError(f"** is only allowed as the last segment: {pattern}")
            body.append("(?:/.*)?")
            continue
        if part == "*":
            body.append("/[^/]+")
            continue
        if "*" in part or "?" in part:
            raise MatchError(f"only a whole-segment * and a trailing ** are supported: {pattern}")
        body.append("/" + re.escape(part))
    body.append("$")
    return re.compile("".join(body))


def unsafe_request_path(raw_path: bytes) -> bool:
    """Return true when a raw request path must be rejected.

    The query string is ignored. The raw bytes and up to three percent-decodings
    are checked. A path is unsafe when any of these holds:

    1. A segment is ``.`` or ``..`` once text after ``;`` is removed.
    2. A backslash, or an encoded slash or backslash, is present.
    3. A fourth decoding would still change the bytes.
    """
    view = raw_path.split(b"?", 1)[0]
    for index in range(4):
        if _dot_segment(view) or _other_separator(view):
            return True
        decoded = unquote_to_bytes(view)
        if decoded == view:
            return False
        if index == 3:
            return True
        view = decoded
    return False


def _dot_segment(view: bytes) -> bool:
    for part in view.replace(b"\\", b"/").split(b"/"):
        segment = part.split(b";", 1)[0]
        if segment in {b".", b".."}:
            return True
    return False


def _other_separator(view: bytes) -> bool:
    if b"\\" in view:
        return True
    folded = view.lower()
    return b"%2f" in folded or b"%5c" in folded


def compile_regex(pattern: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern)
    except re.error as exc:
        raise MatchError(f"invalid path_regex: {exc}") from exc


class _Route(Protocol):
    pattern: re.Pattern[str]
    methods: frozenset[str]


@dataclass(frozen=True)
class RouteMatch:
    kind: str
    route: object | None = None
    allow: tuple[str, ...] = ()


def match_request(
    routes: tuple[_Route, ...],
    free_patterns: tuple[re.Pattern[str], ...],
    method: str,
    path: str,
) -> RouteMatch:
    for pattern in free_patterns:
        if pattern.fullmatch(path):
            return RouteMatch(kind="free")
    path_hits: list[_Route] = []
    for route in routes:
        if route.pattern.fullmatch(path):
            if method in route.methods:
                return RouteMatch(kind="route", route=route)
            path_hits.append(route)
    if path_hits:
        allow = tuple(sorted({item for route in path_hits for item in route.methods}))
        return RouteMatch(kind="method", allow=allow)
    return RouteMatch(kind="not_found")
