"""Route and free-path matching. First match wins. Unknown paths fail closed."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol


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
