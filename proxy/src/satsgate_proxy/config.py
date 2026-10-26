"""YAML config. Secrets are read from the environment and are not logged."""

from __future__ import annotations

import hashlib
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from satsgate_proxy.match import MatchError, compile_glob, compile_regex

log = logging.getLogger("satsgate_proxy")


def key_fingerprint(api_key: str) -> str:
    """Short SHA-256 id for logs. Not a prefix of the key and not reversible from the log line."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:12]

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_ROUTE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.0-9A-Z^_`a-z|~]+$")
_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
_FORBIDDEN_PROXIES = frozenset({"*", "0.0.0.0/0", "::/0"})
_TOP_LEVEL = frozenset({"core", "upstream", "origin", "pricing", "server", "limits", "free_paths", "routes"})
_CORE_KEYS = frozenset({"base_url", "api_key_env", "timeout_seconds"})
_UPSTREAM_KEYS = frozenset({"base_url", "timeout_seconds", "inject_headers"})
_ORIGIN_KEYS = frozenset({"secret_env", "max_skew_seconds"})
_PRICING_KEYS = frozenset({"sats_per_credit"})
_SERVER_KEYS = frozenset({"host", "port", "listen", "trusted_proxies", "pending_retry_after_seconds", "public_base"})
_LIMIT_KEYS = frozenset({"max_request_bytes", "max_response_bytes"})
_ROUTE_KEYS = frozenset(
    {"name", "methods", "path", "path_regex", "price_sats", "access", "scope", "description", "x402"}
)
_INJECT_KEYS = frozenset({"name", "value_env"})
_HOP = frozenset(
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
        "host",
        "content-length",
    }
)

MAX_PAYWALL_USES = 100_000
MAX_ACCESS_SECONDS = 604_800
MAX_PRICE_SATS = 10_000_000
MAX_REQUEST_BYTES = 32 * 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
DEFAULT_REQUEST_BYTES = 1024 * 1024
DEFAULT_RESPONSE_BYTES = 10 * 1024 * 1024
CHEAP_CALL_MULTIPLE = 10
MEMO_MAX = 250


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Access:
    kind: str
    n: int | None

    def policy(self) -> tuple[int | None, int | None]:
        if self.kind == "per_request":
            return 1, None
        if self.kind == "uses":
            return self.n, None
        return None, self.n

    def label(self) -> str:
        if self.kind == "per_request":
            return "per_request"
        if self.kind == "uses":
            return f"uses:{self.n}"
        return f"pass:{self.n}"


@dataclass(frozen=True)
class Route:
    name: str
    methods: frozenset[str]
    pattern: re.Pattern[str]
    price_sats: int
    access: Access
    scope: str
    resource: str
    description: str | None
    x402: bool = False

    def __repr__(self) -> str:
        return f"Route({self.name} {self.access.label()} {self.price_sats}sats {self.scope})"


@dataclass(frozen=True)
class Settings:
    core_base_url: str
    api_key: str = field(repr=False)
    core_timeout: float
    upstream_base_url: str
    upstream_timeout: float
    inject_headers: tuple[tuple[str, str], ...] = field(repr=False)
    origin_secret: str = field(repr=False)
    max_skew_seconds: int
    sats_per_credit: int
    host: str
    port: int
    trusted_proxies: str
    pending_retry_after: int
    max_request_bytes: int
    max_response_bytes: int
    free_patterns: tuple[re.Pattern[str], ...]
    routes: tuple[Route, ...]
    warnings: tuple[str, ...]
    public_base: str = ""

    def __repr__(self) -> str:
        return (
            f"Settings(core={self.core_base_url}, upstream={self.upstream_base_url}, "
            f"routes={len(self.routes)})"
        )


def _mapping(value: object, label: str) -> dict:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a mapping")
    return value


def _reject_unknown(data: dict, allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError(f"unknown {label} key: {unknown[0]}")


def _require(data: dict, key: str, label: str) -> object:
    if key not in data or data[key] is None:
        raise ConfigError(f"{label} is required")
    return data[key]


def _as_str(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label} must be a string")
    return value.strip()


def _as_int(value: object, label: str, *, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{label} must be an integer")
    if value < lo or value > hi:
        raise ConfigError(f"{label} must be from {lo} to {hi}")
    return value


def _as_float(value: object, label: str, *, lo: float, hi: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{label} must be a number")
    number = float(value)
    if number < lo or number > hi:
        raise ConfigError(f"{label} must be from {lo} to {hi}")
    return number


def _env_name(value: object, label: str) -> str:
    name = _as_str(value, label)
    if not _ENV_NAME.fullmatch(name):
        raise ConfigError(f"{label} is not an environment variable name")
    return name


def _env_value(name: str) -> str:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        raise ConfigError(f"environment variable {name} is not set")
    return raw.strip()


def _http_base(value: object, label: str) -> str:
    text = _as_str(value, label)
    parts = urlsplit(text)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ConfigError(f"{label} must be an http(s) URL")
    if parts.username or parts.password:
        raise ConfigError(f"{label} must not include userinfo")
    if parts.query or parts.fragment:
        raise ConfigError(f"{label} must not include a query or fragment")
    if parts.path not in {"", "/"}:
        raise ConfigError(f"{label} must not include a path")
    return f"{parts.scheme}://{parts.netloc}"


def _parse_access(value: object) -> Access:
    text = _as_str(value, "access")
    if text == "per_request":
        return Access("per_request", None)
    kind, sep, raw = text.partition(":")
    if sep != ":" or kind not in {"uses", "pass"}:
        raise ConfigError("access must be per_request, uses:N, or pass:<seconds>")
    try:
        n = int(raw)
    except ValueError as exc:
        raise ConfigError("access must be per_request, uses:N, or pass:<seconds>") from exc
    if kind == "uses":
        if n < 1 or n > MAX_PAYWALL_USES:
            raise ConfigError(f"uses must be from 1 to {MAX_PAYWALL_USES}")
        return Access("uses", n)
    if n < 1 or n > MAX_ACCESS_SECONDS:
        raise ConfigError(f"pass seconds must be from 1 to {MAX_ACCESS_SECONDS}")
    return Access("pass", n)


def _parse_listen(value: str) -> tuple[str, int]:
    if value.startswith("["):
        end = value.find("]")
        if end == -1 or not value[end:].startswith("]:"):
            raise ConfigError("listen must be host:port")
        host = value[1:end]
        port_text = value[end + 2 :]
    else:
        if value.count(":") != 1:
            raise ConfigError("listen must be host:port")
        host, port_text = value.rsplit(":", 1)
    if not host:
        raise ConfigError("listen host is empty")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ConfigError("listen port must be an integer") from exc
    if port < 1 or port > 65535:
        raise ConfigError("listen port must be from 1 to 65535")
    return host, port


def _trusted_proxies(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",") if part.strip()]
    elif isinstance(value, list):
        items = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ConfigError("trusted_proxies entries must be strings")
            items.append(item.strip())
    else:
        raise ConfigError("trusted_proxies must be a list or a string")
    if any(item in _FORBIDDEN_PROXIES for item in items):
        raise ConfigError("trusted_proxies must list specific addresses, not the whole internet")
    return ",".join(items)


def _api_key(env_name: str) -> str:
    key = _env_value(env_name)
    if not key.startswith("sgr_") or len(key) < 12:
        raise ConfigError("core api key must be a restricted sgr_ key")
    return key


def _origin_secret(env_name: str) -> tuple[str, str | None]:
    secret = _env_value(env_name)
    if len(secret) < 16:
        raise ConfigError("origin secret must be at least 16 characters")
    warning = None
    if len(secret) < 32:
        warning = "origin secret is shorter than 32 characters; use a long random value"
    return secret, warning


def _inject_headers(value: object) -> tuple[tuple[str, str], ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError("inject_headers must be a list")
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in value:
        data = _mapping(item, "inject_headers entry")
        _reject_unknown(data, _INJECT_KEYS, "inject_headers")
        name = _as_str(_require(data, "name", "inject header name"), "inject header name")
        if not _HEADER_NAME.fullmatch(name):
            raise ConfigError("inject header name is not a valid header name")
        lower = name.lower()
        if lower.startswith("x-satsgate-") or lower in _HOP:
            raise ConfigError(f"inject header {name} is reserved")
        if lower in seen:
            raise ConfigError(f"inject header {name} is listed twice")
        seen.add(lower)
        env_name = _env_name(_require(data, "value_env", "inject value_env"), "inject value_env")
        out.append((name, _env_value(env_name)))
    return tuple(out)


def _description(value: object) -> str | None:
    if value is None:
        return None
    text = _as_str(value, "description")
    cleaned = " ".join(text.split())
    if not cleaned:
        return None
    return cleaned[:MEMO_MAX]


def _routes(value: object) -> tuple[Route, ...]:
    if not isinstance(value, list) or not value:
        raise ConfigError("routes must be a non-empty list")
    routes: list[Route] = []
    names: set[str] = set()
    site: tuple[int, Access] | None = None
    for item in value:
        data = _mapping(item, "route")
        _reject_unknown(data, _ROUTE_KEYS, "route")
        name = _as_str(_require(data, "name", "route name"), "route name")
        if not _ROUTE_NAME.fullmatch(name):
            raise ConfigError(f"route name is invalid: {name}")
        if name in names:
            raise ConfigError(f"duplicate route name: {name}")
        names.add(name)
        methods_raw = _require(data, "methods", f"route {name} methods")
        if not isinstance(methods_raw, list) or not methods_raw:
            raise ConfigError(f"route {name} methods must be a non-empty list")
        methods: set[str] = set()
        for method in methods_raw:
            if not isinstance(method, str):
                raise ConfigError(f"route {name} method must be a string")
            upper = method.strip().upper()
            if upper not in _METHODS:
                raise ConfigError(f"route {name} method is not supported: {upper}")
            methods.add(upper)
        has_path = "path" in data and data["path"] is not None
        has_regex = "path_regex" in data and data["path_regex"] is not None
        if has_path == has_regex:
            raise ConfigError(f"route {name} needs exactly one of path or path_regex")
        try:
            if has_path:
                pattern = compile_glob(_as_str(data["path"], f"route {name} path"))
            else:
                pattern = compile_regex(_as_str(data["path_regex"], f"route {name} path_regex"))
        except MatchError as exc:
            raise ConfigError(str(exc)) from exc
        price = _as_int(_require(data, "price_sats", f"route {name} price_sats"), f"route {name} price_sats", lo=1, hi=MAX_PRICE_SATS)
        access = _parse_access(_require(data, "access", f"route {name} access"))
        scope = _as_str(_require(data, "scope", f"route {name} scope"), f"route {name} scope")
        if scope not in {"route", "site"}:
            raise ConfigError(f"route {name} scope must be route or site")
        if scope == "site":
            if site is None:
                site = (price, access)
            elif site != (price, access):
                raise ConfigError("site-scoped routes must share price_sats and access")
        resource = "site" if scope == "site" else f"route:{name}"
        if "x402" in data and data["x402"] is not None and not isinstance(data["x402"], bool):
            raise ConfigError(f"route {name} x402 must be true or false")
        routes.append(
            Route(
                name=name,
                methods=frozenset(methods),
                pattern=pattern,
                price_sats=price,
                access=access,
                scope=scope,
                resource=resource,
                description=_description(data.get("description")),
                x402=bool(data.get("x402", False)),
            )
        )
    return tuple(routes)


def _free_patterns(value: object) -> tuple[re.Pattern[str], ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ConfigError("free_paths must be a list")
    compiled: list[re.Pattern[str]] = []
    for item in value:
        try:
            compiled.append(compile_glob(_as_str(item, "free path")))
        except MatchError as exc:
            raise ConfigError(str(exc)) from exc
    return tuple(compiled)


def _cheap_warnings(routes: tuple[Route, ...], sats_per_credit: int) -> list[str]:
    threshold = CHEAP_CALL_MULTIPLE * sats_per_credit
    warnings: list[str] = []
    for route in routes:
        if route.access.kind == "per_request" and route.price_sats < threshold:
            warnings.append(
                f"route {route.name} price {route.price_sats} sats per_request is below {threshold} "
                f"(10 x sats_per_credit {sats_per_credit}). "
                "Cheap calls should use uses:N or pass:<seconds> so one credit covers many requests."
            )
    return warnings


def _redact(secrets: list[str]) -> None:
    logger = logging.getLogger("satsgate_proxy")
    logger.filters = [item for item in logger.filters if not isinstance(item, _Redact)]
    logger.addFilter(_Redact([item for item in secrets if len(item) >= 8]))


class _Redact(logging.Filter):
    def __init__(self, secrets: list[str]) -> None:
        super().__init__()
        self.secrets = secrets

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        redacted = message
        for secret in self.secrets:
            if secret in redacted:
                redacted = redacted.replace(secret, "[redacted]")
        if redacted != message:
            record.msg = redacted
            record.args = ()
        return True


def load_settings(path: str | Path) -> Settings:
    config_path = Path(path)
    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config {config_path}") from exc
    try:
        loaded = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigError("config is not valid YAML") from exc
    data = _mapping(loaded, "config")
    _reject_unknown(data, _TOP_LEVEL, "config")

    core = _mapping(_require(data, "core", "core"), "core")
    _reject_unknown(core, _CORE_KEYS, "core")
    upstream = _mapping(_require(data, "upstream", "upstream"), "upstream")
    _reject_unknown(upstream, _UPSTREAM_KEYS, "upstream")
    origin = _mapping(_require(data, "origin", "origin"), "origin")
    _reject_unknown(origin, _ORIGIN_KEYS, "origin")
    pricing = _mapping(data.get("pricing") or {}, "pricing")
    _reject_unknown(pricing, _PRICING_KEYS, "pricing")
    server = _mapping(data.get("server") or {}, "server")
    _reject_unknown(server, _SERVER_KEYS, "server")
    limits = _mapping(data.get("limits") or {}, "limits")
    _reject_unknown(limits, _LIMIT_KEYS, "limits")

    api_key = _api_key(_env_name(core.get("api_key_env", "SATSGATE_API_KEY"), "api_key_env"))
    secret, secret_warning = _origin_secret(_env_name(origin.get("secret_env", "SATSGATE_ORIGIN_SECRET"), "secret_env"))
    inject = _inject_headers(upstream.get("inject_headers"))
    routes = _routes(_require(data, "routes", "routes"))
    sats_per_credit = _as_int(pricing.get("sats_per_credit", 5), "sats_per_credit", lo=1, hi=1_000_000)

    if "listen" in server and ("host" in server or "port" in server):
        raise ConfigError("set listen or host and port, not both")
    if "listen" in server:
        host, port = _parse_listen(_as_str(server["listen"], "listen"))
    else:
        host = _as_str(server.get("host", "127.0.0.1"), "host")
        port = _as_int(server.get("port", 8080), "port", lo=1, hi=65535)

    public_base = ""
    if server.get("public_base"):
        public_base = _http_base(server["public_base"], "public_base")
    if any(route.x402 for route in routes) and not public_base:
        raise ConfigError("server.public_base is required when a route sets x402: true")

    warnings = _cheap_warnings(routes, sats_per_credit)
    if secret_warning:
        warnings.append(secret_warning)
    for warning in warnings:
        log.warning("%s", warning)

    _redact([api_key, secret, *[value for _name, value in inject]])
    return Settings(
        core_base_url=_http_base(_require(core, "base_url", "core.base_url"), "core.base_url"),
        api_key=api_key,
        core_timeout=_as_float(core.get("timeout_seconds", 20), "core.timeout_seconds", lo=0.1, hi=120),
        upstream_base_url=_http_base(_require(upstream, "base_url", "upstream.base_url"), "upstream.base_url"),
        upstream_timeout=_as_float(upstream.get("timeout_seconds", 30), "upstream.timeout_seconds", lo=0.1, hi=120),
        inject_headers=inject,
        origin_secret=secret,
        max_skew_seconds=_as_int(origin.get("max_skew_seconds", 300), "max_skew_seconds", lo=1, hi=3600),
        sats_per_credit=sats_per_credit,
        host=host,
        port=port,
        trusted_proxies=_trusted_proxies(server.get("trusted_proxies")),
        pending_retry_after=_as_int(
            server.get("pending_retry_after_seconds", 2),
            "pending_retry_after_seconds",
            lo=1,
            hi=60,
        ),
        max_request_bytes=_as_int(
            limits.get("max_request_bytes", DEFAULT_REQUEST_BYTES),
            "max_request_bytes",
            lo=1,
            hi=MAX_REQUEST_BYTES,
        ),
        max_response_bytes=_as_int(
            limits.get("max_response_bytes", DEFAULT_RESPONSE_BYTES),
            "max_response_bytes",
            lo=1,
            hi=MAX_RESPONSE_BYTES,
        ),
        free_patterns=_free_patterns(data.get("free_paths")),
        routes=routes,
        warnings=tuple(warnings),
        public_base=public_base,
    )
