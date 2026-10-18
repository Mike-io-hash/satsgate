"""Environment for the gate process. The origin secret is not an env var.

Core decrypts one site's secret and returns it on the internal config route.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit


class ConfigError(ValueError):
    pass


def _int_env(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(str(raw).strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _float_env(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = float(str(raw).strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number") from exc
    if value < minimum or value > maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _core_url(raw: str) -> str:
    text = (raw or "").strip().rstrip("/")
    parsed = urlsplit(text)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ConfigError("SATSGATE_GATE_CORE_URL must be an http(s) origin with no userinfo, path, query, or fragment")
    return text


@dataclass(frozen=True)
class Settings:
    core_base_url: str
    gate_token: str
    trusted_proxies: str
    cache_seconds: float
    core_timeout: float
    upstream_timeout: float
    max_request_bytes: int
    max_response_bytes: int
    rl_window_seconds: int
    rl_per_site: int
    rl_per_buyer: int
    pending_retry_after: int
    resolver: Callable | None = None

    def __repr__(self) -> str:
        return (
            f"Settings(core={self.core_base_url}, cache={self.cache_seconds},"
            f" token_set={bool(self.gate_token)})"
        )


def load_settings() -> Settings:
    proxies = os.environ.get("SATSGATE_GATE_TRUSTED_PROXIES", "").strip()
    if any(part.strip() in {"*", "0.0.0.0/0", "::/0"} for part in proxies.split(",") if part.strip()):
        raise ConfigError("SATSGATE_GATE_TRUSTED_PROXIES must list specific proxy IPs, not the whole internet")
    return Settings(
        core_base_url=_core_url(os.environ.get("SATSGATE_GATE_CORE_URL", "http://satsgate:8000")),
        gate_token=os.environ.get("SATSGATE_GATE_TOKEN", "").strip(),
        trusted_proxies=proxies,
        cache_seconds=_float_env("SATSGATE_GATE_CACHE_SECONDS", 5, minimum=0, maximum=60),
        core_timeout=_float_env("SATSGATE_GATE_CORE_TIMEOUT", 10, minimum=1, maximum=60),
        upstream_timeout=_float_env("SATSGATE_GATE_UPSTREAM_TIMEOUT", 15, minimum=1, maximum=120),
        max_request_bytes=_int_env("SATSGATE_GATE_MAX_REQUEST_BYTES", 1024 * 1024, minimum=1, maximum=32 * 1024 * 1024),
        max_response_bytes=_int_env(
            "SATSGATE_GATE_MAX_RESPONSE_BYTES",
            10 * 1024 * 1024,
            minimum=1,
            maximum=64 * 1024 * 1024,
        ),
        rl_window_seconds=_int_env("SATSGATE_GATE_RL_WINDOW_SECONDS", 60, minimum=1, maximum=3600),
        rl_per_site=_int_env("SATSGATE_GATE_RL_PER_SITE", 600, minimum=0, maximum=100_000),
        rl_per_buyer=_int_env("SATSGATE_GATE_RL_PER_BUYER", 60, minimum=0, maximum=100_000),
        pending_retry_after=_int_env("SATSGATE_GATE_PENDING_RETRY_AFTER", 2, minimum=1, maximum=60),
    )
