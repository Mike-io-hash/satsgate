"""Environment configuration. Secrets are never returned by repr or logs."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from satsgate_mcp.urls import UrlError, validate_url

_TRUE = frozenset({"1", "true", "yes", "on"})


class ConfigError(ValueError):
    pass


def _optional_int(name: str, *, minimum: int, maximum: int) -> int | None:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return None
    try:
        value = int(str(raw).strip())
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer.") from exc
    if value < minimum or value > maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}.")
    return value


def _usd_atomic(name: str) -> int | None:
    """USD from the environment as USDC atomic units (6 decimals).

    ``0.01`` is 10000. More than 6 decimal places is rejected. Unset is None.
    """
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return None
    text = str(raw).strip()
    if text.startswith("+"):
        text = text[1:]
    if not re.fullmatch(r"\d+(\.\d+)?", text):
        raise ConfigError(f"{name} must be a USD amount with up to 6 decimal places.")
    whole, _, frac = text.partition(".")
    if len(frac) > 6:
        raise ConfigError(f"{name} must have at most 6 decimal places.")
    atomic = int(whole) * 1_000_000 + int((frac or "0").ljust(6, "0"))
    if atomic > 1_000_000 * 1_000_000:
        raise ConfigError(f"{name} must be at most 1000000 USD.")
    return atomic


def _allowlist() -> tuple[str, ...]:
    raw = os.environ.get("SATSGATE_MCP_URL_ALLOWLIST", "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class Settings:
    nwc_uri: str
    max_payment_sats: int | None
    daily_max_sats: int | None
    max_payment_usd_atomic: int | None
    daily_max_usd_atomic: int | None
    auto_pay: bool
    data_dir: Path
    core_url: str
    api_key: str
    api_key_rejected: bool
    allowlist: tuple[str, ...]
    timeout: float
    registry: str
    max_body_bytes: int

    def __repr__(self) -> str:
        nwc = "set" if self.nwc_uri else "unset"
        key = "set" if self.api_key else "unset"
        return (
            f"Settings(nwc_uri={nwc}, api_key={key}, max_payment_sats={self.max_payment_sats}, "
            f"daily_max_sats={self.daily_max_sats}, max_payment_usd_atomic={self.max_payment_usd_atomic}, "
            f"daily_max_usd_atomic={self.daily_max_usd_atomic}, auto_pay={self.auto_pay}, "
            f"core_url={self.core_url!r})"
        )


def load_settings() -> Settings:
    nwc = os.environ.get("SATSGATE_MCP_NWC_URI", "").strip()
    if nwc and not nwc.lower().startswith("nostr+walletconnect://"):
        raise ConfigError("SATSGATE_MCP_NWC_URI must be a nostr+walletconnect URI.")
    if nwc and ("secret=" not in nwc.lower() or "relay=" not in nwc.lower()):
        raise ConfigError("SATSGATE_MCP_NWC_URI must include relay and secret.")

    raw_key = os.environ.get("SATSGATE_MCP_API_KEY", "").strip()
    rejected = False
    api_key = ""
    if raw_key:
        if raw_key.startswith("sgr_") and len(raw_key) >= 12 and " " not in raw_key:
            api_key = raw_key
        else:
            rejected = True

    data_dir = Path(os.environ.get("SATSGATE_MCP_DATA_DIR", "~/.local/share/satsgate-mcp")).expanduser()
    timeout = _optional_int("SATSGATE_MCP_HTTP_TIMEOUT", minimum=1, maximum=120)
    max_body = _optional_int("SATSGATE_MCP_MAX_BODY_BYTES", minimum=1024, maximum=10_000_000)
    core = os.environ.get("SATSGATE_MCP_CORE_URL", "https://api.satsgate.org").strip().rstrip("/")
    try:
        core = validate_url(core)
    except UrlError as exc:
        raise ConfigError("SATSGATE_MCP_CORE_URL is not an http(s) URL.") from exc

    return Settings(
        nwc_uri=nwc,
        max_payment_sats=_optional_int("SATSGATE_MCP_MAX_PAYMENT_SATS", minimum=0, maximum=100_000_000),
        daily_max_sats=_optional_int("SATSGATE_MCP_DAILY_MAX_SATS", minimum=0, maximum=100_000_000),
        max_payment_usd_atomic=_usd_atomic("SATSGATE_MCP_MAX_PAYMENT_USD"),
        daily_max_usd_atomic=_usd_atomic("SATSGATE_MCP_DAILY_MAX_USD"),
        auto_pay=os.environ.get("SATSGATE_MCP_AUTO_PAY", "").strip().lower() in _TRUE,
        data_dir=data_dir,
        core_url=core,
        api_key=api_key,
        api_key_rejected=rejected,
        allowlist=_allowlist(),
        timeout=float(timeout if timeout is not None else 20),
        registry=os.environ.get("SATSGATE_MCP_REGISTRY", "").strip(),
        max_body_bytes=max_body if max_body is not None else 1_000_000,
    )
