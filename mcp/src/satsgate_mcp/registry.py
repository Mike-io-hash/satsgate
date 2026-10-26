"""Site directory.

The default is ``GET {SATSGATE_MCP_CORE_URL}/v1/sites`` (approved sites that
opted in). ``SATSGATE_MCP_REGISTRY``, when set, replaces that with a JSON file
or another http(s) URL.

A file is ``{"sites": [{"name", "url", "description"}]}``.
The core directory is the same ``sites`` array plus ``hosted_registry: true``,
``slug``, ``url`` (the public gate URL), ``routes``, and ``next_cursor``.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from satsgate_mcp.config import Settings
from satsgate_mcp.urls import UrlError, validate_url

_CURSOR = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$")
_MAX_PAGES = 5
_REGISTRY_TIMEOUT = 5.0
_PUBLIC_DETAIL = (
    "Approved, listed sites from the public Satsgate directory. "
    "Unlisted and unapproved sites are not included."
)
_OVERRIDE_DETAIL = (
    "This list comes from SATSGATE_MCP_REGISTRY. "
    "Unset it to read the public directory."
)


class RegistryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _hidden(item: dict) -> bool:
    """Drop a row the public directory must not show.

    ``GET /v1/sites`` already omits these. A row that still carries ``status``
    other than ``approved``, or ``listed`` other than true, is skipped. A
    local file that does not set either field is unchanged.
    """
    if "status" in item and item.get("status") != "approved":
        return True
    if "listed" in item and item.get("listed") not in (True, 1):
        return True
    return False


def _one_site(item: object, allowlist: tuple[str, ...]) -> dict | None:
    if not isinstance(item, dict) or _hidden(item):
        return None
    name = item.get("name")
    if not isinstance(name, str) or not name.strip():
        name = item.get("display_name")
    url = item.get("url")
    if not isinstance(name, str) or not name.strip() or not isinstance(url, str):
        return None
    try:
        checked = validate_url(url.strip(), allowlist)
    except UrlError:
        return None
    entry: dict = {"name": name.strip()[:80], "url": checked}
    slug = item.get("slug")
    if isinstance(slug, str) and _CURSOR.fullmatch(slug):
        entry["slug"] = slug
    description = item.get("description")
    if isinstance(description, str) and description.strip():
        entry["description"] = description.strip()[:300]
    routes = item.get("routes")
    if isinstance(routes, list):
        kept: list[dict] = []
        for route in routes[:50]:
            if not isinstance(route, dict):
                continue
            path = route.get("path")
            if not isinstance(path, str) or not path.startswith("/"):
                continue
            price = route.get("price_sats")
            has_sats = isinstance(price, int) and not isinstance(price, bool)
            currency = route.get("price_currency")
            usd = route.get("price_usd_atomic")
            has_usd = (
                currency == "usd"
                and isinstance(usd, int)
                and not isinstance(usd, bool)
                and usd >= 1
            )
            if not has_sats and not has_usd:
                continue
            uses = route.get("max_uses")
            access = route.get("access_seconds")
            kept_route: dict = {
                "path": path[:200],
                "max_uses": uses if isinstance(uses, int) and not isinstance(uses, bool) else None,
                "access_seconds": access if isinstance(access, int) and not isinstance(access, bool) else None,
            }
            if has_sats:
                kept_route["price_sats"] = price
            if currency in {"sats", "usd"}:
                kept_route["price_currency"] = currency
            if isinstance(usd, int) and not isinstance(usd, bool) and usd >= 1:
                kept_route["price_usd_atomic"] = usd
            kept.append(kept_route)
        if kept:
            entry["routes"] = kept
    return entry


def _sites(payload: object, allowlist: tuple[str, ...], *, override: bool) -> dict:
    if not isinstance(payload, dict) or not isinstance(payload.get("sites"), list):
        raise RegistryError("invalid_registry", "Registry JSON needs an object with a sites array.")
    hosted = payload.get("hosted_registry") is True
    sites: list[dict] = []
    skipped = 0
    for item in payload["sites"]:
        parsed = _one_site(item, allowlist)
        if parsed is None:
            skipped += 1
            continue
        sites.append(parsed)
    detail = _OVERRIDE_DETAIL if override and not hosted else _PUBLIC_DETAIL
    return {
        "ok": True,
        "hosted_registry": hosted,
        "detail": detail,
        "sites": sites,
        "skipped": skipped,
    }


def _with_cursor(url: str, cursor: str) -> str:
    parts = urlsplit(url)
    query = [(key, value) for key, value in parse_qsl(parts.query, keep_blank_values=True) if key != "cursor"]
    query.append(("cursor", cursor))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), ""))


def load_registry_text(text: str, allowlist: tuple[str, ...], *, override: bool) -> dict:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RegistryError("invalid_registry", "Registry file is not JSON.") from exc
    return _sites(payload, allowlist, override=override)


def _registry_timeout(settings: Settings) -> float:
    return min(float(settings.timeout), _REGISTRY_TIMEOUT)


def _response_text(response: httpx.Response) -> str:
    try:
        return response.content[: 256 * 1024].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RegistryError("invalid_registry", "The site directory response was not UTF-8 JSON.") from exc


def _next_cursor(text: str) -> str:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return ""
    if isinstance(payload, dict) and isinstance(payload.get("next_cursor"), str):
        if _CURSOR.fullmatch(payload["next_cursor"]):
            return payload["next_cursor"]
    return ""


async def _fetch_text(client: httpx.AsyncClient, url: str, timeout: float) -> str:
    try:
        response = await client.get(url, timeout=timeout)
    except httpx.TimeoutException as exc:
        raise RegistryError("registry_unavailable", "The site directory did not respond in time.") from exc
    except httpx.HTTPError as exc:
        raise RegistryError("registry_unavailable", "The site directory could not be reached.") from exc
    if response.status_code != 200:
        raise RegistryError(
            "registry_unavailable",
            f"The site directory returned HTTP {response.status_code}.",
        )
    return _response_text(response)


async def load_registry(settings: Settings, client: httpx.AsyncClient) -> dict:
    raw = settings.registry.strip()
    override = bool(raw)
    if not override:
        raw = settings.core_url.rstrip("/") + "/v1/sites"
    if raw.startswith("http://") or raw.startswith("https://"):
        url = validate_url(raw, settings.allowlist)
        timeout = _registry_timeout(settings)
        collected: list[dict] = []
        skipped = 0
        hosted = False
        cursor = ""
        for _page in range(_MAX_PAGES):
            target = _with_cursor(url, cursor) if cursor else url
            text = await _fetch_text(client, target, timeout)
            page = load_registry_text(text, settings.allowlist, override=override)
            hosted = hosted or bool(page["hosted_registry"])
            collected.extend(page["sites"])
            skipped += int(page["skipped"])
            nxt = _next_cursor(text)
            if not nxt or nxt == cursor:
                break
            cursor = nxt
        detail = _OVERRIDE_DETAIL if override and not hosted else _PUBLIC_DETAIL
        return {
            "ok": True,
            "hosted_registry": hosted,
            "detail": detail,
            "sites": collected,
            "skipped": skipped,
        }
    if "://" in raw:
        raise RegistryError("invalid_registry", "SATSGATE_MCP_REGISTRY must be a file path or an http(s) URL.")
    path = Path(raw).expanduser()
    if not path.is_file():
        raise RegistryError("invalid_registry", "SATSGATE_MCP_REGISTRY is not a file.")
    try:
        text = path.read_text(encoding="utf-8")[: 256 * 1024]
    except OSError as exc:
        raise RegistryError("invalid_registry", "SATSGATE_MCP_REGISTRY could not be read.") from exc
    return load_registry_text(text, settings.allowlist, override=True)
