"""Site directory: a local JSON file, or GET /v1/sites from satsgate core.

A file is ``{"sites": [{"name", "url", "description"}]}``.
The core directory is the same ``sites`` array plus ``hosted_registry: true``,
``slug``, ``routes``, and ``next_cursor``. This reader keeps both.
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


class RegistryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _one_site(item: object, allowlist: tuple[str, ...]) -> dict | None:
    if not isinstance(item, dict):
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
            price = route.get("price_sats")
            if not isinstance(path, str) or not path.startswith("/") or isinstance(price, bool):
                continue
            if not isinstance(price, int):
                continue
            uses = route.get("max_uses")
            access = route.get("access_seconds")
            kept.append(
                {
                    "path": path[:200],
                    "price_sats": price,
                    "max_uses": uses if isinstance(uses, int) and not isinstance(uses, bool) else None,
                    "access_seconds": access if isinstance(access, int) and not isinstance(access, bool) else None,
                }
            )
        if kept:
            entry["routes"] = kept
    return entry


def _sites(payload: object, allowlist: tuple[str, ...]) -> dict:
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
    if hosted:
        detail = "Approved sites that opted into the public Satsgate directory."
    else:
        detail = "This is a local file or URL. Set SATSGATE_MCP_REGISTRY to https://api.satsgate.org/v1/sites for the hosted directory."
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


def load_registry_text(text: str, allowlist: tuple[str, ...]) -> dict:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RegistryError("invalid_registry", "Registry file is not JSON.") from exc
    return _sites(payload, allowlist)


async def load_registry(settings: Settings, client: httpx.AsyncClient) -> dict:
    raw = settings.registry
    if not raw:
        return {
            "ok": False,
            "error": "registry_not_configured",
            "hosted_registry": False,
            "detail": (
                "SATSGATE_MCP_REGISTRY is unset. Point it at a JSON file or an http(s) URL. "
                "A hosted Satsgate registry is not available yet."
            ),
            "sites": [],
        }
    if raw.startswith("http://") or raw.startswith("https://"):
        url = validate_url(raw, settings.allowlist)
        collected: list[dict] = []
        skipped = 0
        hosted = False
        cursor = ""
        for _page in range(_MAX_PAGES):
            target = _with_cursor(url, cursor) if cursor else url
            response = await client.get(target)
            if response.status_code != 200:
                raise RegistryError("registry_unavailable", f"Registry URL returned HTTP {response.status_code}.")
            page = load_registry_text(response.content[: 256 * 1024].decode("utf-8"), settings.allowlist)
            hosted = hosted or bool(page["hosted_registry"])
            collected.extend(page["sites"])
            skipped += int(page["skipped"])
            nxt = ""
            try:
                payload = json.loads(response.content[: 256 * 1024].decode("utf-8"))
            except json.JSONDecodeError:
                payload = None
            if isinstance(payload, dict) and isinstance(payload.get("next_cursor"), str):
                if _CURSOR.fullmatch(payload["next_cursor"]):
                    nxt = payload["next_cursor"]
            if not nxt or nxt == cursor:
                break
            cursor = nxt
        detail = page["detail"]
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
    text = path.read_text(encoding="utf-8")[: 256 * 1024]
    return load_registry_text(text, settings.allowlist)
