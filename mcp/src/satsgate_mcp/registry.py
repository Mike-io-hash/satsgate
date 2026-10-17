"""Optional local registry. A hosted Satsgate directory is not part of this release."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from satsgate_mcp.config import Settings
from satsgate_mcp.urls import UrlError, validate_url


class RegistryError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _sites(payload: object, allowlist: tuple[str, ...]) -> dict:
    if not isinstance(payload, dict) or not isinstance(payload.get("sites"), list):
        raise RegistryError("invalid_registry", "Registry JSON needs an object with a sites array.")
    sites: list[dict[str, str]] = []
    skipped = 0
    for item in payload["sites"]:
        if not isinstance(item, dict):
            skipped += 1
            continue
        name = item.get("name")
        url = item.get("url")
        if not isinstance(name, str) or not name.strip() or not isinstance(url, str):
            skipped += 1
            continue
        try:
            checked = validate_url(url.strip(), allowlist)
        except UrlError:
            skipped += 1
            continue
        description = item.get("description")
        entry = {"name": name.strip()[:80], "url": checked}
        if isinstance(description, str) and description.strip():
            entry["description"] = description.strip()[:300]
        sites.append(entry)
    return {
        "ok": True,
        "hosted_registry": False,
        "detail": "This is a local file or URL. A hosted Satsgate registry is not available yet.",
        "sites": sites,
        "skipped": skipped,
    }


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
        response = await client.get(url)
        if response.status_code != 200:
            raise RegistryError("registry_unavailable", f"Registry URL returned HTTP {response.status_code}.")
        body = response.content[: 256 * 1024]
        return load_registry_text(body.decode("utf-8"), settings.allowlist)
    if "://" in raw:
        raise RegistryError("invalid_registry", "SATSGATE_MCP_REGISTRY must be a file path or an http(s) URL.")
    path = Path(raw).expanduser()
    if not path.is_file():
        raise RegistryError("invalid_registry", "SATSGATE_MCP_REGISTRY is not a file.")
    text = path.read_text(encoding="utf-8")[: 256 * 1024]
    return load_registry_text(text, settings.allowlist)
