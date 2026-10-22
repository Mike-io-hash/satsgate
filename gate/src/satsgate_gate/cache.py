"""Short cache of an approved site. Status is never cached.

The cache may hold the route's main price and which rails are enabled.
It must not hold a derived quote. That amount is locked on the challenge.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass(frozen=True)
class GateRoute:
    path: str
    price_sats: int | None
    max_uses: int | None
    access_seconds: int | None
    price_currency: str = "sats"
    price_usd_atomic: int | None = None


@dataclass(frozen=True)
class CachedSite:
    slug: str
    client_id: int
    origin_url: str
    payee: str | None
    routes: tuple[GateRoute, ...]
    origin_secret: str = field(repr=False)
    rail_lightning: bool = True
    rail_x402: bool = False

    def route(self, path: str) -> GateRoute | None:
        for item in self.routes:
            if item.path == path:
                return item
        return None

    def resource(self, path: str) -> str:
        return f"gate:{self.slug}:{path}"


class SiteCache:
    def __init__(self, ttl_seconds: float) -> None:
        self.ttl_seconds = float(ttl_seconds)
        self._lock = threading.Lock()
        self._items: dict[str, tuple[float, CachedSite]] = {}

    def get(self, slug: str) -> CachedSite | None:
        if self.ttl_seconds <= 0:
            return None
        now = time.monotonic()
        with self._lock:
            item = self._items.get(slug)
            if item is None:
                return None
            expires, site = item
            if now >= expires:
                del self._items[slug]
                return None
            return site

    def put(self, site: CachedSite) -> None:
        if self.ttl_seconds <= 0:
            return
        with self._lock:
            self._items[site.slug] = (time.monotonic() + self.ttl_seconds, site)

    def drop(self, slug: str) -> None:
        with self._lock:
            self._items.pop(slug, None)
