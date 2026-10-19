"""Sites and routes for the hosted proxy beta.

Registration checks the origin once. A name can be pointed at a private
address later (DNS rebinding). The gate resolves again on every forward and
connects to the public address from that lookup.
"""

from __future__ import annotations

import ipaddress
import re
import secrets
import time
from urllib.parse import urlsplit, urlunsplit

from . import config
from .db import _connect
from .site_secret import (
    SiteSecretError,
    decrypt_origin_secret,
    encrypt_origin_secret,
    fingerprint_origin_secret,
)
from .ssrf import SSRFError, guard_url

_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$")
_RESERVED_SLUGS = frozenset(
    {
        "about",
        "account",
        "admin",
        "api",
        "app",
        "approve",
        "assets",
        "auth",
        "beta",
        "billing",
        "blog",
        "callback",
        "callbacks",
        "cdn",
        "credits",
        "dashboard",
        "debug",
        "dev",
        "disable",
        "disabled",
        "docs",
        "edit",
        "favicon",
        "files",
        "free",
        "gate",
        "graphql",
        "health",
        "healthz",
        "help",
        "home",
        "index",
        "internal",
        "invoice",
        "invoices",
        "keys",
        "live",
        "localhost",
        "login",
        "mail",
        "me",
        "media",
        "metrics",
        "mine",
        "mcp",
        "new",
        "ns1",
        "null",
        "openapi",
        "origin",
        "paid",
        "pay",
        "paywall",
        "pending",
        "privacy",
        "proxy",
        "public",
        "ready",
        "redoc",
        "registry",
        "robots",
        "root",
        "routes",
        "satsgate",
        "secret",
        "settings",
        "site",
        "sites",
        "static",
        "status",
        "support",
        "terms",
        "test",
        "topup",
        "undefined",
        "upload",
        "uploads",
        "v1",
        "webhook",
        "webhooks",
        "well-known",
        "www",
    }
)
_NAME_MAX = 80
_DESCRIPTION_MAX = 300
_PATH = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")
_STATUSES = frozenset({"pending", "approved", "disabled"})


class OriginError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def clean_slug(slug: str) -> str:
    text = (slug or "").strip()
    if not _SLUG.fullmatch(text):
        raise ValueError("invalid_slug")
    if text in _RESERVED_SLUGS:
        raise ValueError("slug_reserved")
    return text


def clean_display_name(name: str) -> str:
    text = (name or "").strip()
    if not text or len(text) > _NAME_MAX or _has_controls(text):
        raise ValueError("invalid_display_name")
    return text


def clean_description(description: str | None) -> str | None:
    if description is None:
        return None
    text = description.strip()
    if not text:
        return None
    if len(text) > _DESCRIPTION_MAX or _has_controls(text):
        raise ValueError("invalid_description")
    return text


def clean_path(path: str) -> str:
    text = (path or "").strip()
    if (
        not text
        or len(text) > 200
        or not text.startswith("/")
        or not _PATH.fullmatch(text)
        or ".." in text
        or "//" in text
        or "\\" in text
        or "?" in text
        or "#" in text
    ):
        raise ValueError("invalid_path")
    return text


def clean_price(price_sats: int) -> int:
    if isinstance(price_sats, bool) or not isinstance(price_sats, int):
        raise ValueError("invalid_price")
    if price_sats < 1 or price_sats > 10_000_000:
        raise ValueError("invalid_price")
    return price_sats


def clean_usd(amount: int) -> int:
    if isinstance(amount, bool) or not isinstance(amount, int):
        raise ValueError("invalid_price")
    if amount < 1 or amount > int(config.X402_MAX_USD_ATOMIC):
        raise ValueError("invalid_price")
    return amount


def clean_currency(value: str | None) -> str:
    text = (value or "sats").strip().lower()
    if text not in {"sats", "usd"}:
        raise ValueError("invalid_price")
    return text


def clean_usage(max_uses: int | None, access_seconds: int | None) -> tuple[int | None, int | None]:
    """Same bounds as a paywall challenge. Both omitted means the 0.6.0 open grant."""
    if max_uses is not None:
        if isinstance(max_uses, bool) or not isinstance(max_uses, int):
            raise ValueError("invalid_usage")
        if max_uses < 1 or max_uses > config.MAX_PAYWALL_USES:
            raise ValueError("invalid_usage")
    if access_seconds is not None:
        if isinstance(access_seconds, bool) or not isinstance(access_seconds, int):
            raise ValueError("invalid_usage")
        if access_seconds < 1 or access_seconds > int(config.PAYWALL_ACCESS_CAP_SECONDS):
            raise ValueError("invalid_usage")
    return max_uses, access_seconds


def _has_controls(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def _ip_trick(host: str) -> bool:
    """Decimal, hex, and zero-padded forms that some resolvers treat as addresses."""
    if host.startswith(("0x", "0X")):
        return True
    if host.isdigit():
        return True
    parts = host.split(".")
    if 1 < len(parts) <= 4 and all(part.isdigit() for part in parts):
        if any(len(part) > 1 and part.startswith("0") for part in parts):
            return True
    return False


def validate_origin_url(url: str, *, resolver=None) -> str:
    """https origin with a public address. Query, fragment, and userinfo are rejected.

    DNS is resolved now. The gate resolves again on every forward.
    """
    raw = (url or "").strip()
    if not raw or _has_controls(raw) or any(ch in raw for ch in " \t"):
        raise OriginError("invalid_origin")
    parsed = urlsplit(raw)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise OriginError("invalid_origin")
    host = parsed.hostname
    if not host:
        raise OriginError("invalid_origin")
    try:
        host_idna = host.encode("idna").decode("ascii").lower().rstrip(".")
    except Exception as exc:  # noqa: BLE001
        raise OriginError("invalid_origin") from exc
    if _ip_trick(host_idna):
        raise OriginError("origin_rejected")
    try:
        literal = ipaddress.ip_address(host_idna)
    except ValueError:
        literal = None
    if literal is not None:
        from .ssrf import is_public_ip

        if not is_public_ip(host_idna):
            raise OriginError("origin_rejected")
    path = parsed.path or ""
    if ".." in path or "\\" in path or "//" in path:
        raise OriginError("invalid_origin")
    try:
        guarded = guard_url(raw, resolver=resolver)
    except SSRFError as exc:
        raise OriginError("origin_rejected") from exc
    port = parsed.port
    hostport = guarded.host if port in (None, 443) else f"{guarded.host}:{port}"
    kept_path = "" if path in {"", "/"} else path
    return urlunsplit(("https", hostport, kept_path, "", ""))


def gate_url(slug: str) -> str:
    return f"{config.GATE_PUBLIC_BASE}/{slug}/"


def _new_origin_secret() -> tuple[str, str, str]:
    key = config.site_secret_key()
    if key is None:
        raise ValueError("site_secret_key_unconfigured")
    secret = secrets.token_hex(32)
    try:
        blob = encrypt_origin_secret(secret, key)
    except SiteSecretError as exc:
        raise ValueError(exc.code) from exc
    return secret, blob, fingerprint_origin_secret(secret)


def get_site_by_slug(db_path: str, slug: str) -> dict | None:
    """Site row plus routes. Includes client_id. Does not include the origin secret."""
    try:
        slug = clean_slug(slug)
    except ValueError:
        return None
    with _connect(db_path) as conn:
        row = conn.execute("SELECT * FROM sites WHERE slug = ?", (slug,)).fetchone()
        if row is None:
            return None
        public = _site_owner(row, _routes_for(conn, int(row["id"])))
        public["client_id"] = int(row["client_id"])
    return public


def load_origin_secret(db_path: str, *, site_id: int) -> str:
    """Decrypt one site's origin secret. The internal gate route is the HTTP caller."""
    key = config.site_secret_key()
    if key is None:
        raise ValueError("site_secret_key_unconfigured")
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT origin_secret_ciphertext FROM sites WHERE id = ?",
            (int(site_id),),
        ).fetchone()
    if row is None:
        raise ValueError("site_not_found")
    try:
        return decrypt_origin_secret(row["origin_secret_ciphertext"], key)
    except SiteSecretError as exc:
        raise ValueError(exc.code) from exc


def _route_public(row) -> dict:
    currency = row["price_currency"] if row["price_currency"] else "sats"
    return {
        "id": int(row["id"]),
        "path": row["path_pattern"],
        "price_currency": currency,
        "price_sats": None if row["price_sats"] is None else int(row["price_sats"]),
        "price_usd_atomic": None if row["price_usd_atomic"] is None else int(row["price_usd_atomic"]),
        "max_uses": None if row["max_uses"] is None else int(row["max_uses"]),
        "access_seconds": None if row["access_seconds"] is None else int(row["access_seconds"]),
    }


def _site_owner(row, routes: list[dict]) -> dict:
    return {
        "id": int(row["id"]),
        "slug": row["slug"],
        "display_name": row["display_name"],
        "description": row["description"],
        "origin_url": row["origin_url"],
        "status": row["status"],
        "listed": bool(row["listed"]),
        "gate_url": gate_url(row["slug"]),
        "secret_fingerprint": row["secret_fingerprint"],
        "created_at": int(row["created_at"]),
        "updated_at": int(row["updated_at"]),
        "approved_at": None if row["approved_at"] is None else int(row["approved_at"]),
        "rail_lightning": bool(int(row["rail_lightning"])),
        "rail_x402": bool(int(row["rail_x402"])),
        "routes": routes,
    }


def _site_public(row, routes: list[dict]) -> dict:
    description = row["description"]
    item = {
        "name": row["display_name"],
        "slug": row["slug"],
        "url": gate_url(row["slug"]),
        "routes": [_public_route(route) for route in routes],
    }
    if isinstance(description, str) and description:
        item["description"] = description
    return item


def _public_route(route: dict) -> dict:
    """Directory row. A USD route does not advertise a sats figure. payTo stays off."""
    item = {
        "path": route["path"],
        "price_currency": route.get("price_currency") or "sats",
        "max_uses": route["max_uses"],
        "access_seconds": route["access_seconds"],
    }
    if item["price_currency"] == "usd":
        item["price_usd_atomic"] = route["price_usd_atomic"]
    else:
        item["price_sats"] = route["price_sats"]
    return item


def _routes_for(conn, site_id: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM site_routes WHERE site_id = ? ORDER BY id",
        (int(site_id),),
    ).fetchall()
    return [_route_public(row) for row in rows]


def _owned(conn, *, client_id: int, slug: str):
    return conn.execute(
        "SELECT * FROM sites WHERE slug = ? AND client_id = ?",
        (slug, int(client_id)),
    ).fetchone()


def create_site(
    db_path: str,
    *,
    client_id: int,
    slug: str,
    display_name: str,
    description: str | None,
    origin_url: str,
    listed: bool,
    max_sites: int,
    resolver=None,
) -> dict:
    slug = clean_slug(slug)
    display_name = clean_display_name(display_name)
    description = clean_description(description)
    origin = validate_origin_url(origin_url, resolver=resolver)
    secret, blob, fingerprint = _new_origin_secret()
    now = int(time.time())
    status = "approved" if config.SITES_AUTO_APPROVE else "pending"
    approved_at = now if status == "approved" else None
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        count = conn.execute("SELECT COUNT(*) FROM sites WHERE client_id = ?", (int(client_id),)).fetchone()
        if count and int(count[0]) >= int(max_sites):
            conn.execute("ROLLBACK")
            raise ValueError("site_limit")
        try:
            cur = conn.execute(
                """
                INSERT INTO sites(
                  client_id, slug, display_name, description, origin_url, status, listed,
                  origin_secret_ciphertext, secret_fingerprint, created_at, updated_at, approved_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    int(client_id),
                    slug,
                    display_name,
                    description,
                    origin,
                    status,
                    1 if listed else 0,
                    blob,
                    fingerprint,
                    now,
                    now,
                    approved_at,
                ),
            )
        except Exception as exc:  # noqa: BLE001
            conn.execute("ROLLBACK")
            if "UNIQUE" in str(exc).upper():
                raise ValueError("slug_taken") from None
            raise
        site_id = int(cur.lastrowid)
        row = conn.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
        public = _site_owner(row, [])
        conn.execute("COMMIT")
    if secret in blob:
        raise RuntimeError("origin secret was stored in the clear")
    public["origin_secret"] = secret
    return public


def list_sites_for_client(db_path: str, *, client_id: int) -> list[dict]:
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM sites WHERE client_id = ? ORDER BY slug",
            (int(client_id),),
        ).fetchall()
        return [_site_owner(row, _routes_for(conn, int(row["id"]))) for row in rows]


def get_site_for_client(db_path: str, *, client_id: int, slug: str) -> dict | None:
    try:
        slug = clean_slug(slug)
    except ValueError:
        return None
    with _connect(db_path) as conn:
        row = _owned(conn, client_id=client_id, slug=slug)
        if row is None:
            return None
        return _site_owner(row, _routes_for(conn, int(row["id"])))


def update_site(
    db_path: str,
    *,
    client_id: int,
    slug: str,
    display_name: str | None = None,
    description: str | None = None,
    origin_url: str | None = None,
    listed: bool | None = None,
    set_description: bool = False,
    rail_lightning: bool | None = None,
    rail_x402: bool | None = None,
    resolver=None,
) -> dict | None:
    slug = clean_slug(slug)
    if (
        display_name is None
        and not set_description
        and origin_url is None
        and listed is None
        and rail_lightning is None
        and rail_x402 is None
    ):
        raise ValueError("empty_update")
    new_name = None if display_name is None else clean_display_name(display_name)
    new_description = clean_description(description) if set_description else None
    new_origin = None if origin_url is None else validate_origin_url(origin_url, resolver=resolver)
    now = int(time.time())
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _owned(conn, client_id=client_id, slug=slug)
        if row is None:
            conn.execute("ROLLBACK")
            return None
        next_lightning = int(row["rail_lightning"]) if rail_lightning is None else (1 if rail_lightning else 0)
        next_x402 = int(row["rail_x402"]) if rail_x402 is None else (1 if rail_x402 else 0)
        if next_lightning == 0 and next_x402 == 0:
            conn.execute("ROLLBACK")
            raise ValueError("rails_required")
        if next_x402 == 1 and int(row["rail_x402"]) != 1:
            payee = conn.execute(
                "SELECT payee_evm_verified_at FROM clients WHERE id = ?",
                (int(client_id),),
            ).fetchone()
            if payee is None or payee["payee_evm_verified_at"] is None:
                conn.execute("ROLLBACK")
                raise ValueError("payee_evm_not_verified")
        conn.execute(
            """
            UPDATE sites
            SET display_name = ?, description = ?, origin_url = ?, listed = ?,
                rail_lightning = ?, rail_x402 = ?, updated_at = ?
            WHERE slug = ? AND client_id = ?
            """,
            (
                row["display_name"] if new_name is None else new_name,
                new_description if set_description else row["description"],
                row["origin_url"] if new_origin is None else new_origin,
                row["listed"] if listed is None else (1 if listed else 0),
                next_lightning,
                next_x402,
                now,
                slug,
                int(client_id),
            ),
        )
        updated = _owned(conn, client_id=client_id, slug=slug)
        public = _site_owner(updated, _routes_for(conn, int(updated["id"])))
        conn.execute("COMMIT")
    return public


def delete_site(db_path: str, *, client_id: int, slug: str) -> bool:
    try:
        slug = clean_slug(slug)
    except ValueError:
        return False
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _owned(conn, client_id=client_id, slug=slug)
        if row is None:
            conn.execute("ROLLBACK")
            return False
        conn.execute("DELETE FROM sites WHERE id = ?", (int(row["id"]),))
        conn.execute("COMMIT")
    return True


def rotate_site_secret(db_path: str, *, client_id: int, slug: str) -> dict | None:
    slug = clean_slug(slug)
    secret, blob, fingerprint = _new_origin_secret()
    now = int(time.time())
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = _owned(conn, client_id=client_id, slug=slug)
        if row is None:
            conn.execute("ROLLBACK")
            return None
        conn.execute(
            """
            UPDATE sites
            SET origin_secret_ciphertext = ?, secret_fingerprint = ?, updated_at = ?
            WHERE id = ?
            """,
            (blob, fingerprint, now, int(row["id"])),
        )
        updated = _owned(conn, client_id=client_id, slug=slug)
        public = _site_owner(updated, _routes_for(conn, int(updated["id"])))
        conn.execute("COMMIT")
    public["origin_secret"] = secret
    return public


def _priced(currency: str, price_sats: int | None, price_usd_atomic: int | None) -> tuple[str, int | None, int | None]:
    kind = clean_currency(currency)
    if kind == "sats":
        if price_usd_atomic is not None:
            raise ValueError("price_conflict")
        return kind, clean_price(price_sats), None
    if price_sats is not None:
        raise ValueError("price_conflict")
    return kind, None, clean_usd(price_usd_atomic)


def add_route(
    db_path: str,
    *,
    client_id: int,
    slug: str,
    path_pattern: str,
    price_sats: int | None = None,
    max_uses: int | None,
    access_seconds: int | None,
    max_routes: int,
    price_currency: str = "sats",
    price_usd_atomic: int | None = None,
) -> dict:
    slug = clean_slug(slug)
    path = clean_path(path_pattern)
    currency, price, usd = _priced(price_currency, price_sats, price_usd_atomic)
    uses, access = clean_usage(max_uses, access_seconds)
    now = int(time.time())
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        site = _owned(conn, client_id=client_id, slug=slug)
        if site is None:
            conn.execute("ROLLBACK")
            raise ValueError("site_not_found")
        count = conn.execute(
            "SELECT COUNT(*) FROM site_routes WHERE site_id = ?",
            (int(site["id"]),),
        ).fetchone()
        if count and int(count[0]) >= int(max_routes):
            conn.execute("ROLLBACK")
            raise ValueError("route_limit")
        try:
            cur = conn.execute(
                """
            INSERT INTO site_routes(
              site_id, path_pattern, price_sats, price_currency, price_usd_atomic,
              max_uses, access_seconds, created_at, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (int(site["id"]), path, price, currency, usd, uses, access, now, now),
            )
        except Exception as exc:  # noqa: BLE001
            conn.execute("ROLLBACK")
            if "UNIQUE" in str(exc).upper():
                raise ValueError("route_exists") from None
            raise
        route_id = int(cur.lastrowid)
        row = conn.execute("SELECT * FROM site_routes WHERE id = ?", (route_id,)).fetchone()
        conn.execute("UPDATE sites SET updated_at = ? WHERE id = ?", (now, int(site["id"])))
        public = _route_public(row)
        conn.execute("COMMIT")
    return public


def update_route(
    db_path: str,
    *,
    client_id: int,
    slug: str,
    route_id: int,
    path_pattern: str | None = None,
    price_sats: int | None = None,
    max_uses: int | None = None,
    access_seconds: int | None = None,
    set_max_uses: bool = False,
    set_access_seconds: bool = False,
    price_currency: str | None = None,
    price_usd_atomic: int | None = None,
    set_price: bool = False,
) -> dict | None:
    slug = clean_slug(slug)
    if (
        path_pattern is None
        and price_sats is None
        and not set_max_uses
        and not set_access_seconds
        and not set_price
    ):
        raise ValueError("empty_update")
    new_path = None if path_pattern is None else clean_path(path_pattern)
    new_price = None if price_sats is None else clean_price(price_sats)
    if set_max_uses:
        clean_usage(max_uses, None)
    if set_access_seconds:
        clean_usage(None, access_seconds)
    now = int(time.time())
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        site = _owned(conn, client_id=client_id, slug=slug)
        if site is None:
            conn.execute("ROLLBACK")
            return None
        row = conn.execute(
            "SELECT * FROM site_routes WHERE id = ? AND site_id = ?",
            (int(route_id), int(site["id"])),
        ).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            return None
        currency = row["price_currency"] or "sats"
        sats_price = row["price_sats"] if new_price is None else new_price
        usd_price = row["price_usd_atomic"]
        if set_price:
            currency, sats_price, usd_price = _priced(
                price_currency or currency,
                price_sats,
                price_usd_atomic,
            )
        elif new_price is not None and currency == "usd":
            conn.execute("ROLLBACK")
            raise ValueError("price_conflict")
        try:
            conn.execute(
                """
                UPDATE site_routes
                SET path_pattern = ?, price_sats = ?, price_currency = ?, price_usd_atomic = ?,
                    max_uses = ?, access_seconds = ?, updated_at = ?
                WHERE id = ? AND site_id = ?
                """,
                (
                    row["path_pattern"] if new_path is None else new_path,
                    sats_price,
                    currency,
                    usd_price,
                    max_uses if set_max_uses else row["max_uses"],
                    access_seconds if set_access_seconds else row["access_seconds"],
                    now,
                    int(route_id),
                    int(site["id"]),
                ),
            )
        except Exception as exc:  # noqa: BLE001
            conn.execute("ROLLBACK")
            if "UNIQUE" in str(exc).upper():
                raise ValueError("route_exists") from None
            raise
        updated = conn.execute(
            "SELECT * FROM site_routes WHERE id = ? AND site_id = ?",
            (int(route_id), int(site["id"])),
        ).fetchone()
        conn.execute("UPDATE sites SET updated_at = ? WHERE id = ?", (now, int(site["id"])))
        public = _route_public(updated)
        conn.execute("COMMIT")
    return public


def delete_route(db_path: str, *, client_id: int, slug: str, route_id: int) -> bool:
    try:
        slug = clean_slug(slug)
    except ValueError:
        return False
    now = int(time.time())
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        site = _owned(conn, client_id=client_id, slug=slug)
        if site is None:
            conn.execute("ROLLBACK")
            return False
        cur = conn.execute(
            "DELETE FROM site_routes WHERE id = ? AND site_id = ?",
            (int(route_id), int(site["id"])),
        )
        if cur.rowcount == 0:
            conn.execute("ROLLBACK")
            return False
        conn.execute("UPDATE sites SET updated_at = ? WHERE id = ?", (now, int(site["id"])))
        conn.execute("COMMIT")
    return True


def list_public_sites(db_path: str, *, limit: int, cursor: str | None) -> dict:
    if limit < 1 or limit > 100:
        raise ValueError("invalid_limit")
    if cursor is not None:
        try:
            cursor = clean_slug(cursor)
        except ValueError as exc:
            raise ValueError("invalid_cursor") from exc
    sql = """
        SELECT * FROM sites
        WHERE status = 'approved' AND listed = 1
    """
    params: list = []
    if cursor is not None:
        sql += " AND slug > ?"
        params.append(cursor)
    sql += " ORDER BY slug LIMIT ?"
    params.append(int(limit) + 1)
    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        page = rows[: int(limit)]
        sites = [_site_public(row, _routes_for(conn, int(row["id"]))) for row in page]
    next_cursor = page[-1]["slug"] if len(rows) > int(limit) and page else None
    return {"ok": True, "hosted_registry": True, "sites": sites, "next_cursor": next_cursor}


def admin_list_sites(db_path: str, *, status: str | None, limit: int) -> list[dict]:
    if status is not None and status not in _STATUSES:
        raise ValueError("invalid_status")
    if limit < 1 or limit > 100:
        raise ValueError("invalid_limit")
    sql = "SELECT * FROM sites"
    params: list = []
    if status is not None:
        sql += " WHERE status = ?"
        params.append(status)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        items = []
        for row in rows:
            item = _site_owner(row, _routes_for(conn, int(row["id"])))
            item["client_id"] = int(row["client_id"])
            items.append(item)
    return items


def admin_set_status(db_path: str, *, slug: str, status: str) -> dict | None:
    if status not in {"approved", "disabled"}:
        raise ValueError("invalid_status")
    try:
        slug = clean_slug(slug)
    except ValueError:
        return None
    now = int(time.time())
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM sites WHERE slug = ?", (slug,)).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            return None
        approved_at = row["approved_at"]
        if status == "approved" and approved_at is None:
            approved_at = now
        conn.execute(
            "UPDATE sites SET status = ?, approved_at = ?, updated_at = ? WHERE id = ?",
            (status, approved_at, now, int(row["id"])),
        )
        updated = conn.execute("SELECT * FROM sites WHERE id = ?", (int(row["id"]),)).fetchone()
        public = _site_owner(updated, _routes_for(conn, int(updated["id"])))
        public["client_id"] = int(updated["client_id"])
        conn.execute("COMMIT")
    return public
