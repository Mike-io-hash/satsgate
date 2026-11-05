"""Prove the merchant controls origin_url and has the receipt checker installed.

One HTTPS GET, SSRF-guarded, no redirects, 5 seconds, 4 KiB.
"""

from __future__ import annotations

import json
import time
from urllib.parse import urlsplit, urlunsplit

from . import config, db_sites, receipts
from .ssrf import SSRFError, safe_get_response

_CHECK_BYTES = 4096


class OriginCheckError(Exception):
    def __init__(self, code: str, status: int = 400) -> None:
        super().__init__(code)
        self.code = code
        self.status = status


def check_url(origin_url: str) -> str:
    parts = urlsplit(origin_url)
    base = (parts.path or "").rstrip("/")
    return urlunsplit(("https", parts.netloc, f"{base}/.well-known/satsgate-check", "", ""))


def verify_origin(db_path: str, *, site: dict, resolver=None) -> dict:
    site_id = int(site["id"])
    now = int(time.time())
    if not db_sites.record_origin_attempt(db_path, site_id=site_id, now=now):
        raise OriginCheckError("rate_limited", 429)
    try:
        secret = db_sites.load_origin_secret(db_path, site_id=site_id)
    except ValueError as exc:
        code = str(exc)
        raise OriginCheckError(code, 503 if code == "site_secret_key_unconfigured" else 404) from exc
    jti = receipts.new_check_id()
    token = receipts.encode_token(
        {
            "aud": site["slug"],
            "exp": now + 60,
            "iat": now,
            "iss": config.GATE_PUBLIC_BASE,
            "jti": jti,
            "sub": "/.well-known/satsgate-check",
        },
        secret=secret,
        typ=receipts.TYP_CHECK,
    )
    try:
        status, body = safe_get_response(
            check_url(site["origin_url"]),
            headers={"Accept": "application/json", "Satsgate-Check": token},
            resolver=resolver,
            timeout=5.0,
            max_bytes=_CHECK_BYTES,
        )
    except SSRFError as exc:
        if exc.code in {"destination_rejected", "redirects_not_allowed"}:
            raise OriginCheckError("origin_rejected") from exc
        raise OriginCheckError("origin_unreachable") from exc
    if status != 200:
        raise OriginCheckError("origin_check_failed")
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise OriginCheckError("origin_check_failed") from exc
    proof = payload.get("proof") if isinstance(payload, dict) else None
    if not isinstance(payload, dict) or payload.get("ok") is not True or not receipts.proof_matches(secret, jti, proof):
        raise OriginCheckError("origin_check_failed")
    db_sites.mark_origin_verified(db_path, site_id=site_id, now=now)
    approved = db_sites.maybe_auto_approve(db_path, slug=site["slug"])
    if approved is not None:
        return approved
    fresh = db_sites.get_site_by_slug(db_path, site["slug"])
    if fresh is None:
        raise OriginCheckError("site_not_found", 404)
    fresh.pop("client_id", None)
    return fresh
