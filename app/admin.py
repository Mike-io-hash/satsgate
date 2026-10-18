from __future__ import annotations

import hmac
import time

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse

from . import config
from . import db_admin
from . import db_sites

# Operator routes stay callable when SATSGATE_ADMIN_TOKEN is set, but the
# public docs and OpenAPI document only the customer API in production.
router = APIRouter(include_in_schema=config.is_local_env())


def _require_admin(x_admin_token: str | None):
    """Return a JSONResponse if unauthorized, else None."""

    if not config.ADMIN_TOKEN:
        # Disabled by default.
        return JSONResponse(status_code=404, content={"ok": False, "error": "not_found"})

    if not x_admin_token or not hmac.compare_digest(x_admin_token, config.ADMIN_TOKEN):
        return JSONResponse(status_code=401, content={"ok": False, "error": "unauthorized"})

    return None


@router.get("/v1/admin/overview")
def v1_admin_overview(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    since_hours: int = 24,
):
    """Operator-only overview.

    Protected by `SATSGATE_ADMIN_TOKEN` + `X-Admin-Token`.
    """

    err = _require_admin(x_admin_token)
    if err:
        return err

    since_hours = max(1, min(int(since_hours), 24 * 30))
    since_ts = int(time.time()) - (since_hours * 3600)

    overview = db_admin.operator_overview(config.DB_PATH, since_ts=since_ts)

    return {
        "ok": True,
        "window_hours": since_hours,
        "overview": overview,
    }


@router.get("/v1/admin/sites")
def v1_admin_sites(
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
    status: str | None = None,
    limit: int = 50,
):
    """Operator list. Includes the owner id and origin. Does not include the HMAC secret."""
    err = _require_admin(x_admin_token)
    if err:
        return err
    try:
        sites = db_sites.admin_list_sites(config.DB_PATH, status=status, limit=int(limit))
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"ok": False, "error": str(exc)})
    return {"ok": True, "sites": sites}


@router.post("/v1/admin/sites/{slug}/approve")
def v1_admin_sites_approve(
    slug: str,
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
):
    err = _require_admin(x_admin_token)
    if err:
        return err
    site = db_sites.admin_set_status(config.DB_PATH, slug=slug, status="approved")
    if site is None:
        return JSONResponse(status_code=404, content={"ok": False, "error": "site_not_found"})
    return {"ok": True, "site": site}


@router.post("/v1/admin/sites/{slug}/disable")
def v1_admin_sites_disable(
    slug: str,
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
):
    err = _require_admin(x_admin_token)
    if err:
        return err
    site = db_sites.admin_set_status(config.DB_PATH, slug=slug, status="disabled")
    if site is None:
        return JSONResponse(status_code=404, content={"ok": False, "error": "site_not_found"})
    return {"ok": True, "site": site}
