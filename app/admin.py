from __future__ import annotations

import hmac
import time

from fastapi import APIRouter, Header
from fastapi.responses import JSONResponse

from . import config
from . import db_admin

router = APIRouter()


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
