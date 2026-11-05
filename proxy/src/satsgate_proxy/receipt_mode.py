"""Receipt mode. No sgr_ key and no call to Satsgate.

The origin still receives the existing HMAC signature. A 2xx commits one use.
"""

from __future__ import annotations

import sys
from pathlib import Path

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from satsgate_proxy.config import Settings
from satsgate_proxy.forward import call_upstream
from satsgate_proxy.match import match_request


def _sdk():
    try:
        from satsgate_sdk import receipts as sdk_receipts
    except ImportError:
        root = Path(__file__).resolve().parents[3] / "sdk" / "python" / "src"
        if root.is_dir() and str(root) not in sys.path:
            sys.path.insert(0, str(root))
        from satsgate_sdk import receipts as sdk_receipts
    return sdk_receipts


def open_store(path: str):
    sdk = _sdk()
    if path:
        return sdk.SqliteReceiptStore(path)
    return sdk.MemoryReceiptStore()


def _json(status: int, payload: dict, **headers: str) -> JSONResponse:
    return JSONResponse(payload, status_code=status, headers={"Cache-Control": "no-store", **headers})


async def handle_receipt(request: Request, settings: Settings, method: str, path: str) -> Response:
    sdk = _sdk()
    if path == "/.well-known/satsgate-check" or path.endswith("/.well-known/satsgate-check"):
        status, body = sdk.origin_check_response(
            request.headers.get("satsgate-check", ""),
            secret=settings.origin_secret,
            site=settings.receipt_site,
            previous_secrets=settings.previous_secrets,
        )
        return _json(status, body)
    found = match_request(settings.routes, settings.free_patterns, method, path)
    if found.kind == "not_found":
        return _json(404, {"ok": False, "error": "not_found"})
    if found.kind == "method":
        return JSONResponse(
            {"ok": False, "error": "method_not_allowed"},
            status_code=405,
            headers={"Allow": ", ".join(found.allow), "Cache-Control": "no-store"},
        )
    if found.kind == "free":
        from satsgate_proxy.forward import forward

        return await forward(request, settings, payment_hash=None, resource=None, paid_sats=None, use_spent=False)
    route = found.route
    token = request.headers.get("satsgate-receipt", "").strip()
    pay_at = f"{settings.receipt_gate_base.rstrip('/')}/{settings.receipt_site}{path}"
    if not token:
        return _json(402, {"error": "payment_required", "pay_at": pay_at}, **{"Link": f'<{pay_at}>; rel="satsgate-pay"'})
    try:
        receipt = sdk.verify_receipt(
            token,
            secret=settings.origin_secret,
            site=settings.receipt_site,
            path=path,
            previous_secrets=settings.previous_secrets,
        )
    except sdk.ReceiptError as exc:
        return _json(401, {"error": exc.code})
    store = request.app.state.receipt_store
    try:
        reservation = store.reserve(receipt.jti, receipt.uses, receipt.exp)
    except sdk.ReceiptError as exc:
        return _json(401, {"error": exc.code})
    amount = receipt.claims.get("amt") if isinstance(receipt.claims.get("amt"), dict) else {}
    paid_sats = amount.get("sats") if isinstance(amount.get("sats"), int) else None
    paid_usd = amount.get("usd_atomic") if isinstance(amount.get("usd_atomic"), int) else None
    ph = receipt.claims.get("ph")
    try:
        exchanged = await call_upstream(
            request,
            settings,
            payment_hash=ph if isinstance(ph, str) else receipt.jti,
            resource=route.resource,
            paid_sats=paid_sats,
            paid_usd_atomic=paid_usd,
        )
    except Exception:
        store.release(reservation)
        raise
    if exchanged.error or not (200 <= exchanged.status < 300):
        store.release(reservation)
        return exchanged.response(use_spent=False if exchanged.error else None)
    store.commit(reservation)
    return exchanged.response(use_spent=None)
