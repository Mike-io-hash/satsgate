"""Sell a credit pack for USDC paid to Satsgate's own treasury.

The buyer pays that address through the third-party facilitator. Core does
not sign, custody, or forward the USDC. Credits are closed-loop: the ledger
grows, and there is no USDC refund. One EIP-3009 nonce grants the pack once.
"""

from __future__ import annotations

import logging
import time

from eth_utils import to_checksum_address

from . import config, db_x402, rates, x402, x402_facilitator
from .plans import Plan

log = logging.getLogger("satsgate.x402")
_LOCK_SECONDS = 15


def enabled() -> bool:
    return bool(config.TREASURY_EVM_ADDRESS)


def timeout_seconds() -> int:
    """Same short window the gate uses for a route offer."""
    return x402.offer_timeout_seconds()


def _treasury() -> str:
    treasury = config.TREASURY_EVM_ADDRESS
    if not treasury:
        raise x402.X402Error("x402_topup_disabled", status=400)
    return treasury


def _offer_still_ours(offer: dict, treasury: str) -> None:
    requirements = offer.get("requirements") or {}
    if offer.get("pay_to") != treasury or requirements.get("payTo") != treasury:
        raise x402.X402Error("payto_mismatch")
    if requirements.get("network") != config.X402_NETWORK or offer.get("network") != config.X402_NETWORK:
        raise x402.X402Error("network_mismatch")
    asset = requirements.get("asset")
    try:
        asset = x402.checksum_address(asset)
    except x402.X402Error:
        raise x402.X402Error("asset_mismatch") from None
    if asset != to_checksum_address(config.X402_USDC):
        raise x402.X402Error("asset_mismatch")
    if requirements.get("scheme") != "exact":
        raise x402.X402Error("bad_signature")
    amount = str(int(offer["amount_usd_atomic"]))
    if requirements.get("amount") != amount:
        raise x402.X402Error("amount_mismatch")
    if not offer.get("grant_credits") or int(offer["grant_credits"]) < 1:
        raise x402.X402Error("bad_signature")


def issue(*, client_id: int, plan: Plan, resource_url: str) -> dict:
    """402 body plus the PAYMENT-REQUIRED header value. The amount is locked."""
    treasury = _treasury()
    now = int(time.time())
    rate = rates.quote_rate(now)
    if rate is None:
        raise x402.X402Error("rate_unavailable", status=503)
    atomic = rates.usd_atomic_for_pack(plan.price_sats, rate)
    if atomic is None:
        raise x402.X402Error("amount_unavailable", status=400)
    resource = f"v1/topup/{plan.id}"
    existing = db_x402.find_topup_offer(
        config.DB_PATH,
        client_id=client_id,
        resource=resource,
        pay_to=treasury,
        amount_usd_atomic=atomic,
        grant_credits=plan.credits,
        now=now,
    )
    window = timeout_seconds()
    if existing is None or not existing.get("requirements") or not existing.get("resource_url"):
        requirements = x402.accept_for(
            resource_url=resource_url,
            amount=atomic,
            pay_to=treasury,
            timeout_seconds=window,
        )
        existing = db_x402.create_offer(
            config.DB_PATH,
            client_id=client_id,
            resource=resource,
            resource_url=resource_url,
            price_currency="sats",
            amount_sats=plan.price_sats,
            amount_usd_atomic=atomic,
            pay_to=treasury,
            requirements=requirements,
            buyer_ip_hash=None,
            max_uses=None,
            access_seconds=None,
            rate_num=int(rate.rate_num),
            rate_den=int(rate.rate_den),
            rate_fetched_at=int(rate.fetched_at),
            grant_credits=plan.credits,
            enforce=False,
            now=now,
            expires_at=now + window,
        )
        reused = False
    else:
        reused = True
        resource_url = str(existing["resource_url"])
    _offer_still_ours(existing, treasury)
    view = {
        "ok": False,
        "error": "payment_required",
        "rail": "x402",
        "plan": plan.to_dict(),
        "offer_id": existing["id"],
        "expires_at": existing["expires_at"],
        "reused": reused,
        "credits": int(existing["grant_credits"]),
        "price_currency": "usd",
        "payment_required": x402.b64_json(
            x402.payment_required_document(resource_url=resource_url, accept=existing["requirements"])
        ),
        "x402": {
            "scheme": "exact",
            "network": config.X402_NETWORK,
            "asset": to_checksum_address(config.X402_USDC),
            "amount": str(int(existing["amount_usd_atomic"])),
            "payTo": treasury,
            "expires_at": existing["expires_at"],
        },
        "rate": {
            "rate_num": int(existing["rate_num"]),
            "rate_den": int(existing["rate_den"]),
            "fetched_at": existing["rate_fetched_at"],
        },
    }
    return view


def _bind(encoded: str, *, client_id: int, plan_id: str) -> tuple[dict, dict, dict]:
    payload = x402.decode_payment_signature(encoded)
    resource = f"v1/topup/{plan_id}"
    offers = db_x402.recent_offers(config.DB_PATH, client_id=client_id, resource=resource)
    if not offers:
        raise x402.X402Error("not_found", status=404)
    treasury = _treasury()
    first_error: x402.X402Error | None = None
    for offer in offers:
        if not offer.get("resource_url") or not offer.get("amount_usd_atomic"):
            continue
        offer["resource_url"] = str(offer["resource_url"])
        try:
            _offer_still_ours(offer, treasury)
            fields = x402.validate_payload(payload, offer=offer)
        except x402.X402Error as exc:
            if first_error is None:
                first_error = exc
            continue
        return payload, offer, fields
    if first_error is not None:
        raise first_error
    raise x402.X402Error("not_found", status=404)


def _reject(fields: dict, *, now: int, reason: str | None = None) -> None:
    db_x402.set_authorization_state(
        config.DB_PATH,
        network=fields["network"],
        asset=fields["asset"],
        payer=fields["payer"],
        nonce=fields["nonce"],
        state="rejected",
        now=now,
    )
    raise x402.X402Error("x402_rejected", reason=reason)


def _back_to_verified(fields: dict) -> None:
    db_x402.set_authorization_state(
        config.DB_PATH,
        network=fields["network"],
        asset=fields["asset"],
        payer=fields["payer"],
        nonce=fields["nonce"],
        state="verified",
        now=int(time.time()),
        expect=("settling",),
    )


def _row(fields: dict):
    return db_x402.authorization_row(
        config.DB_PATH,
        network=fields["network"],
        asset=fields["asset"],
        payer=fields["payer"],
        nonce=fields["nonce"],
    )


def _replay_if_granted(row) -> None:
    if row is not None and int(row["credit_charged"] or 0) == 1:
        raise x402.X402Error("x402_replay", status=409)


def settle(*, client_id: int, plan: Plan, encoded: str) -> dict:
    """Verify, settle, then grant. A failed settle adds no credits."""
    now = int(time.time())
    payload, offer, fields = _bind(encoded, client_id=client_id, plan_id=plan.id)
    state = db_x402.insert_pending(
        config.DB_PATH,
        network=fields["network"],
        asset=fields["asset"],
        payer=fields["payer"],
        nonce=fields["nonce"],
        offer_id=offer["id"],
        value=fields["value"],
        pay_to=fields["pay_to"],
        now=now,
    )
    if state == "rejected":
        raise x402.X402Error("x402_rejected")
    row = _row(fields)
    if row is not None and state != "inserted":
        if row["offer_id"] != offer["id"] or str(row["value_atomic"]) != fields["value"] or row["pay_to"] != fields["pay_to"]:
            raise x402.X402Error("x402_replay", status=409)
    _replay_if_granted(row)
    if state == "settled":
        raise x402.X402Error("x402_replay", status=409)
    if state == "pending":
        if row is not None and now - int(row["updated_at"]) < _LOCK_SECONDS:
            raise x402.X402Error("x402_in_progress", status=409)
    elif state not in {"inserted", "verified", "settling"}:
        raise x402.X402Error("x402_in_progress", status=409)

    if state in {"inserted", "pending"}:
        try:
            result = x402_facilitator.verify(payload, offer["requirements"])
        except x402_facilitator.FacilitatorError as exc:
            raise x402.X402Error(exc.code, status=502) from exc
        if not result.get("isValid"):
            reason = x402.public_reason(result.get("invalidReason"))
            log.warning("x402 topup verify rejected offer=%s reason=%s", offer["id"], reason or "")
            _reject(fields, now=now, reason=reason)
        try:
            payer = x402.checksum_address(result.get("payer"))
        except x402.X402Error:
            payer = ""
        if payer != fields["payer"]:
            log.warning("x402 topup verify rejected offer=%s reason=payer_mismatch", offer["id"])
            _reject(fields, now=now, reason="payer_mismatch")
        db_x402.set_authorization_state(
            config.DB_PATH,
            network=fields["network"],
            asset=fields["asset"],
            payer=fields["payer"],
            nonce=fields["nonce"],
            state="verified",
            now=now,
        )

    locked = db_x402.set_authorization_state(
        config.DB_PATH,
        network=fields["network"],
        asset=fields["asset"],
        payer=fields["payer"],
        nonce=fields["nonce"],
        state="settling",
        now=now,
        expect=("verified",),
    )
    if not locked:
        again = _row(fields)
        _replay_if_granted(again)
        if again is not None and again["state"] == "settling" and now - int(again["updated_at"]) < _LOCK_SECONDS:
            raise x402.X402Error("x402_in_progress", status=409)
        if again is None or again["state"] not in {"settling", "verified"}:
            raise x402.X402Error("x402_in_progress", status=409)
    try:
        settled = x402_facilitator.settle(payload, offer["requirements"])
    except x402_facilitator.FacilitatorError as exc:
        _back_to_verified(fields)
        raise x402.X402Error(exc.code, status=502) from exc
    if not settled.get("success"):
        _back_to_verified(fields)
        reason = x402.public_reason(settled.get("errorReason") or settled.get("invalidReason"))
        log.warning("x402 topup settle failed offer=%s reason=%s", offer["id"], reason or "")
        raise x402.X402Error("x402_rejected", reason=reason)
    tx = settled.get("transaction") or settled.get("tx")
    if not isinstance(tx, str) or not tx.startswith("0x") or len(tx) < 10:
        _back_to_verified(fields)
        log.warning("x402 topup settle failed offer=%s reason=bad_tx", offer["id"])
        raise x402.X402Error("x402_rejected")
    try:
        paid_by = x402.checksum_address(settled.get("payer") or fields["payer"])
    except x402.X402Error:
        paid_by = ""
    if paid_by != fields["payer"]:
        _back_to_verified(fields)
        log.warning("x402 topup settle failed offer=%s reason=payer_mismatch", offer["id"])
        raise x402.X402Error("x402_rejected", reason="payer_mismatch")
    granted = db_x402.grant_topup_credits(
        config.DB_PATH,
        network=fields["network"],
        asset=fields["asset"],
        payer=fields["payer"],
        nonce=fields["nonce"],
        tx_hash=tx,
        client_id=client_id,
        offer_id=offer["id"],
        plan_id=plan.id,
        credits=int(offer["grant_credits"]),
        sats=int(offer["amount_sats"] or plan.price_sats),
        amount_usd_atomic=int(offer["amount_usd_atomic"]),
        pay_to=fields["pay_to"],
        expires_at=int(offer["expires_at"]),
        now=now,
    )
    return {
        "ok": True,
        "rail": "x402",
        "plan": plan.to_dict(),
        "credits_added": granted["credits_added"],
        "credits": granted["credits"],
        "tx": granted["tx_hash"],
        "transaction": granted["tx_hash"],
        "network": config.X402_NETWORK,
        "amount_usd_atomic": int(offer["amount_usd_atomic"]),
        "payment_response": x402.payment_response_b64(tx=granted["tx_hash"], payer=fields["payer"]),
    }
