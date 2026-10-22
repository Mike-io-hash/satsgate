"""Verify, then the caller serves, then settle. Credits move only after settle."""

from __future__ import annotations

import logging
import time

from eth_utils import to_checksum_address

from . import config, db, db_x402, rates, x402, x402_facilitator

log = logging.getLogger("satsgate.x402")
_COST = 1
_LOCK_SECONDS = 15


def quote_plan(site: dict, route: dict) -> dict:
    """Which rails to offer, and the derived amount when a fresh median exists.

    A missing or stale rate drops the derived rail. The main currency stays.
    """
    lightning_on = bool(int(site.get("rail_lightning", 1)))
    x402_on = bool(int(site.get("rail_x402", 0)))
    currency = route.get("price_currency") or "sats"
    main_sats = int(route["price_sats"]) if currency == "sats" and route.get("price_sats") else None
    main_usd = int(route["price_usd_atomic"]) if currency == "usd" and route.get("price_usd_atomic") else None
    rate = rates.quote_rate()
    derived_usd = rates.usd_atomic_from_sats(main_sats, rate) if rate is not None and main_sats and x402_on else None
    derived_sats = rates.sats_from_usd_atomic(main_usd, rate) if rate is not None and main_usd and lightning_on else None
    lightning_sats = main_sats if lightning_on and main_sats else derived_sats if lightning_on else None
    x402_atomic = main_usd if x402_on and main_usd else derived_usd if x402_on else None
    used = rate if derived_usd is not None or derived_sats is not None else None
    return {
        "price_currency": currency,
        "main_sats": main_sats,
        "main_usd": main_usd,
        "lightning_sats": lightning_sats,
        "x402_atomic": x402_atomic,
        "rate": used,
        "x402_on": x402_on,
    }


def _rate_view(offer: dict) -> dict | None:
    if offer.get("rate_num") is None or offer.get("rate_den") is None:
        return None
    return {
        "rate_num": int(offer["rate_num"]),
        "rate_den": int(offer["rate_den"]),
        "fetched_at": offer.get("rate_fetched_at"),
    }


def x402_view(offer: dict, *, resource_url: str, reused: bool, resource: str) -> dict:
    offer["resource_url"] = resource_url
    amount = str(int(offer["amount_usd_atomic"]))
    document = x402.payment_required_document(resource_url=resource_url, accept=offer["requirements"])
    body = {
        "ok": True,
        "rail": "x402",
        "resource": resource,
        "offer_id": offer["id"],
        "expires_at": offer["expires_at"],
        "reused": reused,
        "payment_required": x402.b64_json(document),
        "price_currency": offer.get("price_currency"),
        "x402": {
            "scheme": "exact",
            "network": offer.get("network") or config.X402_NETWORK,
            "asset": offer.get("asset") or to_checksum_address(config.X402_USDC),
            "amount": amount,
            "payTo": offer["pay_to"],
            "expires_at": offer["expires_at"],
        },
    }
    rate = _rate_view(offer)
    if rate is not None:
        body["rate"] = rate
    if offer.get("amount_sats") is not None:
        body["amount_sats"] = int(offer["amount_sats"])
    return body


def _store_kwargs(plan: dict, *, pay_to: str | None, requirements: dict | None) -> dict:
    currency = plan["price_currency"]
    if currency == "sats":
        amount_sats = plan["main_sats"]
        amount_usd = plan["x402_atomic"]
    else:
        amount_usd = plan["main_usd"]
        amount_sats = plan["lightning_sats"]
    rate = plan.get("rate")
    return {
        "price_currency": currency,
        "amount_sats": amount_sats,
        "amount_usd_atomic": amount_usd,
        "pay_to": pay_to,
        "requirements": requirements,
        "rate_num": None if rate is None else int(rate.rate_num),
        "rate_den": None if rate is None else int(rate.rate_den),
        "rate_fetched_at": None if rate is None else int(rate.fetched_at),
    }


def issue_offer(
    *,
    client_id: int,
    slug: str,
    path: str,
    resource: str,
    pay_to: str,
    plan: dict,
    max_uses: int | None,
    access_seconds: int | None,
    buyer_ip_hash: str | None,
) -> dict:
    now = int(time.time())
    url = x402.resource_url(slug, path)
    amount = int(plan["x402_atomic"])
    existing = db_x402.find_reusable_offer(
        config.DB_PATH,
        client_id=client_id,
        resource=resource,
        price_currency=plan["price_currency"],
        main_sats=plan["main_sats"],
        main_usd=plan["main_usd"],
        pay_to=pay_to,
        buyer_ip_hash=buyer_ip_hash,
        max_uses=max_uses,
        access_seconds=access_seconds,
        now=now,
    )
    if existing is None or not existing.get("requirements"):
        window = x402.offer_timeout_seconds()
        requirements = x402.accept_for(
            resource_url=url,
            amount=amount,
            pay_to=pay_to,
            timeout_seconds=window,
        )
        try:
            db.preview_challenge_capacity(
                config.DB_PATH,
                **db_x402._limits(client_id=client_id, api_key_id=None, buyer_ip_hash=buyer_ip_hash, now=now),
            )
        except db.ChallengeLimit:
            raise
        existing = db_x402.create_offer(
            config.DB_PATH,
            client_id=client_id,
            resource=resource,
            resource_url=url,
            buyer_ip_hash=buyer_ip_hash,
            max_uses=max_uses,
            access_seconds=access_seconds,
            expires_at=now + window,
            now=now,
            **_store_kwargs(plan, pay_to=pay_to, requirements=requirements),
        )
        reused = False
    else:
        reused = True
    return x402_view(existing, resource_url=url, reused=reused, resource=resource)


def _bind(encoded: str, *, client_id: int, resource: str, resource_url: str) -> tuple[dict, dict, dict]:
    payload = x402.decode_payment_signature(encoded)
    offers = db_x402.recent_offers(config.DB_PATH, client_id=client_id, resource=resource)
    if not offers:
        raise x402.X402Error("not_found", status=404)
    first_error: x402.X402Error | None = None
    for offer in offers:
        if not offer.get("amount_usd_atomic") or not offer.get("pay_to") or not offer.get("requirements"):
            continue
        offer["resource_url"] = resource_url
        try:
            fields = x402.validate_payload(payload, offer=offer)
        except x402.X402Error as exc:
            if first_error is None:
                first_error = exc
            continue
        return payload, offer, fields
    if first_error is not None:
        raise first_error
    raise x402.X402Error("not_found", status=404)


def _require_credit(client_id: int) -> int:
    credits = db_x402.client_credits(config.DB_PATH, client_id)
    if credits < _COST:
        raise ValueError("insufficient balance")
    return credits


def verify_payment(*, client_id: int, slug: str, path: str, resource: str, encoded: str) -> dict:
    now = int(time.time())
    payload, offer, fields = _bind(encoded, client_id=client_id, resource=resource, resource_url=x402.resource_url(slug, path))
    _require_credit(client_id)
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
    if state == "settled":
        raise x402.X402Error("x402_replay")
    if state == "verified":
        return _serve(offer, fields["payer"], nonce=fields["nonce"])
    if state == "pending":
        row = db_x402.authorization_row(
            config.DB_PATH,
            network=fields["network"],
            asset=fields["asset"],
            payer=fields["payer"],
            nonce=fields["nonce"],
        )
        if row is not None and now - int(row["updated_at"]) < _LOCK_SECONDS:
            raise x402.X402Error("x402_in_progress", status=409)
    elif state not in {"inserted", "settling"}:
        raise x402.X402Error("x402_in_progress", status=409)

    try:
        result = x402_facilitator.verify(payload, offer["requirements"])
    except x402_facilitator.FacilitatorError as exc:
        raise x402.X402Error(exc.code, status=502) from exc
    if not result.get("isValid"):
        db_x402.set_authorization_state(
            config.DB_PATH,
            network=fields["network"],
            asset=fields["asset"],
            payer=fields["payer"],
            nonce=fields["nonce"],
            state="rejected",
            now=now,
        )
        reason = x402.public_reason(result.get("invalidReason"))
        log.warning("x402 verify rejected offer=%s reason=%s", offer["id"], reason or "")
        raise x402.X402Error("x402_rejected", reason=reason)
    try:
        payer = x402.checksum_address(result.get("payer"))
    except x402.X402Error:
        payer = ""
    if payer != fields["payer"]:
        db_x402.set_authorization_state(
            config.DB_PATH,
            network=fields["network"],
            asset=fields["asset"],
            payer=fields["payer"],
            nonce=fields["nonce"],
            state="rejected",
            now=now,
        )
        raise x402.X402Error("x402_rejected", reason="payer_mismatch")
    db_x402.set_authorization_state(
        config.DB_PATH,
        network=fields["network"],
        asset=fields["asset"],
        payer=fields["payer"],
        nonce=fields["nonce"],
        state="verified",
        now=now,
    )
    return _serve(offer, payer, nonce=fields["nonce"])


def _serve(offer: dict, payer: str, *, nonce: str) -> dict:
    """What the gate needs to call the origin. The quote was locked on the offer."""
    return {
        "ok": True,
        "serve": True,
        "offer_id": offer["id"],
        "payer": payer,
        "expires_at": offer["expires_at"],
        "amount_usd_atomic": int(offer["amount_usd_atomic"]),
        "nonce": nonce,
    }


def settle_payment(*, client_id: int, slug: str, path: str, resource: str, encoded: str) -> dict:
    """Called only after the origin returned 2xx. A failed settle does not debit."""
    now = int(time.time())
    payload, offer, fields = _bind(encoded, client_id=client_id, resource=resource, resource_url=x402.resource_url(slug, path))
    row = db_x402.authorization_row(
        config.DB_PATH,
        network=fields["network"],
        asset=fields["asset"],
        payer=fields["payer"],
        nonce=fields["nonce"],
    )
    if row is None:
        raise x402.X402Error("bad_signature")
    if row["offer_id"] != offer["id"]:
        bound = db_x402.get_offer(config.DB_PATH, row["offer_id"])
        if bound is None:
            raise x402.X402Error("bad_signature")
        bound["resource_url"] = x402.resource_url(slug, path)
        fields = x402.validate_payload(payload, offer=bound)
        offer = bound
    if int(row["credit_charged"] or 0) == 1:
        return _replay(row, offer, fields["payer"], client_id)
    if row["state"] == "rejected":
        raise x402.X402Error("x402_rejected")
    if row["state"] not in {"verified", "settling", "settled"}:
        raise x402.X402Error("x402_in_progress", status=409)
    _require_credit(client_id)
    if row["state"] == "settled" and row["tx_hash"]:
        charged = db_x402.mark_settled_and_charge(
            config.DB_PATH,
            network=fields["network"],
            asset=fields["asset"],
            payer=fields["payer"],
            nonce=fields["nonce"],
            tx_hash=row["tx_hash"],
            client_id=client_id,
            resource=resource,
            access_seconds=offer["access_seconds"],
            max_uses=offer["max_uses"],
            cost=_COST,
            now=now,
        )
        return _settled_body(charged, fields["payer"])
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
        again = db_x402.authorization_row(
            config.DB_PATH,
            network=fields["network"],
            asset=fields["asset"],
            payer=fields["payer"],
            nonce=fields["nonce"],
        )
        if again is not None and int(again["credit_charged"] or 0) == 1:
            return _replay(again, offer, fields["payer"], client_id)
        if again is not None and again["state"] == "settling" and now - int(again["updated_at"]) < _LOCK_SECONDS:
            raise x402.X402Error("x402_in_progress", status=409)
    try:
        result = x402_facilitator.settle(payload, offer["requirements"])
    except x402_facilitator.FacilitatorError as exc:
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
        raise x402.X402Error(exc.code, status=502) from exc
    if not result.get("success"):
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
        reason = x402.public_reason(result.get("errorReason") or result.get("invalidReason"))
        log.warning("x402 settle failed offer=%s status=200 reason=%s", offer["id"], reason or "")
        raise x402.X402Error("x402_rejected", reason=reason)
    tx = result.get("transaction") or result.get("tx")
    if not isinstance(tx, str) or not tx.startswith("0x") or len(tx) < 10:
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
        log.warning("x402 settle failed offer=%s status=200 reason=bad_tx", offer["id"])
        raise x402.X402Error("x402_rejected")
    try:
        paid_by = x402.checksum_address(result.get("payer") or fields["payer"])
    except x402.X402Error:
        paid_by = ""
    if paid_by != fields["payer"]:
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
        log.warning("x402 settle failed offer=%s status=200 reason=payer_mismatch", offer["id"])
        raise x402.X402Error("x402_rejected", reason="payer_mismatch")
    charged = db_x402.mark_settled_and_charge(
        config.DB_PATH,
        network=fields["network"],
        asset=fields["asset"],
        payer=fields["payer"],
        nonce=fields["nonce"],
        tx_hash=tx,
        client_id=client_id,
        resource=resource,
        access_seconds=offer["access_seconds"],
        max_uses=offer["max_uses"],
        cost=_COST,
        now=now,
    )
    return _settled_body(charged, fields["payer"])


def _replay(row, offer: dict, payer: str, client_id: int) -> dict:
    tx = row["tx_hash"] or ""
    credits = db_x402.client_credits(config.DB_PATH, client_id)
    return {
        "ok": True,
        "serve": False,
        "charged": 0,
        "credits": credits,
        "replay": True,
        "tx": tx,
        "payment_response": x402.payment_response_b64(tx=tx, payer=payer),
        "offer_id": offer["id"],
    }


def _settled_body(charged: dict, payer: str) -> dict:
    return {
        "ok": True,
        "serve": False,
        "charged": charged["charged"],
        "credits": charged["credits"],
        "replay": False,
        "tx": charged["tx_hash"],
        "payment_response": x402.payment_response_b64(tx=charged["tx_hash"], payer=payer),
    }
