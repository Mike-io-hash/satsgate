"""Discover a 402, pay it as a human or with NWC, and reuse a token while it lasts."""

from __future__ import annotations

import base64
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit

import httpx

from satsgate_mcp.budget import refusal
from satsgate_mcp.challenge import Challenge, ChallengeError, parse_challenge
from satsgate_mcp.config import Settings
from satsgate_mcp.nwc import NwcError, NwcWallet
from satsgate_mcp.qr import invoice_qr
from satsgate_mcp.redact import scrub
from satsgate_mcp.registry import RegistryError, load_registry
from satsgate_mcp.store import Store
from satsgate_mcp.urls import UrlError, validate_url
from satsgate_mcp.x402 import ParsedX402, for_agent, payment_response_fields

log = logging.getLogger("satsgate_mcp")

_METHODS = frozenset({"GET", "HEAD", "POST"})
_QUOTE_REUSE_SECONDS = 60
_USD_DAY = 24 * 60 * 60
_SIGNATURE_MAX = 8192
_REQUOTE = frozenset({"token_used_up", "token_expired"})
_PREIMAGE = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_X402_RETRY_NEW = frozenset({"bad_signature", "expired", "x402_replay"})
_X402_ERRORS = {
    "x402_rejected": (
        "The gate returned x402_rejected. A failed verify needs a new PAYMENT-SIGNATURE. "
        "A failed settle can be retried with this same header. The gate does not ask for a new nonce "
        "while that payment is still pending. Satsgate did not move the USDC."
    ),
    "x402_replay": "This signature was already settled. Sending it again will not fetch the resource.",
    "x402_in_progress": "Settlement is still in progress. Retry the same PAYMENT-SIGNATURE after a short wait.",
    "expired": "The offer expired. Fetch a new 402 and pay the amount that one states.",
    "bad_signature": "The gate rejected the PAYMENT-SIGNATURE. It was not logged. Fetch a new 402 if the offer changed.",
    "one_rail_only": (
        "The gate saw both an L402 Authorization and PAYMENT-SIGNATURE. "
        "This call sends only one. Retry the same PAYMENT-SIGNATURE without an L402 header."
    ),
    "paywall_unavailable": (
        "The gate could not finish verification or settlement. Nothing was settled and no merchant credit was taken. "
        "You can retry the same PAYMENT-SIGNATURE."
    ),
    "payment_required": (
        "The server still wants payment. The signature was not accepted as payment for this 402. "
        "Compare it with the requirements. Retrying the same header is safe while the offer is unchanged."
    ),
}


class BuyerError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class Presentation:
    payload: dict
    qr_png: bytes | None = None


class Buyer:
    def __init__(
        self,
        settings: Settings,
        *,
        store: Store,
        wallet: NwcWallet | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        now: Callable[[], int] | None = None,
    ) -> None:
        self.settings = settings
        self.store = store
        self.wallet = wallet if wallet is not None else NwcWallet(settings.nwc_uri, timeout=settings.timeout)
        self._transport = transport
        self._now = now or _unix

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=self._transport,
            timeout=httpx.Timeout(self.settings.timeout),
            follow_redirects=False,
            trust_env=False,
        )

    def _secrets(self, *extra: str) -> tuple[str, ...]:
        return tuple(item for item in (self.settings.nwc_uri, self.settings.api_key, *extra) if item)

    def _scrub(self, text: str, *extra: str) -> str:
        return scrub(text, self._secrets(*extra))

    async def discover(self, url: str, method: str = "GET") -> dict:
        challenge, response = await self._fetch_challenge(url, method, body=None, reuse=False)
        if challenge is None:
            return response
        return self._annotate(challenge)

    async def quote(self, url: str, method: str = "GET") -> dict:
        found = await self.discover(url, method)
        if found.get("payment_required"):
            found["summary"] = found.get("summary") or ""
        return found

    async def pay_and_fetch(
        self,
        url: str,
        mode: str = "human",
        method: str = "GET",
        body: str | None = None,
        payment_signature: str | None = None,
    ) -> Presentation:
        way = mode.strip().lower()
        if way not in {"human", "nwc"}:
            raise BuyerError("invalid_mode", "mode must be human or nwc.")
        if payment_signature is not None and payment_signature != "":
            return await self._pay_with_signature(url, method, body, payment_signature)
        payload = None if body is None else body.encode("utf-8")
        if payload is not None and len(payload) > self.settings.max_body_bytes:
            raise BuyerError("request_too_large", "The request body is above SATSGATE_MCP_MAX_BODY_BYTES.")
        method = _method(method)
        target = validate_url(url, self.settings.allowlist)
        key = _cache_key(method, target)

        cached = self._usable_token(key)
        if cached is not None:
            presented = await self._fetch_with_cached(cached, payload, allow_autopay=(way == "nwc"))
            return presented

        challenge = self._fresh_quote(key, payload)
        if challenge is None:
            challenge, free = await self._fetch_challenge(target, method, payload, reuse=False)
            if challenge is None:
                return Presentation(free)

        if not challenge.offers_lightning:
            return self._x402_offer(self._annotate(challenge), mode=way)
        if way == "human":
            return self._human_offer(challenge)
        return await self._pay_with_nwc(challenge, allow_autopay=False)

    async def check_payment(self, payment_hash: str) -> Presentation:
        if not _HEX64.fullmatch(payment_hash or ""):
            raise BuyerError("invalid_payment_hash", "payment_hash must be 64 hex characters.")
        row = self.store.quote_by_hash(payment_hash.lower())
        if row is None:
            token = self.store.token_by_hash(payment_hash.lower())
            if token is not None and self._token_usable(token):
                return await self._fetch_with_cached(token, None, allow_autopay=False)
            raise BuyerError(
                "unknown_payment",
                "No stored invoice uses that payment_hash. Call discover or pay_and_fetch first.",
            )
        challenge = _challenge_from_quote(row)
        if self.settings.api_key and challenge.resource:
            state = await self._core_status(challenge)
            if state["state"] == "pending":
                return Presentation(_pending(challenge, state.get("retry_after")))
            if state["state"] == "preimage_required":
                return Presentation(_preimage_required(challenge))
            if state["state"] == "error":
                return Presentation(state["payload"])
        fetched = await self._send(
            challenge.method,
            challenge.url,
            {"Authorization": f"L402 {challenge.macaroon}"},
            challenge.request_body,
        )
        return await self._interpret(fetched, challenge, preimage=None, allow_autopay=False)

    async def credits_balance(self) -> dict:
        if self.settings.api_key_rejected:
            return {
                "ok": False,
                "error": "invalid_api_key",
                "detail": "SATSGATE_MCP_API_KEY was ignored because it is not a restricted sgr_ key. No request was sent.",
            }
        if not self.settings.api_key:
            return {
                "ok": False,
                "error": "api_key_not_configured",
                "detail": "Set SATSGATE_MCP_API_KEY to a restricted sgr_ key to use the read-only merchant tools.",
            }
        response = await self._send(
            "GET",
            f"{self.settings.core_url}/v1/balance",
            {"X-Api-Key": self.settings.api_key, "Accept": "application/json"},
            None,
        )
        body = _json(response.body)
        if response.status == 403 and body.get("error") == "insufficient_scope":
            return {
                "ok": False,
                "error": "insufficient_scope",
                "detail": (
                    "This restricted key cannot read the credit balance. "
                    "Core allows GET /v1/balance for the account key only. No write was attempted."
                ),
            }
        if response.status == 200 and isinstance(body.get("credits"), int):
            return {"ok": True, "credits": body["credits"], "core_url": self.settings.core_url}
        return {
            "ok": False,
            "error": "balance_unavailable",
            "status": response.status,
            "detail": self._scrub(str(body.get("error") or "The balance request failed.")),
        }

    async def challenge_status(self, payment_hash: str, expected_resource: str | None = None) -> dict:
        if not self.settings.api_key:
            return {
                "ok": False,
                "error": "api_key_not_configured",
                "detail": "Set SATSGATE_MCP_API_KEY to a restricted sgr_ key. This tool only reads status.",
            }
        normalized = payment_hash.strip().lower()
        if not _HEX64.fullmatch(normalized):
            raise BuyerError("invalid_payment_hash", "payment_hash must be 64 hex characters.")
        row = self.store.quote_by_hash(normalized)
        token = self.store.token_by_hash(normalized)
        macaroon = ""
        resource = expected_resource.strip() if isinstance(expected_resource, str) else ""
        if row is not None:
            macaroon = str(row["macaroon"])
            if not resource and row["resource"]:
                resource = str(row["resource"])
        if token is not None:
            macaroon = str(token["macaroon"])
            if not resource and token["resource"]:
                resource = str(token["resource"])
        if not macaroon or not resource:
            raise BuyerError(
                "macaroon_not_stored",
                "Discover that URL first. This tool does not take a macaroon argument, and it does not write anything.",
            )
        query = urlencode({"expected_resource": resource, "cost_credits": "1", "consume": "false"})
        url = f"{self.settings.core_url}/v1/paywall/status/{normalized}?{query}"
        response = await self._send(
            "GET",
            url,
            {
                "X-Api-Key": self.settings.api_key,
                "Authorization": f"L402 {macaroon}",
                "Accept": "application/json",
            },
            None,
        )
        body = _json(response.body)
        public = {key: body.get(key) for key in ("ok", "status", "settled", "error", "uses_remaining", "access_until", "amount_sats")}
        public["http_status"] = response.status
        public["payment_hash"] = normalized
        public["consume"] = False
        if response.status == 401 and body.get("error") == "preimage_required":
            public["detail"] = (
                "The payee wallet did not advertise LUD-21 verify. "
                "A macaroon-only poll cannot see this payment. Use NWC mode, which returns a preimage."
            )
        return public

    async def list_sites(self) -> dict:
        async with self._client() as client:
            try:
                return await load_registry(self.settings, client)
            except (RegistryError, UrlError) as exc:
                code = getattr(exc, "code", "invalid_registry")
                return {"ok": False, "error": code, "detail": self._scrub(str(exc)), "sites": []}

    def _usable_token(self, key: str) -> dict | None:
        row = self.store.token_for(key)
        if row is None or not self._token_usable(row):
            return None
        return dict(row)

    def _token_usable(self, row) -> bool:
        now = self._now()
        access_until = row["access_until"]
        if access_until is not None and now > int(access_until):
            return False
        remaining = row["uses_remaining"]
        if remaining is not None and int(remaining) <= 0:
            return False
        return True

    def _fresh_quote(self, key: str, body: bytes | None) -> Challenge | None:
        row = self.store.quote_for(key)
        if row is None:
            return None
        age = self._now() - int(row["created_at"])
        if age < 0 or age > _QUOTE_REUSE_SECONDS:
            return None
        expires = row["invoice_expires_at"]
        if expires is not None and self._now() >= int(expires):
            return None
        stored = row["request_body"]
        if body != stored and not (body in (None, b"") and stored in (None, b"")):
            return None
        return _challenge_from_quote(row)

    async def _fetch_challenge(
        self,
        url: str,
        method: str,
        body: bytes | None,
        *,
        reuse: bool,
    ) -> tuple[Challenge | None, dict]:
        method = _method(method)
        target = validate_url(url, self.settings.allowlist)
        if reuse:
            cached = self._fresh_quote(_cache_key(method, target), body)
            if cached is not None:
                return cached, cached.public()
        response = await self._send(method, target, {"Accept": "application/json, */*"}, body)
        return self._challenge_or_content(response, method, target, body)

    def _challenge_or_content(
        self,
        response: "_Raw",
        method: str,
        url: str,
        body: bytes | None,
    ) -> tuple[Challenge | None, dict]:
        parsed = _json(response.body)
        if response.status == 402 and parsed.get("error") == "payment_pending":
            return None, _pending_unknown(parsed, response)
        if 300 <= response.status < 400:
            raise BuyerError("redirect_not_followed", "The server redirected. This client does not follow redirects.")
        if response.status == 402:
            try:
                challenge = parse_challenge(
                    method=method,
                    url=url,
                    status=response.status,
                    www_authenticate=response.headers.get("www-authenticate", ""),
                    body=response.body,
                    request_body=body,
                    payment_required=response.headers.get("payment-required", ""),
                )
            except ChallengeError as exc:
                raise BuyerError(exc.code, exc.message) from None
            self._remember_quote(challenge)
            return challenge, challenge.public()
        if 200 <= response.status < 300:
            return None, self._content(response, payment_hash=None, uses_remaining=None)
        raise BuyerError(
            "request_failed",
            self._scrub(f"The server returned HTTP {response.status}."),
        )

    def _remember_quote(self, challenge: Challenge) -> None:
        self.store.save_quote(
            {
                "payment_hash": challenge.payment_hash,
                "cache_key": _cache_key(challenge.method, challenge.url),
                "method": challenge.method,
                "url": challenge.url,
                "macaroon": challenge.macaroon,
                "invoice": challenge.invoice,
                "resource": challenge.resource,
                "amount_sats": challenge.amount_sats,
                "max_uses": challenge.max_uses,
                "access_seconds": challenge.access_seconds,
                "invoice_expires_at": challenge.invoice_expires_at,
                "reason": challenge.reason,
                "request_body": challenge.request_body,
                "created_at": self._now(),
                "x402_json": None if challenge.x402 is None else challenge.x402.to_json(),
            }
        )

    def _annotate(self, challenge: Challenge) -> dict:
        payload = challenge.public()
        if challenge.x402 is None:
            return payload
        spent = self.store.spent_usd_since(self._now() - _USD_DAY)
        view = for_agent(challenge.x402, self.settings, spent)
        payload["x402"] = view
        if not view.get("payable"):
            extra = view.get("cap_detail") or view.get("detail")
            if extra:
                payload["summary"] = f"{payload.get('summary', '')} {extra}".strip()
        elif view.get("detail"):
            payload["summary"] = f"{payload.get('summary', '')} {view['detail']}".strip()
        return payload

    def _x402_offer(self, payload: dict, *, mode: str) -> Presentation:
        payload["mode"] = mode
        payload["auto_paid"] = False
        x402 = payload.get("x402") if isinstance(payload.get("x402"), dict) else {}
        if x402.get("payable"):
            payload["action"] = "pay_x402_external"
            detail = str(x402["payment"]["detail"])
            if mode == "nwc":
                detail = "NWC pays a Lightning invoice. This 402 has no invoice. " + detail
            payload["detail"] = detail
            return Presentation(payload)
        payload["ok"] = False
        payload["error"] = x402.get("error") or "not_payable"
        payload["action"] = "refused"
        payload["signature_sent"] = False
        payload["detail"] = str(x402.get("cap_detail") or x402.get("detail") or "The USDC requirement was not paid.")
        return Presentation(payload)

    def _human_offer(self, challenge: Challenge) -> Presentation:
        payload = self._annotate(challenge)
        png, text = invoice_qr(challenge.invoice)
        payload["mode"] = "human"
        payload["action"] = "pay_invoice"
        payload["qr_text"] = text
        lightning = (
            "Pay this invoice from any Lightning wallet, then call check_payment with payment_hash. "
            "Do not send a preimage. check_payment polls settlement and retries the URL with the macaroon."
        )
        x402 = payload.get("x402") if isinstance(payload.get("x402"), dict) else None
        if x402 and x402.get("payable"):
            payload["detail"] = (
                lightning
                + " This 402 also offers USDC. Paying the invoice does not pay the USDC amount. "
                + str(x402["payment"]["detail"])
            )
        elif x402:
            extra = x402.get("cap_detail") or x402.get("detail") or ""
            payload["detail"] = f"{lightning} {extra}".strip()
        else:
            payload["detail"] = lightning
        return Presentation(payload, png)

    async def _pay_with_signature(
        self,
        url: str,
        method: str,
        body: str | None,
        payment_signature: str,
    ) -> Presentation:
        """Forward a PAYMENT-SIGNATURE the caller already has. This process does not sign."""
        signature = _clean_payment_signature(payment_signature)
        payload = None if body is None else body.encode("utf-8")
        if payload is not None and len(payload) > self.settings.max_body_bytes:
            raise BuyerError("request_too_large", "The request body is above SATSGATE_MCP_MAX_BODY_BYTES.")
        method = _method(method)
        target = validate_url(url, self.settings.allowlist)
        challenge, free = await self._fetch_challenge(target, method, payload, reuse=True)
        if challenge is None:
            free["signature_sent"] = False
            free["detail"] = (
                "The URL did not return a 402, so the PAYMENT-SIGNATURE was not sent. "
                "Nothing was signed by this server."
            )
            return Presentation(free)
        annotated = self._annotate(challenge)
        x402 = annotated.get("x402") if isinstance(annotated.get("x402"), dict) else None
        if not x402 or not x402.get("offered"):
            annotated["ok"] = False
            annotated["error"] = "x402_not_offered"
            annotated["action"] = "requote"
            annotated["signature_sent"] = False
            annotated["detail"] = "This 402 did not offer x402. The PAYMENT-SIGNATURE was not sent."
            return Presentation(annotated)
        if not x402.get("payable"):
            annotated["ok"] = False
            annotated["error"] = x402.get("error") or "not_payable"
            annotated["action"] = "refused"
            annotated["signature_sent"] = False
            annotated["detail"] = str(
                x402.get("cap_detail") or x402.get("detail") or "The USDC requirement was not paid."
            )
            return Presentation(annotated)
        fetched = await self._send(
            challenge.method,
            challenge.url,
            {"PAYMENT-SIGNATURE": signature},
            challenge.request_body if payload is None else payload,
        )
        return Presentation(self._interpret_signed(fetched, challenge, annotated, signature))

    def _interpret_signed(
        self,
        response: "_Raw",
        challenge: Challenge,
        annotated: dict,
        signature: str,
    ) -> dict:
        x402 = annotated.get("x402") if isinstance(annotated.get("x402"), dict) else {}
        charge = x402.get("charge_atomic") if isinstance(x402, dict) else None
        parsed = _json(response.body)
        if 200 <= response.status < 300:
            if isinstance(charge, int) and not isinstance(charge, bool) and charge > 0:
                host = urlsplit(challenge.url).hostname or ""
                self.store.record_usd_spend(
                    created_at=self._now(),
                    amount_usd_atomic=charge,
                    host=host,
                    resource=challenge.url,
                )
            content = self._content(response, None, None)
            if isinstance(content.get("body"), str):
                content["body"] = self._scrub(str(content["body"]), signature)
            content["paid_with"] = "x402"
            content["signature_sent"] = True
            content["retry_same_payment_signature"] = False
            display = _first_display(x402)
            if display:
                content["amount_atomic"] = display[0]
                content["amount_display"] = display[1]
            fields = payment_response_fields(response.headers.get("payment-response", ""))
            if fields:
                content["payment_response"] = fields
            content["detail"] = (
                "The server returned the resource. payment_response, when present, is the settlement report "
                "(success, transaction, network, payer). This server did not sign the payment and did not log the header."
            )
            return content
        if 300 <= response.status < 400:
            raise BuyerError("redirect_not_followed", "The server redirected. This client does not follow redirects.")
        error = parsed.get("error") if isinstance(parsed.get("error"), str) else ""
        explanation = _X402_ERRORS.get(error)
        if explanation is None:
            explanation = (
                f"The server returned HTTP {response.status}. "
                "If that status is the origin, the payment was not settled and no merchant credit was taken. "
                "Retry pay_and_fetch with the same PAYMENT-SIGNATURE while the offer is valid. "
                "This server did not sign a new payment."
            )
        body_text = ""
        if response.body and len(response.body) <= 2000:
            body_text = self._scrub(response.body.decode("utf-8", errors="replace"), signature)
        return {
            "ok": False,
            "payment_required": response.status == 402,
            "error": error or "request_failed",
            "http_status": response.status,
            "signature_sent": True,
            "retry_same_payment_signature": error not in _X402_RETRY_NEW,
            "url": challenge.url,
            "method": challenge.method,
            "x402": x402,
            "detail": explanation,
            "body": body_text or None,
        }

    async def _pay_with_nwc(self, challenge: Challenge, *, allow_autopay: bool) -> Presentation:
        if not self.settings.nwc_uri:
            raise BuyerError(
                "nwc_not_configured",
                "SATSGATE_MCP_NWC_URI is not set. Use mode human, or set the wallet URI in the environment. "
                "Do not paste it into the chat.",
            )
        blocked = refusal(self.settings, self.store, challenge.amount_sats, self._now())
        if blocked:
            payload = self._annotate(challenge)
            payload["ok"] = False
            payload["error"] = "over_budget"
            payload["action"] = "requote"
            payload["auto_paid"] = False
            payload["detail"] = blocked
            return Presentation(payload)
        if allow_autopay and not self.settings.auto_pay:
            payload = self._annotate(challenge)
            payload["action"] = "requote"
            payload["auto_paid"] = False
            payload["detail"] = (
                "The previous token is used up or expired. This is a new quote. "
                "Call pay_and_fetch again to pay it. Auto-pay is off (SATSGATE_MCP_AUTO_PAY)."
            )
            return Presentation(payload)
        try:
            preimage = await self.wallet.pay_invoice(challenge.invoice)
        except (NwcError, BuyerError) as exc:
            raise BuyerError("nwc_failed", self._scrub(str(exc), challenge.macaroon)) from None
        if not _PREIMAGE.fullmatch(preimage):
            raise BuyerError("nwc_failed", "NWC wallet returned a preimage that is not 64 hex characters.")
        host = urlsplit(challenge.url).hostname or ""
        self.store.record_spend(
            created_at=self._now(),
            amount_sats=challenge.amount_sats,
            payment_hash=challenge.payment_hash,
            host=host,
        )
        fetched = await self._send(
            challenge.method,
            challenge.url,
            {"Authorization": f"L402 {challenge.macaroon}:{preimage.lower()}"},
            challenge.request_body,
        )
        presented = await self._interpret(fetched, challenge, preimage=preimage.lower(), allow_autopay=False)
        if presented.payload.get("ok"):
            presented.payload["auto_paid"] = bool(allow_autopay and self.settings.auto_pay)
            presented.payload["paid_sats"] = challenge.amount_sats
        return presented

    async def _fetch_with_cached(self, row, body: bytes | None, *, allow_autopay: bool) -> Presentation:
        macaroon = str(row["macaroon"])
        preimage = row["preimage"]
        header = f"L402 {macaroon}"
        if isinstance(preimage, str) and preimage:
            header = f"{header}:{preimage}"
        request_body = body if body is not None else None
        fetched = await self._send(str(row["method"]), str(row["url"]), {"Authorization": header}, request_body)
        challenge = Challenge(
            method=str(row["method"]),
            url=str(row["url"]),
            macaroon=macaroon,
            invoice="",
            payment_hash=str(row["payment_hash"]),
            amount_sats=int(row["amount_sats"]),
            resource=row["resource"],
            max_uses=row["max_uses"],
            access_seconds=row["access_seconds"],
            invoice_expires_at=row["invoice_expires_at"],
            reason=None,
            request_body=request_body,
            uses_left=row["uses_remaining"],
            access_until=row["access_until"],
        )
        return await self._interpret(
            fetched,
            challenge,
            preimage=preimage if isinstance(preimage, str) else None,
            allow_autopay=allow_autopay,
        )

    async def _interpret(
        self,
        response: "_Raw",
        challenge: Challenge,
        *,
        preimage: str | None,
        allow_autopay: bool,
    ) -> Presentation:
        parsed = _json(response.body)
        if response.status == 402 and parsed.get("error") == "payment_pending":
            retry = _retry_after(response, parsed)
            return Presentation(_pending(challenge, retry))
        if 200 <= response.status < 300:
            remaining = self._remember_token(challenge, preimage)
            self.store.delete_quote(challenge.payment_hash)
            return Presentation(self._content(response, challenge.payment_hash, remaining))
        if 300 <= response.status < 400:
            raise BuyerError("redirect_not_followed", "The server redirected. This client does not follow redirects.")
        if response.status == 402:
            self.store.delete_token(_cache_key(challenge.method, challenge.url))
            try:
                fresh = parse_challenge(
                    method=challenge.method,
                    url=challenge.url,
                    status=402,
                    www_authenticate=response.headers.get("www-authenticate", ""),
                    body=response.body,
                    request_body=challenge.request_body,
                    payment_required=response.headers.get("payment-required", ""),
                )
            except ChallengeError as exc:
                raise BuyerError(exc.code, exc.message) from None
            self._remember_quote(fresh)
            reason = fresh.reason or ""
            if allow_autopay and reason in _REQUOTE and self.settings.auto_pay and fresh.offers_lightning:
                paid = await self._pay_with_nwc(fresh, allow_autopay=True)
                return paid
            payload = self._annotate(fresh)
            payload["action"] = "requote"
            payload["auto_paid"] = False
            if reason in _REQUOTE:
                payload["detail"] = (
                    f"The server rejected the token ({reason}). Here is a new quote. "
                    "It was not paid. Call pay_and_fetch again if you want to pay it."
                )
            else:
                payload["detail"] = "The server returned a new 402. It was not paid."
            if not fresh.offers_lightning:
                return Presentation(payload)
            png, text = invoice_qr(fresh.invoice)
            payload["qr_text"] = text
            return Presentation(payload, png)
        raise BuyerError("request_failed", self._scrub(f"The server returned HTTP {response.status}."))

    def _remember_token(self, challenge: Challenge, preimage: str | None) -> int | None:
        if challenge.uses_left is not None:
            remaining: int | None = int(challenge.uses_left) - 1
        elif challenge.max_uses is not None:
            remaining = challenge.max_uses - 1
        else:
            remaining = None
        if challenge.access_until is not None:
            access_until = int(challenge.access_until)
        elif challenge.access_seconds is not None:
            access_until = self._now() + int(challenge.access_seconds)
        else:
            access_until = None
        self.store.save_token(
            {
                "cache_key": _cache_key(challenge.method, challenge.url),
                "method": challenge.method,
                "url": challenge.url,
                "macaroon": challenge.macaroon,
                "preimage": preimage,
                "payment_hash": challenge.payment_hash,
                "resource": challenge.resource,
                "amount_sats": challenge.amount_sats,
                "max_uses": challenge.max_uses,
                "access_seconds": challenge.access_seconds,
                "uses_remaining": remaining,
                "access_until": access_until,
                "invoice_expires_at": challenge.invoice_expires_at,
                "updated_at": self._now(),
            }
        )
        return remaining

    async def _core_status(self, challenge: Challenge) -> dict:
        resource = challenge.resource or ""
        query = urlencode({"expected_resource": resource, "cost_credits": "1", "consume": "false"})
        url = f"{self.settings.core_url}/v1/paywall/status/{challenge.payment_hash}?{query}"
        response = await self._send(
            "GET",
            url,
            {
                "X-Api-Key": self.settings.api_key,
                "Authorization": f"L402 {challenge.macaroon}",
                "Accept": "application/json",
            },
            None,
        )
        body = _json(response.body)
        error = body.get("error") if isinstance(body.get("error"), str) else ""
        if response.status == 200 and body.get("settled") is True and body.get("status") != "pending":
            return {"state": "settled"}
        if response.status == 200 and (body.get("status") == "pending" or body.get("settled") is False):
            return {"state": "pending", "retry_after": _retry_after(response, body)}
        if error == "preimage_required":
            return {"state": "preimage_required"}
        if error in _REQUOTE:
            return {
                "state": "error",
                "payload": {
                    "ok": False,
                    "error": error,
                    "action": "requote",
                    "payment_hash": challenge.payment_hash,
                    "detail": f"Core rejected the token ({error}). Call discover for a new quote. Nothing was paid.",
                },
            }
        return {
            "state": "error",
            "payload": {
                "ok": False,
                "error": "status_unavailable",
                "http_status": response.status,
                "detail": self._scrub(error or f"Status returned HTTP {response.status}."),
            },
        }

    def _content(self, response: "_Raw", payment_hash: str | None, uses_remaining: int | None) -> dict:
        content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        view: dict[str, object] = {
            "ok": True,
            "payment_required": False,
            "status": response.status,
            "content_type": content_type,
            "truncated": response.truncated,
            "payment_hash": payment_hash,
            "uses_remaining": uses_remaining,
        }
        textual = not content_type or content_type.startswith("text/") or "json" in content_type or content_type.startswith("application/xml")
        if textual:
            view["body"] = response.body.decode("utf-8", errors="replace")
        elif len(response.body) <= 200_000:
            view["binary"] = True
            view["body_base64"] = base64.b64encode(response.body).decode("ascii")
        else:
            view["binary"] = True
            view["detail"] = "The response is binary and larger than the inline cap."
        return view

    async def _send(self, method: str, url: str, headers: dict[str, str], body: bytes | None) -> "_Raw":
        target = validate_url(url) if _is_core(url, self.settings.core_url) else validate_url(url, self.settings.allowlist)
        outbound = {"Accept": headers.get("Accept", "*/*"), "Accept-Encoding": "identity"}
        for name, value in headers.items():
            if name.lower() in {"authorization", "x-api-key", "content-type", "accept", "payment-signature"}:
                outbound[name] = value
        if body:
            outbound.setdefault("Content-Type", "application/json")
        async with self._client() as client:
            request = client.build_request(method, target, headers=outbound, content=body)
            request.extensions["timeout"] = httpx.Timeout(self.settings.timeout).as_dict()
            try:
                response = await client.send(request, stream=True, follow_redirects=False)
            except httpx.TimeoutException as exc:
                raise BuyerError("timeout", "The request timed out.") from exc
            except httpx.HTTPError as exc:
                raise BuyerError("connection_failed", self._scrub(type(exc).__name__)) from None
            chunks = bytearray()
            truncated = False
            async for chunk in response.aiter_bytes():
                if len(chunks) + len(chunk) > self.settings.max_body_bytes:
                    room = self.settings.max_body_bytes - len(chunks)
                    if room > 0:
                        chunks.extend(chunk[:room])
                    truncated = True
                    break
                chunks.extend(chunk)
            await response.aclose()
        host = urlsplit(target).hostname or ""
        path = urlsplit(target).path
        log.info("request %s %s%s -> %s", method, host, path, response.status_code)
        lowered = {key.lower(): value for key, value in response.headers.items()}
        return _Raw(response.status_code, lowered, bytes(chunks), truncated)


@dataclass
class _Raw:
    status: int
    headers: dict[str, str]
    body: bytes
    truncated: bool


def _clean_payment_signature(value: str) -> str:
    if not value or any(char.isspace() for char in value) or any(char in value for char in "\r\n\x00"):
        raise BuyerError(
            "invalid_payment_signature",
            "PAYMENT-SIGNATURE must be a single line without spaces. It was not sent.",
        )
    if len(value.encode("utf-8")) > _SIGNATURE_MAX:
        raise BuyerError(
            "invalid_payment_signature",
            "PAYMENT-SIGNATURE is longer than 8192 bytes. It was not sent.",
        )
    return value


def _first_display(x402: dict) -> tuple[str, str] | None:
    accepts = x402.get("accepts")
    if not isinstance(accepts, list):
        return None
    for item in accepts:
        if not isinstance(item, dict):
            continue
        atomic = item.get("amount_atomic")
        shown = item.get("amount_display")
        if isinstance(atomic, str) and isinstance(shown, str):
            return atomic, shown
    return None


def _unix() -> int:
    import time

    return int(time.time())


def _method(method: str) -> str:
    upper = method.strip().upper()
    if upper not in _METHODS:
        raise BuyerError("invalid_method", "method must be GET, HEAD, or POST.")
    return upper


def _cache_key(method: str, url: str) -> str:
    return f"{method} {url}"


def _json(body: bytes) -> dict:
    if not body:
        return {}
    try:
        import json

        parsed = json.loads(body)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _retry_after(response: _Raw, body: dict) -> int:
    raw = response.headers.get("retry-after", "")
    if raw.isdigit():
        return max(1, int(raw))
    value = body.get("retry_after_seconds")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 1:
        return value
    return 2


def _pending(challenge: Challenge, retry_after: int | None) -> dict:
    return {
        "ok": False,
        "error": "payment_pending",
        "payment_hash": challenge.payment_hash,
        "retry_after_seconds": retry_after or 2,
        "detail": "The invoice is not settled yet. Pay it if you have not, then call check_payment again. Do not pay a second invoice.",
    }


def _pending_unknown(body: dict, response: _Raw) -> dict:
    payment_hash = body.get("payment_hash") if isinstance(body.get("payment_hash"), str) else ""
    return {
        "ok": False,
        "error": "payment_pending",
        "payment_hash": payment_hash,
        "retry_after_seconds": _retry_after(response, body),
        "detail": "The invoice is not settled yet. Retry check_payment. Do not pay a second invoice.",
    }


def _preimage_required(challenge: Challenge) -> dict:
    return {
        "ok": False,
        "error": "preimage_required",
        "payment_hash": challenge.payment_hash,
        "detail": (
            "The payee wallet did not advertise LUD-21 verify, so a macaroon-only poll cannot finish. "
            "Pay with mode nwc, which uses the preimage, or use a wallet that can show the preimage."
        ),
    }


def _challenge_from_quote(row) -> Challenge:
    raw = row["x402_json"] if "x402_json" in row.keys() else None
    parsed = ParsedX402.from_json(raw) if isinstance(raw, str) and raw else None
    invoice = str(row["invoice"])
    return Challenge(
        method=str(row["method"]),
        url=str(row["url"]),
        macaroon=str(row["macaroon"]),
        invoice=invoice,
        payment_hash=str(row["payment_hash"]),
        amount_sats=int(row["amount_sats"]),
        resource=row["resource"],
        max_uses=row["max_uses"],
        access_seconds=row["access_seconds"],
        invoice_expires_at=row["invoice_expires_at"],
        reason=row["reason"],
        request_body=row["request_body"],
        offers_lightning=bool(invoice),
        x402=parsed,
    )


def _is_core(url: str, core_url: str) -> bool:
    base = core_url.rstrip("/")
    return url == base or url.startswith(base + "/")
