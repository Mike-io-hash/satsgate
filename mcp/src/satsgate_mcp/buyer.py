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

log = logging.getLogger("satsgate_mcp")

_METHODS = frozenset({"GET", "HEAD", "POST"})
_QUOTE_REUSE_SECONDS = 60
_REQUOTE = frozenset({"token_used_up", "token_expired"})
_PREIMAGE = re.compile(r"^[0-9a-fA-F]{64}$")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


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
        return challenge.public()

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
    ) -> Presentation:
        way = mode.strip().lower()
        if way not in {"human", "nwc"}:
            raise BuyerError("invalid_mode", "mode must be human or nwc.")
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
            }
        )

    def _human_offer(self, challenge: Challenge) -> Presentation:
        png, text = invoice_qr(challenge.invoice)
        payload = challenge.public()
        payload["mode"] = "human"
        payload["action"] = "pay_invoice"
        payload["qr_text"] = text
        payload["detail"] = (
            "Pay this invoice from any Lightning wallet, then call check_payment with payment_hash. "
            "Do not send a preimage. check_payment polls settlement and retries the URL with the macaroon."
        )
        return Presentation(payload, png)

    async def _pay_with_nwc(self, challenge: Challenge, *, allow_autopay: bool) -> Presentation:
        if not self.settings.nwc_uri:
            raise BuyerError(
                "nwc_not_configured",
                "SATSGATE_MCP_NWC_URI is not set. Use mode human, or set the wallet URI in the environment. "
                "Do not paste it into the chat.",
            )
        blocked = refusal(self.settings, self.store, challenge.amount_sats, self._now())
        if blocked:
            payload = challenge.public()
            payload["ok"] = False
            payload["error"] = "over_budget"
            payload["action"] = "requote"
            payload["auto_paid"] = False
            payload["detail"] = blocked
            return Presentation(payload)
        if allow_autopay and not self.settings.auto_pay:
            payload = challenge.public()
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
                )
            except ChallengeError as exc:
                raise BuyerError(exc.code, exc.message) from None
            self._remember_quote(fresh)
            reason = fresh.reason or ""
            if allow_autopay and reason in _REQUOTE and self.settings.auto_pay:
                paid = await self._pay_with_nwc(fresh, allow_autopay=True)
                return paid
            payload = fresh.public()
            payload["action"] = "requote"
            payload["auto_paid"] = False
            if reason in _REQUOTE:
                payload["detail"] = (
                    f"The server rejected the token ({reason}). Here is a new quote. "
                    "It was not paid. Call pay_and_fetch again if you want to pay it."
                )
            else:
                payload["detail"] = "The server returned a new 402. It was not paid."
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
            if name.lower() in {"authorization", "x-api-key", "content-type", "accept"}:
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
    return Challenge(
        method=str(row["method"]),
        url=str(row["url"]),
        macaroon=str(row["macaroon"]),
        invoice=str(row["invoice"]),
        payment_hash=str(row["payment_hash"]),
        amount_sats=int(row["amount_sats"]),
        resource=row["resource"],
        max_uses=row["max_uses"],
        access_seconds=row["access_seconds"],
        invoice_expires_at=row["invoice_expires_at"],
        reason=row["reason"],
        request_body=row["request_body"],
    )


def _is_core(url: str, core_url: str) -> bool:
    base = core_url.rstrip("/")
    return url == base or url.startswith(base + "/")
