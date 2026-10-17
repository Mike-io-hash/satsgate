from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

import httpx


class SatsgateError(RuntimeError):
    """Raised when satsgate returns a non-OK response."""

    def __init__(self, message: str, *, status_code: int | None = None, data: dict | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.data = data


@dataclass(frozen=True)
class Challenge:
    resource: str
    amount_sats: int
    payee_lightning_address: str | None
    macaroon: str
    invoice: str
    payment_hash: str
    valid_until: int
    www_authenticate: str
    claim_until: int | None = None
    invoice_expires_at: int | None = None
    cache_until: int | None = None
    payee_saved: bool = False


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    client_id: int
    resource: str | None
    payment_hash: str
    charged_credits: int
    new_balance: int
    valid_until: int
    amount_sats: int | None = None
    payee_lightning_address: str | None = None
    claim_until: int | None = None
    invoice_expires_at: int | None = None
    cache_until: int | None = None


def _decode_token_bytes(token: str) -> bytes:
    compact = "".join(token.split())
    padded = compact + ("=" * ((4 - (len(compact) % 4)) % 4))
    if any(char in compact for char in "-_"):
        return base64.urlsafe_b64decode(padded)
    return base64.b64decode(padded)


def decode_macaroon_payload(macaroon_b64: str) -> dict[str, Any]:
    """Read the v2 bindings inside a macaroon.

    Accepts the macaroons satsgate issues now and the older signed-JSON tokens.
    This does NOT verify the signature (the server does that in /verify).
    """

    raw = _decode_token_bytes(macaroon_b64)
    if raw.startswith(b"{"):
        payload_bytes, _sig = raw.rsplit(b".", 1)
        return json.loads(payload_bytes.decode("utf-8"))

    from pymacaroons import Macaroon

    mac = Macaroon.deserialize("".join(macaroon_b64.split()))
    fields: dict[str, str] = {}
    for caveat in mac.caveats:
        text = caveat.caveat_id.decode("utf-8") if isinstance(caveat.caveat_id, bytes) else str(caveat.caveat_id)
        key, value = text.split("=", 1)
        fields[key] = value
    return {
        "v": int(fields["v"]),
        "kid": fields.get("kid"),
        "purpose": fields.get("purpose"),
        "cid": int(fields["cid"]) if "cid" in fields else None,
        "ph": fields["ph"].lower(),
        "res": fields["res"],
        "amt": int(fields["amt"]),
        "payee_h": fields.get("payee_h"),
        "inv_h": fields.get("inv_h"),
        "exp": int(fields["exp"]),
    }


def parse_l402_authorization(auth: str) -> tuple[str, str]:
    """Returns (macaroon_b64, preimage_hex). Accepts the L402 and legacy LSAT schemes."""

    if not auth:
        raise SatsgateError("missing Authorization credentials")

    parts = auth.strip().split(None, 1)
    if len(parts) != 2:
        raise SatsgateError("malformed Authorization header")

    scheme, token = parts
    if scheme.lower() not in {"l402", "lsat"}:
        raise SatsgateError("scheme is not L402")

    try:
        macaroon_b64, preimage_hex = token.split(":", 1)
    except ValueError as e:
        raise SatsgateError("malformed L402 token") from e

    # validate hex
    try:
        raw = bytes.fromhex(preimage_hex)
    except ValueError as e:
        raise SatsgateError("preimage is not hex") from e
    if len(raw) != 32:
        raise SatsgateError("preimage is not hex")

    return macaroon_b64, preimage_hex.lower()


def sha256_hex_of_hexbytes(preimage_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(preimage_hex)).hexdigest()


def _optional_int(data: dict, key: str) -> int | None:
    raw = data.get(key)
    if raw is None or raw == "":
        return None
    return int(raw)


def _cache_deadline(data: dict) -> int:
    """How long the SDK may remember a successful unlock.

    `cache_until` is that hint. Older servers only send `valid_until` (the macaroon exp).
    """
    for key in ("cache_until", "claim_until", "valid_until"):
        value = _optional_int(data, key)
        if value:
            return value
    return 0


class SatsgateClient:
    """Minimal synchronous client for the satsgate API."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        timeout_seconds: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._http = httpx.Client(timeout=timeout_seconds)

        # payment_hash -> cache_until (a cache hint, not a content-access grant)
        self._verified: dict[str, int] = {}

    def __enter__(self) -> "SatsgateClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        self.close()

    def close(self) -> None:
        self._http.close()

    def _headers(self) -> dict[str, str]:
        return {"X-Api-Key": self.api_key}

    def _ok_or_raise(self, r: httpx.Response) -> dict:
        try:
            data = r.json()
        except Exception:
            raise SatsgateError(
                f"request failed ({r.status_code}): non-json response",
                status_code=r.status_code,
                data=None,
            )

        if r.status_code != 200 or not data.get("ok"):
            raise SatsgateError(
                f"request failed ({r.status_code}): {data}",
                status_code=r.status_code,
                data=data,
            )

        return data

    # --- Billing / account ---

    def list_plans(self) -> list[dict]:
        r = self._http.get(f"{self.base_url}/v1/plans")
        data = self._ok_or_raise(r)
        return data["plans"]

    def balance(self) -> dict:
        r = self._http.get(f"{self.base_url}/v1/balance", headers=self._headers())
        return self._ok_or_raise(r)

    def get_client(self) -> dict:
        r = self._http.get(f"{self.base_url}/v1/client", headers=self._headers())
        return self._ok_or_raise(r)

    def set_payee(self, lightning_address: str) -> dict:
        r = self._http.post(
            f"{self.base_url}/v1/client/payee",
            headers={**self._headers(), "Content-Type": "application/json"},
            json={"payee_lightning_address": lightning_address},
        )
        return self._ok_or_raise(r)

    # --- Reporting ---

    def ledger(self, *, limit: int = 50, before_id: int | None = None) -> dict:
        params: dict[str, Any] = {"limit": int(limit)}
        if before_id is not None:
            params["before_id"] = int(before_id)

        r = self._http.get(f"{self.base_url}/v1/ledger", headers=self._headers(), params=params)
        return self._ok_or_raise(r)

    def usage_summary(self, *, since_hours: int = 24) -> dict:
        r = self._http.get(
            f"{self.base_url}/v1/usage/summary",
            headers=self._headers(),
            params={"since_hours": int(since_hours)},
        )
        return self._ok_or_raise(r)

    def usage_daily(self, *, days: int = 30) -> dict:
        r = self._http.get(
            f"{self.base_url}/v1/usage/daily",
            headers=self._headers(),
            params={"days": int(days)},
        )
        return self._ok_or_raise(r)

    def usage_forecast(
        self,
        *,
        lookback_hours: int = 24,
        buffer_days: int = 7,
        max_topups: int = 3,
        trigger_hours: int = 24,
    ) -> dict:
        r = self._http.get(
            f"{self.base_url}/v1/usage/forecast",
            headers=self._headers(),
            params={
                "lookback_hours": int(lookback_hours),
                "buffer_days": int(buffer_days),
                "max_topups": int(max_topups),
                "trigger_hours": int(trigger_hours),
            },
        )
        return self._ok_or_raise(r)

    # --- Paywall ---

    def paywall_challenge(
        self,
        *,
        resource: str,
        amount_sats: int,
        memo: str | None = None,
        ttl_seconds: int | None = None,
    ) -> Challenge:
        body: dict[str, Any] = {
            "resource": resource,
            "amount_sats": int(amount_sats),
        }
        if memo is not None:
            body["memo"] = memo
        if ttl_seconds is not None:
            body["ttl_seconds"] = int(ttl_seconds)

        r = self._http.post(
            f"{self.base_url}/v1/paywall/challenge",
            headers={**self._headers(), "Content-Type": "application/json"},
            json=body,
        )
        data = self._ok_or_raise(r)

        return Challenge(
            resource=data["resource"],
            amount_sats=int(data["amount_sats"]),
            payee_lightning_address=data.get("payee_lightning_address"),
            macaroon=data["macaroon"],
            invoice=data["invoice"],
            payment_hash=data["payment_hash"],
            valid_until=int(data["valid_until"]),
            www_authenticate=data["www_authenticate"],
            claim_until=_optional_int(data, "claim_until"),
            invoice_expires_at=_optional_int(data, "invoice_expires_at"),
            cache_until=_optional_int(data, "cache_until"),
            payee_saved=bool(data.get("payee_saved")),
        )

    def paywall_verify(
        self,
        *,
        authorization_header: str,
        expected_resource: str,
        cost_credits: int = 1,
        use_cache: bool = True,
    ) -> VerifyResult:
        """Verify payment and spend credits.

        `expected_resource` is required and must exactly match the challenge resource.
        Tokens are v2 and are bound to the satsgate client that minted them.
        `use_cache=True` remembers a successful unlock until `cache_until` (or
        `valid_until` on older servers). That avoids calling verify on every request.
        It is not a content-access window; the merchant decides how long the buyer may use the product.
        The server, not this client, decides whether a macaroon whose `exp` has passed
        can still be unlocked inside the invoice claim window.
        """

        if not expected_resource or not str(expected_resource).strip():
            raise SatsgateError("expected_resource is required")

        macaroon_b64, preimage_hex = parse_l402_authorization(authorization_header)
        payload = decode_macaroon_payload(macaroon_b64)

        if payload.get("v") != 2:
            raise SatsgateError("unsupported token version")
        if payload.get("res") != expected_resource:
            raise SatsgateError("resource mismatch")

        payment_hash = str(payload.get("ph"))

        # quick local check
        if sha256_hex_of_hexbytes(preimage_hex) != payment_hash:
            raise SatsgateError("preimage does not match payment_hash")

        now = int(time.time())

        if use_cache:
            cached_until = self._verified.get(payment_hash)
            if cached_until and now <= cached_until:
                return VerifyResult(
                    ok=True,
                    client_id=-1,
                    resource=str(payload.get("res")),
                    payment_hash=payment_hash,
                    charged_credits=0,
                    new_balance=-1,
                    valid_until=cached_until,
                )

        r = self._http.post(
            f"{self.base_url}/v1/paywall/verify",
            headers={
                **self._headers(),
                "Content-Type": "application/json",
                "Authorization": authorization_header,
            },
            json={"expected_resource": expected_resource, "cost_credits": int(cost_credits)},
        )
        data = self._ok_or_raise(r)

        vu = int(data.get("valid_until") or 0)
        cache_until = _cache_deadline(data)
        if cache_until:
            self._verified[payment_hash] = cache_until

        return VerifyResult(
            ok=True,
            client_id=int(data["client_id"]),
            resource=data.get("resource"),
            payment_hash=str(data["payment_hash"]),
            charged_credits=int(data["charged_credits"]),
            new_balance=int(data["new_balance"]),
            valid_until=vu,
            amount_sats=int(data["amount_sats"]) if data.get("amount_sats") is not None else None,
            payee_lightning_address=data.get("payee_lightning_address"),
            claim_until=_optional_int(data, "claim_until"),
            invoice_expires_at=_optional_int(data, "invoice_expires_at"),
            cache_until=cache_until or None,
        )

    def _poll(self, send, *, interval_seconds: float, timeout_seconds: float) -> dict:
        """Call `send` until the body says the payment settled or the deadline passes."""
        interval = max(0.0, float(interval_seconds))
        deadline = time.monotonic() + max(0.0, float(timeout_seconds))
        while True:
            response = send()
            try:
                data = response.json()
            except Exception:
                data = None
            if response.status_code == 200 and isinstance(data, dict) and data.get("settled") is True:
                return data
            retryable = isinstance(data, dict) and (
                data.get("status") == "pending" or data.get("error") in {"payment_pending", "lud21_unavailable", "payee_fetch_failed"}
            )
            if response.status_code not in {200, 402, 502} or not retryable or time.monotonic() >= deadline:
                raise SatsgateError(
                    "payment still pending" if retryable else f"request failed ({response.status_code}): {data}",
                    status_code=response.status_code,
                    data=data if isinstance(data, dict) else None,
                )
            time.sleep(interval)

    def poll_topup(
        self,
        *,
        macaroon: str,
        payment_hash: str,
        interval_seconds: float = 2.0,
        timeout_seconds: float = 180.0,
    ) -> dict:
        """Poll `GET /v1/topup/status/{payment_hash}` until LUD-21 settlement.

        Pay the invoice from any wallet, then call this with the macaroon from
        the 402 response. No preimage is sent. The API key is present only on
        the call that creates the account.

        Raises if the provider did not advertise a verify URL (`preimage_required`)
        or the timeout elapses first.
        """

        def _send():
            return self._http.get(
                f"{self.base_url}/v1/topup/status/{payment_hash}",
                headers={"Authorization": f"L402 {macaroon}"},
            )

        return self._poll(_send, interval_seconds=interval_seconds, timeout_seconds=timeout_seconds)

    def poll_paywall(
        self,
        *,
        macaroon: str,
        payment_hash: str,
        expected_resource: str,
        cost_credits: int = 1,
        interval_seconds: float = 2.0,
        timeout_seconds: float = 180.0,
    ) -> VerifyResult:
        """Poll a paywall challenge until the stored LUD-21 URL reports it settled.

        Uses the merchant API key plus `Authorization: L402 <macaroon>`.
        This is an alternative to `paywall_verify`. The first settled response
        spends credits once for the payment hash; a repeat spends 0.
        """

        if not expected_resource or not str(expected_resource).strip():
            raise SatsgateError("expected_resource is required")

        def _send():
            return self._http.get(
                f"{self.base_url}/v1/paywall/status/{payment_hash}",
                headers={**self._headers(), "Authorization": f"L402 {macaroon}"},
                params={"expected_resource": expected_resource, "cost_credits": int(cost_credits)},
            )

        data = self._poll(_send, interval_seconds=interval_seconds, timeout_seconds=timeout_seconds)
        vu = int(data.get("valid_until") or 0)
        cache_until = _cache_deadline(data)
        if cache_until:
            self._verified[str(data["payment_hash"])] = cache_until
        return VerifyResult(
            ok=True,
            client_id=int(data["client_id"]),
            resource=data.get("resource"),
            payment_hash=str(data["payment_hash"]),
            charged_credits=int(data["charged_credits"]),
            new_balance=int(data["new_balance"]),
            valid_until=vu,
            amount_sats=int(data["amount_sats"]) if data.get("amount_sats") is not None else None,
            payee_lightning_address=data.get("payee_lightning_address"),
            claim_until=_optional_int(data, "claim_until"),
            invoice_expires_at=_optional_int(data, "invoice_expires_at"),
            cache_until=cache_until or None,
        )
