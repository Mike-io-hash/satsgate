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


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    client_id: int
    resource: str | None
    payment_hash: str
    charged_credits: int
    new_balance: int
    valid_until: int


def _b64decode_url_nopad(s: str) -> bytes:
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode(s + pad)


def decode_macaroon_payload(macaroon_b64: str) -> dict[str, Any]:
    """Decode the JSON payload inside the macaroon.

    Note: this does NOT verify the signature (the server does that in /verify).
    This is used for local caching / quick reads.
    """

    token = _b64decode_url_nopad(macaroon_b64)
    payload_bytes, _sig = token.rsplit(b".", 1)
    return json.loads(payload_bytes.decode("utf-8"))


def parse_l402_authorization(auth: str) -> tuple[str, str]:
    """Returns (macaroon_b64, preimage_hex)."""

    if not auth:
        raise SatsgateError("missing Authorization credentials")

    parts = auth.split(" ", 1)
    if len(parts) != 2:
        raise SatsgateError("malformed Authorization header")

    scheme, token = parts
    if scheme.lower() != "l402":
        raise SatsgateError("scheme is not L402")

    try:
        macaroon_b64, preimage_hex = token.split(":", 1)
    except ValueError as e:
        raise SatsgateError("malformed L402 token") from e

    # validate hex
    try:
        bytes.fromhex(preimage_hex)
    except ValueError as e:
        raise SatsgateError("preimage is not hex") from e

    return macaroon_b64, preimage_hex


def sha256_hex_of_hexbytes(preimage_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(preimage_hex)).hexdigest()


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

        # Simple cache: payment_hash -> valid_until
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
        )

    def paywall_verify(
        self,
        *,
        authorization_header: str,
        expected_resource: str | None = None,
        cost_credits: int = 1,
        use_cache: bool = True,
    ) -> VerifyResult:
        """Verify payment and spend credits.

        `use_cache=True` avoids calling the server repeatedly for the same payment_hash
        (until `valid_until`).
        """

        macaroon_b64, preimage_hex = parse_l402_authorization(authorization_header)
        payload = decode_macaroon_payload(macaroon_b64)

        payment_hash = str(payload.get("ph"))
        valid_until = int(payload.get("exp") or 0)

        # quick local check
        if sha256_hex_of_hexbytes(preimage_hex) != payment_hash:
            raise SatsgateError("preimage does not match payment_hash")

        now = int(time.time())
        if valid_until and now > valid_until:
            raise SatsgateError("token expired")

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
        if vu:
            self._verified[payment_hash] = vu

        return VerifyResult(
            ok=True,
            client_id=int(data["client_id"]),
            resource=data.get("resource"),
            payment_hash=str(data["payment_hash"]),
            charged_credits=int(data["charged_credits"]),
            new_balance=int(data["new_balance"]),
            valid_until=vu,
        )
