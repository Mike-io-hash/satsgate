"""Parse an L402 402 from the WWW-Authenticate header and a Satsgate JSON body."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

from satsgate_mcp.bolt11 import amount_sats, expires_at

log = logging.getLogger("satsgate_mcp")

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_HEADER = re.compile(
    r'(?i)(?:L402|LSAT)\s+(?:macaroon|token)="([^"]+)"\s*,\s*invoice="([^"]+)"'
)
_REASON = re.compile(r"^[A-Za-z0-9_ ]{1,80}$")
_MAX_USES = 100_000
_MAX_ACCESS = 604_800


class ChallengeError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Challenge:
    method: str
    url: str
    macaroon: str
    invoice: str
    payment_hash: str
    amount_sats: int
    resource: str | None
    max_uses: int | None
    access_seconds: int | None
    invoice_expires_at: int | None
    reason: str | None
    request_body: bytes | None
    uses_left: int | None = None
    access_until: int | None = None

    def summary(self) -> str:
        bits = [f"{self.method} {self.url} costs {self.amount_sats} sats."]
        if self.max_uses is not None and self.access_seconds is not None:
            bits.append(
                f"The grant is {self.max_uses} uses or {self.access_seconds} seconds, whichever ends first."
            )
        elif self.max_uses == 1:
            bits.append("One payment covers one request.")
        elif self.max_uses is not None:
            bits.append(f"One payment covers {self.max_uses} requests.")
        elif self.access_seconds is not None:
            bits.append(f"One payment covers {self.access_seconds} seconds after it settles.")
        else:
            bits.append("The server did not state a usage policy.")
        if self.invoice_expires_at is not None:
            bits.append(f"The invoice expires at unix {self.invoice_expires_at}.")
        if self.reason:
            bits.append(f"The previous token was rejected ({self.reason}). This is a new quote, not a payment.")
        return " ".join(bits)

    def public(self) -> dict[str, object]:
        return {
            "ok": True,
            "payment_required": True,
            "url": self.url,
            "method": self.method,
            "amount_sats": self.amount_sats,
            "payment_hash": self.payment_hash,
            "invoice": self.invoice,
            "invoice_expires_at": self.invoice_expires_at,
            "resource": self.resource,
            "max_uses": self.max_uses,
            "access_seconds": self.access_seconds,
            "reason": self.reason,
            "summary": self.summary(),
        }


def _json_object(body: bytes) -> dict:
    if not body:
        return {}
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return parsed


def _positive_int(value: object, *, maximum: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    if value < 1 or value > maximum:
        return None
    return value


def _reason(value: object) -> str | None:
    if not isinstance(value, str) or not _REASON.fullmatch(value):
        return None
    return value


def _secret_text(value: str, label: str) -> str:
    if not value or any(char in value for char in "\r\n\x00 \t"):
        raise ChallengeError("invalid_challenge", f"The {label} is missing or contains whitespace.")
    if len(value) > 8192:
        raise ChallengeError("invalid_challenge", f"The {label} is too long.")
    return value


def macaroon_fields(token: str) -> dict[str, str] | None:
    compact = "".join(str(token).split())
    if not compact:
        return None
    try:
        from pymacaroons import Macaroon

        mac = Macaroon.deserialize(compact)
        fields: dict[str, str] = {}
        for caveat in mac.caveats:
            raw = caveat.caveat_id
            text = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
            if "=" not in text:
                continue
            key, value = text.split("=", 1)
            fields[key] = value
    except Exception:
        log.debug("macaroon could not be decoded")
        return None
    payment_hash = fields.get("ph", "")
    if not _HEX64.fullmatch(payment_hash):
        return None
    fields["ph"] = payment_hash.lower()
    return fields


def header_credentials(header: str) -> tuple[str, str] | None:
    if not header or "\n" in header or "\r" in header:
        return None
    match = _HEADER.search(header.strip())
    if match is None:
        return None
    macaroon, invoice = match.group(1), match.group(2)
    mac_at = header.lower().find("macaroon=")
    token_at = header.lower().find("token=")
    inv_at = header.lower().find("invoice=")
    credential_at = mac_at if mac_at != -1 else token_at
    if credential_at == -1 or inv_at == -1 or credential_at > inv_at:
        return None
    return macaroon, invoice


def parse_challenge(
    *,
    method: str,
    url: str,
    status: int,
    www_authenticate: str,
    body: bytes,
    request_body: bytes | None,
) -> Challenge:
    if status != 402:
        raise ChallengeError("not_a_challenge", f"Expected HTTP 402, got {status}.")
    payload = _json_object(body)
    if payload.get("error") == "payment_pending":
        raise ChallengeError("payment_pending", "The invoice is not settled yet.")
    from_header = header_credentials(www_authenticate)
    macaroon = from_header[0] if from_header else ""
    invoice = from_header[1] if from_header else ""
    if not macaroon and isinstance(payload.get("macaroon"), str):
        macaroon = payload["macaroon"]
    if not invoice and isinstance(payload.get("invoice"), str):
        invoice = payload["invoice"]
    macaroon = _secret_text(macaroon, "macaroon")
    invoice = _secret_text(invoice, "invoice")
    if not invoice.lower().startswith("ln"):
        raise ChallengeError("invalid_challenge", "The invoice is not a BOLT11 string.")

    body_amount = payload.get("amount_sats")
    if isinstance(body_amount, bool) or not isinstance(body_amount, int) or body_amount < 1:
        body_amount = None
    invoice_amount = amount_sats(invoice)
    if body_amount is not None and invoice_amount is not None and body_amount != invoice_amount:
        raise ChallengeError(
            "amount_mismatch",
            f"The JSON amount is {body_amount} sats and the invoice encodes {invoice_amount} sats. Refusing to pay.",
        )
    amount = body_amount if body_amount is not None else invoice_amount
    if amount is None:
        raise ChallengeError(
            "amount_unknown",
            "The 402 did not include a price in sats, and the invoice amount could not be read.",
        )

    fields = macaroon_fields(macaroon)
    payment_hash = payload.get("payment_hash")
    if not isinstance(payment_hash, str) or not _HEX64.fullmatch(payment_hash):
        payment_hash = fields.get("ph") if fields else None
    if not isinstance(payment_hash, str) or not _HEX64.fullmatch(payment_hash):
        raise ChallengeError("invalid_challenge", "The 402 did not include a payment hash.")
    resource = payload.get("resource")
    if not isinstance(resource, str) or not resource.strip():
        resource = fields.get("res") if fields else None
    if isinstance(resource, str):
        resource = resource.strip()[:200] or None

    expiry = payload.get("invoice_expires_at")
    if isinstance(expiry, bool) or not isinstance(expiry, int) or expiry < 1:
        expiry = expires_at(invoice)

    return Challenge(
        method=method.upper(),
        url=url,
        macaroon=macaroon,
        invoice=invoice,
        payment_hash=payment_hash.lower(),
        amount_sats=int(amount),
        resource=resource,
        max_uses=_positive_int(payload.get("max_uses"), maximum=_MAX_USES),
        access_seconds=_positive_int(payload.get("access_seconds"), maximum=_MAX_ACCESS),
        invoice_expires_at=expiry,
        reason=_reason(payload.get("reason")),
        request_body=request_body,
    )
