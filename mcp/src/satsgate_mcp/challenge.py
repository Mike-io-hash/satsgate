"""Parse an L402 402 from the WWW-Authenticate header and a Satsgate JSON body."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

from satsgate_mcp.bolt11 import amount_sats, expires_at
from satsgate_mcp.x402 import ParsedX402, parse_offered

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
    offers_lightning: bool = True
    x402: ParsedX402 | None = None

    def summary(self) -> str:
        if not self.offers_lightning:
            bits = [f"{self.method} {self.url} has no Lightning invoice."]
        else:
            bits = [f"{self.method} {self.url} costs {self.amount_sats} sats."]
        bits.extend(self._policy_bits())
        if self.x402 is not None:
            bits.append(self.x402.price_sentence())
        return " ".join(bits)

    def _policy_bits(self) -> list[str]:
        bits: list[str] = []
        if not self.offers_lightning:
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
            if self.reason:
                bits.append(f"The previous token was rejected ({self.reason}). This is a new quote, not a payment.")
            return bits
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
        return bits

    def public(self) -> dict[str, object]:
        rails: list[str] = []
        if self.offers_lightning:
            rails.append("lightning")
        if self.x402 is not None:
            rails.append("x402")
        payload: dict[str, object] = {
            "ok": True,
            "payment_required": True,
            "url": self.url,
            "method": self.method,
            "resource": self.resource,
            "max_uses": self.max_uses,
            "access_seconds": self.access_seconds,
            "reason": self.reason,
            "rails": rails,
            "summary": self.summary(),
        }
        if self.offers_lightning:
            payload["amount_sats"] = self.amount_sats
            payload["payment_hash"] = self.payment_hash
            payload["invoice"] = self.invoice
            payload["invoice_expires_at"] = self.invoice_expires_at
        return payload


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


def _x402_quote_id(method: str, url: str, parsed: ParsedX402) -> str:
    import hashlib

    raw = parsed.to_json()
    digest = hashlib.sha256(f"{method} {url} {raw}".encode("utf-8")).hexdigest()
    return "x402:" + digest


def parse_challenge(
    *,
    method: str,
    url: str,
    status: int,
    www_authenticate: str,
    body: bytes,
    request_body: bytes | None,
    payment_required: str = "",
) -> Challenge:
    if status != 402:
        raise ChallengeError("not_a_challenge", f"Expected HTTP 402, got {status}.")
    payload = _json_object(body)
    if payload.get("error") == "payment_pending":
        raise ChallengeError("payment_pending", "The invoice is not settled yet.")
    offered = parse_offered(payment_required, payload)
    try:
        challenge = _parse_lightning(
            method=method,
            url=url,
            www_authenticate=www_authenticate,
            payload=payload,
            request_body=request_body,
        )
    except ChallengeError as exc:
        if offered is not None and not offered.malformed:
            return _x402_only(
                method=method,
                url=url,
                payload=payload,
                request_body=request_body,
                parsed=offered,
            )
        if offered is not None and offered.malformed:
            raise ChallengeError("malformed_x402", offered.detail or "The x402 offer could not be parsed.") from None
        raise exc
    if offered is None:
        return challenge
    if offered.malformed:
        return Challenge(
            method=challenge.method,
            url=challenge.url,
            macaroon=challenge.macaroon,
            invoice=challenge.invoice,
            payment_hash=challenge.payment_hash,
            amount_sats=challenge.amount_sats,
            resource=challenge.resource,
            max_uses=challenge.max_uses,
            access_seconds=challenge.access_seconds,
            invoice_expires_at=challenge.invoice_expires_at,
            reason=challenge.reason,
            request_body=challenge.request_body,
            offers_lightning=True,
            x402=offered,
        )
    return Challenge(
        method=challenge.method,
        url=challenge.url,
        macaroon=challenge.macaroon,
        invoice=challenge.invoice,
        payment_hash=challenge.payment_hash,
        amount_sats=challenge.amount_sats,
        resource=challenge.resource,
        max_uses=challenge.max_uses,
        access_seconds=challenge.access_seconds,
        invoice_expires_at=challenge.invoice_expires_at,
        reason=challenge.reason,
        request_body=challenge.request_body,
        offers_lightning=True,
        x402=offered,
    )


def _x402_only(
    *,
    method: str,
    url: str,
    payload: dict,
    request_body: bytes | None,
    parsed: ParsedX402,
) -> Challenge:
    resource = payload.get("resource")
    if not isinstance(resource, str) or not resource.strip():
        resource = parsed.satsgate_resource
    if isinstance(resource, str):
        resource = resource.strip()[:200] or None
    return Challenge(
        method=method.upper(),
        url=url,
        macaroon="",
        invoice="",
        payment_hash=_x402_quote_id(method.upper(), url, parsed),
        amount_sats=0,
        resource=resource,
        max_uses=_positive_int(payload.get("max_uses"), maximum=_MAX_USES),
        access_seconds=_positive_int(payload.get("access_seconds"), maximum=_MAX_ACCESS),
        invoice_expires_at=parsed.expires_at,
        reason=_reason(payload.get("reason")),
        request_body=request_body,
        offers_lightning=False,
        x402=parsed,
    )


def _parse_lightning(
    *,
    method: str,
    url: str,
    www_authenticate: str,
    payload: dict,
    request_body: bytes | None,
) -> Challenge:
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
