"""Parse an x402 v2 PAYMENT-REQUIRED header. This module does not sign or pay.

The header is canonical. A JSON ``x402`` object on the 402 body is only a
mirror for expiry and for clients that do not read headers. Amounts are shown
exactly as the 402 states them. Nothing here converts sats to USDC.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass

from satsgate_mcp.budget import usd_refusal
from satsgate_mcp.config import Settings

_ATOMIC = re.compile(r"^[1-9][0-9]{0,17}$")
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_HEADER_MAX = 8192
_USDC_DECIMALS = 6

# USDC on Base Sepolia and Base. Compared case-insensitively. The 402's own
# spelling is what we show. Mainnet is recognized so a later flag does not
# crash this client. Other networks are reported and are not payable.
_USDC_BY_NETWORK = {
    "eip155:84532": "0x036cbd53842c5426634e7929541ec2318f3dcf7e",
    "eip155:8453": "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
}
_NETWORK_NAMES = {
    "eip155:84532": "Base Sepolia",
    "eip155:8453": "Base",
}


def format_usdc(atomic: int) -> str:
    """Human USDC from a 6-decimal atomic integer. 10000 becomes ``0.01 USDC``."""
    whole, frac = divmod(int(atomic), 10**_USDC_DECIMALS)
    if frac == 0:
        return f"{whole} USDC"
    text = f"{frac:0{_USDC_DECIMALS}d}".rstrip("0")
    return f"{whole}.{text} USDC"


@dataclass(frozen=True)
class ParsedAccept:
    scheme: str | None
    network: str | None
    asset: str | None
    amount_atomic: str | None
    pay_to: str | None
    max_timeout_seconds: int | None
    supported: bool
    unsupported_reason: str | None
    detail: str

    def amount_display(self) -> str | None:
        if not self.supported or self.amount_atomic is None:
            return None
        return format_usdc(int(self.amount_atomic))

    def amount_usdc(self) -> str | None:
        shown = self.amount_display()
        if shown is None:
            return None
        return shown.removesuffix(" USDC")


@dataclass(frozen=True)
class ParsedX402:
    """One 402's x402 offer. ``malformed`` means the header could not be read."""

    malformed: bool
    detail: str | None
    canonical: bool
    resource_url: str | None
    expires_at: int | None
    mirror_disagreed: bool
    accepts: tuple[ParsedAccept, ...]
    satsgate_resource: str | None

    def to_json(self) -> str:
        return json.dumps(_dump(self), separators=(",", ":"), sort_keys=True)

    @staticmethod
    def from_json(text: str) -> ParsedX402 | None:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(payload, dict):
            return None
        accepts_raw = payload.get("accepts")
        if not isinstance(accepts_raw, list):
            return None
        accepts: list[ParsedAccept] = []
        for item in accepts_raw:
            if not isinstance(item, dict):
                return None
            accepts.append(
                ParsedAccept(
                    scheme=_opt_str(item.get("scheme")),
                    network=_opt_str(item.get("network")),
                    asset=_opt_str(item.get("asset")),
                    amount_atomic=_opt_str(item.get("amount_atomic")),
                    pay_to=_opt_str(item.get("pay_to")),
                    max_timeout_seconds=_opt_int(item.get("max_timeout_seconds")),
                    supported=item.get("supported") is True,
                    unsupported_reason=_opt_str(item.get("unsupported_reason")),
                    detail=str(item.get("detail") or ""),
                )
            )
        return ParsedX402(
            malformed=payload.get("malformed") is True,
            detail=_opt_str(payload.get("detail")),
            canonical=payload.get("canonical") is True,
            resource_url=_opt_str(payload.get("resource_url")),
            expires_at=_opt_int(payload.get("expires_at")),
            mirror_disagreed=payload.get("mirror_disagreed") is True,
            accepts=tuple(accepts),
            satsgate_resource=_opt_str(payload.get("satsgate_resource")),
        )

    def price_sentence(self) -> str:
        if self.malformed or not self.accepts:
            return "The x402 offer could not be parsed."
        parts: list[str] = []
        for accept in self.accepts:
            name = _NETWORK_NAMES.get(accept.network or "", accept.network or "unknown network")
            if accept.amount_display():
                parts.append(
                    f"{accept.amount_display()} ({accept.amount_atomic} atomic units) "
                    f"on {name} ({accept.network}), scheme {accept.scheme}, "
                    f"payTo {accept.pay_to}, asset {accept.asset}"
                )
            else:
                parts.append(
                    f"amount {accept.amount_atomic or 'unknown'} atomic units on {name}"
                    f" ({accept.network or 'unknown'}), asset {accept.asset or 'unknown'}, "
                    f"scheme {accept.scheme or 'unknown'}, payTo {accept.pay_to or 'unknown'}"
                )
        resource = self.resource_url or "unknown"
        expiry = f" It expires at unix {self.expires_at}." if self.expires_at is not None else ""
        return f"x402 requires {'; '.join(parts)}. Resource {resource}.{expiry}"


def parse_offered(header: str, body: dict) -> ParsedX402 | None:
    """None when this 402 does not offer x402. Never raises on bad input."""
    mirror = body.get("x402") if isinstance(body, dict) else None
    header_text = header.strip() if isinstance(header, str) else ""
    offered = bool(header_text) or mirror is not None
    if not offered:
        return None
    resource = body.get("resource") if isinstance(body, dict) else None
    satsgate_resource = resource.strip()[:200] if isinstance(resource, str) and resource.strip() else None
    if not header_text:
        parsed = _from_mirror_only(mirror, satsgate_resource)
        return parsed
    if len(header_text) > _HEADER_MAX or any(char in header_text for char in "\r\n\x00"):
        return _malformed("PAYMENT-REQUIRED is missing, too long, or not a single line.", satsgate_resource)
    try:
        raw = base64.b64decode(header_text, validate=True)
    except (binascii.Error, ValueError):
        return _malformed("PAYMENT-REQUIRED is not valid base64.", satsgate_resource)
    if len(raw) > _HEADER_MAX:
        return _malformed("PAYMENT-REQUIRED is too long.", satsgate_resource)
    try:
        document = json.loads(raw)
    except json.JSONDecodeError:
        return _malformed("PAYMENT-REQUIRED is not a JSON object.", satsgate_resource)
    if not isinstance(document, dict):
        return _malformed("PAYMENT-REQUIRED is not a JSON object.", satsgate_resource)
    if document.get("x402Version") != 2:
        return _malformed("PAYMENT-REQUIRED is not x402 version 2.", satsgate_resource)
    resource_url = _resource_url(document.get("resource"))
    accepts = document.get("accepts")
    if not isinstance(accepts, list) or not accepts:
        return _malformed("PAYMENT-REQUIRED did not include any accepts entries.", satsgate_resource)
    parsed_accepts: list[ParsedAccept] = []
    for item in accepts:
        parsed_accepts.append(_one_accept(item))
    expires_at, disagreed = _mirror(mirror, parsed_accepts)
    return ParsedX402(
        malformed=False,
        detail=None,
        canonical=True,
        resource_url=resource_url,
        expires_at=expires_at,
        mirror_disagreed=disagreed,
        accepts=tuple(parsed_accepts),
        satsgate_resource=satsgate_resource,
    )


def for_agent(
    parsed: ParsedX402,
    settings: Settings,
    spent_usd_atomic: int,
) -> dict:
    """Requirements plus whether the USD cap allows an external wallet to pay."""
    if parsed.malformed:
        return {
            "offered": True,
            "ok": False,
            "error": "malformed_x402",
            "payable": False,
            "canonical": parsed.canonical,
            "detail": parsed.detail or "The x402 offer could not be parsed.",
            "resource_url": parsed.resource_url,
            "satsgate_resource": parsed.satsgate_resource,
            "accepts": [],
        }
    accepts_out: list[dict] = []
    payable_amounts: list[int] = []
    block_code: str | None = None
    block_detail: str | None = None
    supported_count = 0
    for accept in parsed.accepts:
        item = _accept_view(accept, parsed)
        if not accept.supported or accept.amount_atomic is None:
            item["within_cap"] = False
            item["payable"] = False
            if block_code is None:
                block_code = accept.unsupported_reason or "unsupported_network"
                block_detail = accept.detail
        else:
            supported_count += 1
            reason = usd_refusal(settings, int(accept.amount_atomic), spent_usd_atomic)
            item["within_cap"] = reason is None
            item["payable"] = reason is None
            if reason is None:
                payable_amounts.append(int(accept.amount_atomic))
            else:
                item["cap_detail"] = reason
                if block_code is None:
                    block_code = _cap_code(settings, int(accept.amount_atomic), spent_usd_atomic)
                    block_detail = reason
        accepts_out.append(item)
    # A signature might select any accept. Proceed only when every accept is
    # supported USDC on Base and inside the cap.
    all_ok = bool(parsed.accepts) and supported_count == len(parsed.accepts) and len(payable_amounts) == supported_count
    if not parsed.canonical:
        all_ok = False
        block_code = block_code or "header_missing"
        block_detail = block_detail or (
            "PAYMENT-REQUIRED was missing. The body fields are shown and are not a payment instruction."
        )
    view: dict = {
        "offered": True,
        "ok": True,
        "payable": all_ok,
        "canonical": parsed.canonical,
        "resource_url": parsed.resource_url,
        "satsgate_resource": parsed.satsgate_resource,
        "expires_at": parsed.expires_at,
        "mirror_disagreed": parsed.mirror_disagreed,
        "accepts": accepts_out,
    }
    if parsed.mirror_disagreed:
        view["detail"] = "The JSON mirror disagreed with PAYMENT-REQUIRED. The header values are shown."
    if not all_ok:
        view["error"] = block_code or "not_payable"
        view["cap_detail"] = block_detail
        view["payable"] = False
        return view
    view["charge_atomic"] = max(payable_amounts)
    view["payment"] = {
        "header_name": "PAYMENT-SIGNATURE",
        "accepts": [
            {
                "scheme": item["scheme"],
                "network": item["network"],
                "asset": item["asset"],
                "amount_atomic": item["amount_atomic"],
                "amount_usdc": item["amount_usdc"],
                "amount_display": item["amount_display"],
                "pay_to": item["pay_to"],
                "resource_url": parsed.resource_url,
                "expires_at": parsed.expires_at,
                "max_timeout_seconds": item["max_timeout_seconds"],
            }
            for item in accepts_out
        ],
        "detail": _PAY_DETAIL,
    }
    return view


_PAY_DETAIL = (
    "This MCP server does not hold a buyer private key, does not sign, and does not submit this payment. "
    "Satsgate does not custody, forward, or refund it. "
    "Pay the exact atomic amount from an external wallet, on the network and asset in this 402, to pay_to, "
    "for resource_url. Then call pay_and_fetch again with payment_signature set to that PAYMENT-SIGNATURE. "
    "Do not send an L402 Authorization on the same request. "
    "The gate verifies, calls the origin, and settles only after a 2xx. "
    "If the origin fails, nothing is settled and no merchant credit is taken. Retry the same PAYMENT-SIGNATURE."
)


def _cap_code(settings: Settings, amount_atomic: int, spent_usd_atomic: int) -> str:
    if settings.max_payment_usd_atomic is None or settings.daily_max_usd_atomic is None:
        return "cap_not_configured"
    if amount_atomic > settings.max_payment_usd_atomic:
        return "over_budget"
    if spent_usd_atomic + amount_atomic > settings.daily_max_usd_atomic:
        return "over_budget"
    return "over_budget"


def _accept_view(accept: ParsedAccept, parsed: ParsedX402) -> dict:
    network = accept.network
    return {
        "scheme": accept.scheme,
        "network": network,
        "network_name": _NETWORK_NAMES.get(network or ""),
        "asset": accept.asset,
        "asset_symbol": "USDC" if accept.supported else None,
        "decimals": _USDC_DECIMALS if accept.supported else None,
        "amount_atomic": accept.amount_atomic,
        "amount_usdc": accept.amount_usdc(),
        "amount_display": accept.amount_display(),
        "pay_to": accept.pay_to,
        "resource_url": parsed.resource_url,
        "expires_at": parsed.expires_at,
        "max_timeout_seconds": accept.max_timeout_seconds,
        "supported": accept.supported,
        "unsupported_reason": accept.unsupported_reason,
        "detail": accept.detail or None,
    }


def _one_accept(item: object) -> ParsedAccept:
    if not isinstance(item, dict):
        return ParsedAccept(
            scheme=None,
            network=None,
            asset=None,
            amount_atomic=None,
            pay_to=None,
            max_timeout_seconds=None,
            supported=False,
            unsupported_reason="malformed_x402",
            detail="An accepts entry was not an object.",
        )
    scheme = item.get("scheme") if isinstance(item.get("scheme"), str) else None
    network = item.get("network") if isinstance(item.get("network"), str) else None
    asset = item.get("asset") if isinstance(item.get("asset"), str) else None
    amount = item.get("amount")
    amount_text = amount.strip() if isinstance(amount, str) else None
    pay_to = item.get("payTo") if isinstance(item.get("payTo"), str) else None
    timeout = item.get("maxTimeoutSeconds")
    max_timeout = timeout if isinstance(timeout, int) and not isinstance(timeout, bool) and timeout >= 1 else None
    if scheme != "exact":
        return ParsedAccept(
            scheme=scheme,
            network=network,
            asset=asset,
            amount_atomic=amount_text,
            pay_to=pay_to,
            max_timeout_seconds=max_timeout,
            supported=False,
            unsupported_reason="unsupported_scheme",
            detail="Only scheme exact is supported. This entry is reported and was not paid.",
        )
    if amount_text is None or not _ATOMIC.fullmatch(amount_text):
        return ParsedAccept(
            scheme=scheme,
            network=network,
            asset=asset,
            amount_atomic=amount_text,
            pay_to=pay_to,
            max_timeout_seconds=max_timeout,
            supported=False,
            unsupported_reason="malformed_x402",
            detail="The amount is not a positive atomic integer string. It was not reinterpreted.",
        )
    if pay_to is None or not _ADDRESS.fullmatch(pay_to):
        return ParsedAccept(
            scheme=scheme,
            network=network,
            asset=asset,
            amount_atomic=amount_text,
            pay_to=pay_to,
            max_timeout_seconds=max_timeout,
            supported=False,
            unsupported_reason="malformed_x402",
            detail="payTo is missing or is not an 0x address.",
        )
    expected = _USDC_BY_NETWORK.get(network or "")
    if expected is None:
        return ParsedAccept(
            scheme=scheme,
            network=network,
            asset=asset,
            amount_atomic=amount_text,
            pay_to=pay_to,
            max_timeout_seconds=max_timeout,
            supported=False,
            unsupported_reason="unsupported_network",
            detail="This network is not USDC on Base. It is reported and was not paid.",
        )
    if not isinstance(asset, str) or asset.lower() != expected:
        return ParsedAccept(
            scheme=scheme,
            network=network,
            asset=asset,
            amount_atomic=amount_text,
            pay_to=pay_to,
            max_timeout_seconds=max_timeout,
            supported=False,
            unsupported_reason="unsupported_asset",
            detail="This asset is not USDC on that Base network. It is reported and was not paid.",
        )
    return ParsedAccept(
        scheme=scheme,
        network=network,
        asset=asset,
        amount_atomic=amount_text,
        pay_to=pay_to,
        max_timeout_seconds=max_timeout,
        supported=True,
        unsupported_reason=None,
        detail="",
    )


def _mirror(mirror: object, accepts: list[ParsedAccept]) -> tuple[int | None, bool]:
    """Expiry from the body. Header amounts win when the mirror disagrees."""
    if not isinstance(mirror, dict):
        return None, False
    expires = mirror.get("expires_at")
    expires_at = expires if isinstance(expires, int) and not isinstance(expires, bool) and expires >= 1 else None
    disagreed = False
    if accepts:
        first = accepts[0]
        for key, expected in (
            ("scheme", first.scheme),
            ("network", first.network),
            ("amount", first.amount_atomic),
        ):
            value = mirror.get(key)
            if value is not None and value != expected:
                disagreed = True
        pay = mirror.get("payTo")
        if isinstance(pay, str) and first.pay_to is not None and pay.lower() != first.pay_to.lower():
            disagreed = True
        asset = mirror.get("asset")
        if isinstance(asset, str) and first.asset is not None and asset.lower() != first.asset.lower():
            disagreed = True
    return expires_at, disagreed


def _from_mirror_only(mirror: object, satsgate_resource: str | None) -> ParsedX402:
    if not isinstance(mirror, dict):
        return _malformed("The x402 body was not an object and PAYMENT-REQUIRED was missing.", satsgate_resource)
    accept = _one_accept(
        {
            "scheme": mirror.get("scheme"),
            "network": mirror.get("network"),
            "asset": mirror.get("asset"),
            "amount": mirror.get("amount"),
            "payTo": mirror.get("payTo"),
        }
    )
    expires = mirror.get("expires_at")
    expires_at = expires if isinstance(expires, int) and not isinstance(expires, bool) and expires >= 1 else None
    return ParsedX402(
        malformed=False,
        detail="PAYMENT-REQUIRED was missing. The body fields are shown and are not a payment instruction.",
        canonical=False,
        resource_url=None,
        expires_at=expires_at,
        mirror_disagreed=False,
        accepts=(accept,),
        satsgate_resource=satsgate_resource,
    )


def _malformed(detail: str, satsgate_resource: str | None) -> ParsedX402:
    return ParsedX402(
        malformed=True,
        detail=detail,
        canonical=False,
        resource_url=None,
        expires_at=None,
        mirror_disagreed=False,
        accepts=(),
        satsgate_resource=satsgate_resource,
    )


def _resource_url(resource: object) -> str | None:
    if isinstance(resource, str) and resource.strip():
        return resource.strip()[:500]
    if isinstance(resource, dict):
        url = resource.get("url")
        if isinstance(url, str) and url.strip():
            return url.strip()[:500]
    return None


def _opt_str(value: object) -> str | None:
    if isinstance(value, str) and value:
        return value
    return None


def _opt_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


def _dump(parsed: ParsedX402) -> dict:
    return {
        "malformed": parsed.malformed,
        "detail": parsed.detail,
        "canonical": parsed.canonical,
        "resource_url": parsed.resource_url,
        "expires_at": parsed.expires_at,
        "mirror_disagreed": parsed.mirror_disagreed,
        "satsgate_resource": parsed.satsgate_resource,
        "accepts": [
            {
                "scheme": item.scheme,
                "network": item.network,
                "asset": item.asset,
                "amount_atomic": item.amount_atomic,
                "pay_to": item.pay_to,
                "max_timeout_seconds": item.max_timeout_seconds,
                "supported": item.supported,
                "unsupported_reason": item.unsupported_reason,
                "detail": item.detail,
            }
            for item in parsed.accepts
        ],
    }


def payment_response_fields(header: str) -> dict | None:
    """Public settle fields. The raw header is not returned."""
    if not header or any(char in header for char in "\r\n"):
        return None
    try:
        raw = base64.b64decode(header, validate=True)
        parsed = json.loads(raw)
    except (binascii.Error, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    out: dict[str, object] = {}
    success = parsed.get("success")
    if isinstance(success, bool):
        out["success"] = success
    for key in ("transaction", "tx", "network", "payer"):
        value = parsed.get(key)
        if isinstance(value, str) and value and len(value) <= 200 and "\n" not in value and "\r" not in value:
            out[key] = value
    return out or None
