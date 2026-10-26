"""x402 v2 payment requirements for USDC on Base.

Core builds the requirements and checks the buyer's payload against the offer
it stored. The facilitator checks the EIP-3009 signature. This module does
not sign, broadcast, or hold a key.

A site is in one mode. Test offers only Base Sepolia. Live offers only Base.
One 402 never lists both networks.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import time

from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import is_checksum_address, to_checksum_address

from . import config

_REASON = re.compile(r"^[a-z0-9_]{1,64}$")
_HEX_ADDR = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BYTES32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
_SIG = re.compile(r"^0x[0-9a-fA-F]{130}$")
_ATOMIC = re.compile(r"^[1-9][0-9]{0,17}$")

NETWORK_SEPOLIA = "eip155:84532"
NETWORK_BASE = "eip155:8453"
_USDC_BY_NETWORK = {
    NETWORK_SEPOLIA: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    NETWORK_BASE: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
}
# EIP-712 domain name() on each USDC contract. Sepolia is "USDC".
# Base mainnet is "USD Coin". version() is "2" on both. assetTransferMethod
# stays eip3009. A buyer signs this exact object. One dict for both networks
# makes CDP reject a valid mainnet signature.
_EXTRA_BY_NETWORK = {
    NETWORK_SEPOLIA: {"name": "USDC", "version": "2", "assetTransferMethod": "eip3009"},
    NETWORK_BASE: {"name": "USD Coin", "version": "2", "assetTransferMethod": "eip3009"},
}
MODES = frozenset({"test", "live"})
TEST_DESCRIPTION = "Test payment on Base Sepolia. Not Base mainnet."


class X402Error(Exception):
    def __init__(self, code: str, *, reason: str | None = None, status: int = 402) -> None:
        super().__init__(code)
        self.code = code
        self.reason = reason if reason and _REASON.fullmatch(reason) else None
        self.status = status


def public_reason(value: object) -> str | None:
    if isinstance(value, str) and _REASON.fullmatch(value):
        return value
    return None


def checksum_address(value: object) -> str:
    if not isinstance(value, str) or not _HEX_ADDR.fullmatch(value):
        raise X402Error("invalid_address", status=400)
    try:
        return to_checksum_address(value)
    except Exception as exc:  # noqa: BLE001
        raise X402Error("invalid_address", status=400) from exc


def payee_message(*, client_id: int, address: str, nonce: str, expires: int) -> str:
    return (
        "Satsgate x402 payee\n"
        "Domain: satsgate\n"
        f"Client: {int(client_id)}\n"
        f"Address: {address}\n"
        f"Nonce: {nonce}\n"
        f"Expires: {int(expires)}\n"
    )


def payee_message_candidates(message: str) -> tuple[str, ...]:
    """Exact challenge text, plus the same text a wallet UI may actually sign.

    Etherscan and BaseScan trim the trailing newline before MetaMask signs.
    Only trailing whitespace is removed. CRLF is the same line break as LF.
    Nonce, expiry, address, client, and domain bytes are not rewritten.
    """
    if not isinstance(message, str) or not message:
        return ()
    crlf = message.replace("\n", "\r\n")
    ordered = (message, message.rstrip(), crlf, crlf.rstrip())
    unique: list[str] = []
    for item in ordered:
        if item and item not in unique:
            unique.append(item)
    return tuple(unique)


def recover_payee_signer(message: str, signature: str, *, address: str) -> str:
    """Recover the signer of the stored challenge or its trimmed form.

    The recovered address must be the claimed address, ignoring checksum case.
    """
    expected = checksum_address(address)
    for candidate in payee_message_candidates(message):
        try:
            recovered = recover_personal_signer(candidate, signature)
        except X402Error:
            continue
        if recovered.lower() == expected.lower():
            return recovered
    raise X402Error("bad_signature", status=400)


def recover_personal_signer(message: str, signature: str) -> str:
    if not isinstance(signature, str) or not _SIG.fullmatch(signature):
        raise X402Error("bad_signature", status=400)
    try:
        recovered = Account.recover_message(encode_defunct(text=message), signature=signature)
    except Exception as exc:  # noqa: BLE001
        raise X402Error("bad_signature", status=400) from exc
    return to_checksum_address(recovered)


def mainnet_enabled() -> bool:
    return bool(config.X402_MAINNET_ENABLED)


def topup_network() -> str:
    """Credit packs use mainnet USDC only while the operator switch is on.

    Selling credits for faucet USDC is not allowed once real money is on.
    Merchant routes can still be in test mode. That choice is the merchant's.
    """
    return NETWORK_BASE if mainnet_enabled() else NETWORK_SEPOLIA


def network_for_mode(mode: str) -> str:
    if mode == "live":
        return NETWORK_BASE
    if mode == "test":
        return NETWORK_SEPOLIA
    raise X402Error("x402_mode_invalid", status=400)


def mode_labels(network: str) -> dict:
    """Labels for the JSON body. They are not part of the EIP-3009 ``extra``."""
    if network == NETWORK_BASE:
        return {"testing": False, "x402_mode": "live"}
    if network == NETWORK_SEPOLIA:
        return {"testing": True, "x402_mode": "test"}
    raise X402Error("network_mismatch")


def usdc_for_network(network: str) -> str:
    asset = _USDC_BY_NETWORK.get(network)
    if asset is None:
        raise X402Error("network_mismatch")
    return to_checksum_address(asset)


def extra_for_network(network: str) -> dict:
    """EIP-712 extra for that network. Callers must not share the stored dict."""
    extra = _EXTRA_BY_NETWORK.get(network)
    if extra is None:
        raise X402Error("network_mismatch")
    return dict(extra)


def resource_url(slug: str, path: str) -> str:
    return f"{config.GATE_PUBLIC_BASE}/{slug}{path}"


def offer_timeout_seconds() -> int:
    """How long a gate-route or credit-pack offer stays valid.

    ``SATSGATE_X402_OFFER_SECONDS`` is clamped into 60..300 here. A Lightning
    invoice and its macaroon keep their own lifetime. This window does not
    shorten that invoice, and the invoice expiry does not stretch this offer.
    An unpaid Lightning quote occupies the buyer cap only for this same window.
    """
    return min(300, max(60, int(config.X402_OFFER_SECONDS)))


def accept_for(
    *,
    resource_url: str,
    amount: int,
    pay_to: str,
    timeout_seconds: int,
    network: str | None = None,
) -> dict:
    chosen = config.X402_NETWORK if network is None else network
    if chosen == NETWORK_BASE and not mainnet_enabled():
        raise X402Error("x402_mainnet_disabled", status=400)
    if chosen not in _USDC_BY_NETWORK:
        raise X402Error("network_mismatch")
    return {
        "scheme": "exact",
        "network": chosen,
        "amount": str(int(amount)),
        "asset": usdc_for_network(chosen),
        "payTo": pay_to,
        "maxTimeoutSeconds": int(timeout_seconds),
        "extra": extra_for_network(chosen),
    }


def payment_required_document(*, resource_url: str, accept: dict) -> dict:
    description = TEST_DESCRIPTION if accept.get("network") == NETWORK_SEPOLIA else ""
    return {
        "x402Version": 2,
        "resource": {"url": resource_url, "description": description, "mimeType": "application/json"},
        "accepts": [accept],
    }


def b64_json(document: dict) -> str:
    raw = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return base64.standard_b64encode(raw).decode("ascii")


def decode_payment_signature(encoded: str) -> dict:
    if not isinstance(encoded, str) or not encoded.strip():
        raise X402Error("bad_signature")
    try:
        raw = base64.b64decode(encoded.strip(), validate=True)
    except binascii.Error as exc:
        raise X402Error("bad_signature") from exc
    if len(raw) > config.X402_SIGNATURE_MAX_BYTES:
        raise X402Error("bad_signature")
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise X402Error("bad_signature") from exc
    if not isinstance(payload, dict):
        raise X402Error("bad_signature")
    return payload


def _resource_url_of(payload: dict) -> str:
    resource = payload.get("resource")
    if isinstance(resource, str):
        return resource
    if isinstance(resource, dict) and isinstance(resource.get("url"), str):
        return resource["url"]
    raise X402Error("resource_mismatch")


def _atomic(value: object) -> str:
    if isinstance(value, bool) or value is None:
        raise X402Error("amount_mismatch")
    text = str(value).strip()
    if not _ATOMIC.fullmatch(text):
        raise X402Error("amount_mismatch")
    return text


def validate_payload(payload: dict, *, offer: dict, now: int | None = None) -> dict:
    """Check the buyer payload against the stored offer. Does not call the facilitator.

    Returns the authorization fields core will bind to the nonce row.
    """
    now = int(time.time()) if now is None else int(now)
    if int(offer["expires_at"]) <= now:
        raise X402Error("expired")
    if payload.get("x402Version") != 2:
        raise X402Error("bad_signature")
    if _resource_url_of(payload) != offer["resource_url"]:
        raise X402Error("resource_mismatch")
    accepted = payload.get("accepted")
    if not isinstance(accepted, dict):
        raise X402Error("bad_signature")
    if accepted.get("scheme") != "exact":
        raise X402Error("bad_signature")
    network = accepted.get("network")
    requirements = offer.get("requirements") if isinstance(offer.get("requirements"), dict) else {}
    offer_network = offer.get("network") or requirements.get("network")
    if not isinstance(network, str):
        raise X402Error("network_mismatch")
    if network == NETWORK_BASE and not mainnet_enabled():
        raise X402Error("network_mismatch")
    if network not in _USDC_BY_NETWORK:
        raise X402Error("network_mismatch")
    if network != offer_network or (requirements.get("network") and network != requirements.get("network")):
        raise X402Error("network_mismatch")
    expected_asset = usdc_for_network(network)
    try:
        asset = checksum_address(accepted.get("asset"))
    except X402Error:
        raise X402Error("asset_mismatch") from None
    if asset != expected_asset:
        raise X402Error("asset_mismatch")
    if requirements.get("asset"):
        try:
            stored_asset = checksum_address(requirements.get("asset"))
        except X402Error:
            raise X402Error("asset_mismatch") from None
        if stored_asset != expected_asset:
            raise X402Error("asset_mismatch")
    try:
        pay_to = checksum_address(accepted.get("payTo"))
    except X402Error:
        raise X402Error("payto_mismatch") from None
    if pay_to != offer["pay_to"]:
        raise X402Error("payto_mismatch")
    amount = _atomic(accepted.get("amount"))
    if amount != str(int(offer["amount_usd_atomic"])):
        raise X402Error("amount_mismatch")
    if accepted.get("extra") != extra_for_network(network):
        raise X402Error("bad_signature")
    inner = payload.get("payload")
    if not isinstance(inner, dict):
        raise X402Error("bad_signature")
    signature = inner.get("signature")
    if not isinstance(signature, str) or not _SIG.fullmatch(signature):
        raise X402Error("bad_signature")
    authorization = inner.get("authorization")
    if not isinstance(authorization, dict):
        raise X402Error("bad_signature")
    try:
        payer = checksum_address(authorization.get("from"))
    except X402Error:
        raise X402Error("bad_signature") from None
    if not is_checksum_address(str(authorization.get("from"))):
        raise X402Error("bad_signature")
    try:
        destination = checksum_address(authorization.get("to"))
    except X402Error:
        raise X402Error("payto_mismatch") from None
    if destination != pay_to:
        raise X402Error("payto_mismatch")
    value = _atomic(authorization.get("value"))
    if value != amount:
        raise X402Error("amount_mismatch")
    nonce = authorization.get("nonce")
    if not isinstance(nonce, str) or not _BYTES32.fullmatch(nonce):
        raise X402Error("bad_signature")
    try:
        valid_before = int(str(authorization.get("validBefore")))
        valid_after = int(str(authorization.get("validAfter")))
    except (TypeError, ValueError) as exc:
        raise X402Error("expired") from exc
    if valid_after > now or valid_before > int(offer["expires_at"]) or valid_before <= now:
        raise X402Error("expired")
    return {
        "payer": payer,
        "nonce": nonce.lower(),
        "value": value,
        "pay_to": pay_to,
        "network": network,
        "asset": expected_asset,
    }


def payment_response_b64(*, tx: str, payer: str, network: str | None = None) -> str:
    """x402 v2 settlement response.

    Spec field is ``transaction`` (coinbase/x402 ``specs/x402-specification-v2.md``,
    section 5.3). ``tx`` repeats the same hash for one release.
    """
    return b64_json(
        {
            "success": True,
            "transaction": tx,
            "tx": tx,
            "network": network or config.X402_NETWORK,
            "payer": payer,
        }
    )
