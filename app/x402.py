"""x402 v2 payment requirements for USDC on Base Sepolia.

Core builds the requirements and checks the buyer's payload against the offer
it stored. The facilitator checks the EIP-3009 signature. This module does
not sign, broadcast, or hold a key.
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

EXTRA = {"name": "USDC", "version": "2", "assetTransferMethod": "eip3009"}


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


def usdc_for_network(network: str) -> str:
    if network != config.X402_NETWORK:
        raise X402Error("network_mismatch")
    return to_checksum_address(config.X402_USDC)


def resource_url(slug: str, path: str) -> str:
    return f"{config.GATE_PUBLIC_BASE}/{slug}{path}"


def accept_for(*, resource_url: str, amount: int, pay_to: str, timeout_seconds: int) -> dict:
    return {
        "scheme": "exact",
        "network": config.X402_NETWORK,
        "amount": str(int(amount)),
        "asset": to_checksum_address(config.X402_USDC),
        "payTo": pay_to,
        "maxTimeoutSeconds": int(timeout_seconds),
        "extra": dict(EXTRA),
    }


def payment_required_document(*, resource_url: str, accept: dict) -> dict:
    return {
        "x402Version": 2,
        "resource": {"url": resource_url, "description": "", "mimeType": "application/json"},
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
    if network != config.X402_NETWORK:
        raise X402Error("network_mismatch")
    try:
        asset = checksum_address(accepted.get("asset"))
    except X402Error:
        raise X402Error("asset_mismatch") from None
    if asset != to_checksum_address(config.X402_USDC):
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
    if accepted.get("extra") != EXTRA:
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
        "network": config.X402_NETWORK,
        "asset": to_checksum_address(config.X402_USDC),
    }


def payment_response_b64(*, tx: str, payer: str) -> str:
    return b64_json(
        {
            "success": True,
            "tx": tx,
            "network": config.X402_NETWORK,
            "payer": payer,
        }
    )
