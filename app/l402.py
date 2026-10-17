from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
from collections.abc import Mapping
from dataclasses import dataclass

from pymacaroons import Macaroon, Verifier
from pymacaroons.macaroon import MACAROON_V2
from pymacaroons.serializers.binary_serializer import BinarySerializer

TOKEN_VERSION = 2
# Lightning Labs L402 identifier version (uint16). Distinct from TOKEN_VERSION.
L402_IDENTIFIER_VERSION = 0
PURPOSE_PAYWALL = "paywall"
PURPOSE_TOPUP = "topup"
PURPOSE_TICKET = "ticket"

_PURPOSES = frozenset({PURPOSE_PAYWALL, PURPOSE_TOPUP, PURPOSE_TICKET})
_CAVEAT_KEYS = frozenset({"v", "kid", "purpose", "cid", "ph", "res", "amt", "payee_h", "inv_h", "exp"})
_REQUIRED_CAVEATS = frozenset({"v", "kid", "purpose", "ph", "res", "amt", "payee_h", "inv_h", "exp"})
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_DIGITS = re.compile(r"^(0|[1-9][0-9]{0,17})$")
# Alby's fetch402 strips the first "L402" and the first "LSAT" from the whole
# header. A macaroon whose base64 contains either substring would be corrupted.
_ALBY_HEADER_TOKENS = ("L402", "LSAT")


@dataclass(frozen=True)
class L402Challenge:
    macaroon: str  # base64
    invoice: str  # bolt11 (or mock)
    payment_hash: str  # hex


class L402Error(Exception):
    pass


def payee_binding(payee: str | None) -> str:
    """Stable hash of the Lightning Address this challenge pays."""
    normalized = (payee or "").strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def invoice_binding(invoice: str) -> str:
    return hashlib.sha256(invoice.encode("utf-8")).hexdigest()


def www_authenticate_header(*, macaroon: str, invoice: str) -> str:
    """Challenge header lnget and fetch402 both parse.

    lnget's regex requires `macaroon` before `invoice`. The macaroon is
    standard base64 (Aperture's credential grammar rejects url-safe `-`/`_`).
    """
    if any(c in macaroon or c in invoice for c in '"\r\n'):
        raise L402Error("invalid macaroon")
    return f'L402 macaroon="{macaroon}", invoice="{invoice}"'


def _decode_token(token: str) -> bytes:
    compact = "".join(str(token).split())
    if not compact:
        raise L402Error("invalid macaroon")
    padded = compact + ("=" * ((4 - (len(compact) % 4)) % 4))
    try:
        if any(char in compact for char in "-_"):
            return base64.urlsafe_b64decode(padded)
        return base64.b64decode(padded, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise L402Error("invalid macaroon") from exc


def _l402_identifier(payment_hash: str, token_id: bytes) -> bytes:
    """Aperture/lnget identifier: uint16 version, 32-byte payment hash, 32-byte token id."""
    if len(token_id) != 32 or not _HEX64.fullmatch(payment_hash):
        raise L402Error("invalid payment_hash")
    return struct.pack(">H", L402_IDENTIFIER_VERSION) + bytes.fromhex(payment_hash) + token_id


def _mint_macaroon_b64(
    *,
    secret: str,
    kid: str,
    purpose: str,
    payment_hash: str,
    resource: str,
    amount_sats: int,
    invoice: str,
    ttl_seconds: int,
    client_id: int | None,
    payee: str | None,
    exp: int | None = None,
) -> str:
    token_id = secrets.token_bytes(32)
    mac = Macaroon(
        location="satsgate",
        identifier=_l402_identifier(payment_hash.lower(), token_id),
        key=secret,
        version=MACAROON_V2,
    )
    expiry = int(time.time()) + int(ttl_seconds) if exp is None else int(exp)
    caveats = [
        f"v={TOKEN_VERSION}",
        f"kid={kid}",
        f"purpose={purpose}",
        f"ph={payment_hash.lower()}",
        f"res={resource}",
        f"amt={int(amount_sats)}",
        f"payee_h={payee_binding(payee)}",
        f"inv_h={invoice_binding(invoice)}",
        f"exp={expiry}",
    ]
    if client_id is not None:
        caveats.append(f"cid={int(client_id)}")
    for caveat in caveats:
        mac.add_first_party_caveat(caveat)
    raw = BinarySerializer().serialize_raw(mac)
    # Standard base64 with padding. Aperture accepts [A-Za-z0-9+/=] only.
    return base64.standard_b64encode(raw).decode("ascii")


def make_macaroon(
    *,
    secret: str,
    kid: str,
    purpose: str,
    payment_hash: str,
    resource: str,
    amount_sats: int,
    invoice: str,
    ttl_seconds: int,
    client_id: int | None,
    payee: str | None,
    exp: int | None = None,
) -> str:
    """Mint a real macaroon whose caveats carry the v2 bindings.

    The identifier is the L402 v0 binary form so lnget can read the payment
    hash. v1 JSON tokens are not issued. In-flight v2 JSON tokens still verify.

    `exp`, when set, is the absolute unix expiry written into the caveat.
    Otherwise the caveat is `now + ttl_seconds`.
    """
    if purpose not in _PURPOSES:
        raise L402Error("invalid purpose")
    if not isinstance(payment_hash, str) or not _HEX64.fullmatch(payment_hash):
        raise L402Error("invalid payment_hash")
    if purpose == PURPOSE_PAYWALL and client_id is None:
        raise L402Error("paywall token requires client_id")
    if not isinstance(resource, str):
        raise L402Error("resource mismatch")

    for _ in range(8):
        token = _mint_macaroon_b64(
            secret=secret,
            kid=kid,
            purpose=purpose,
            payment_hash=payment_hash,
            resource=resource,
            amount_sats=amount_sats,
            invoice=invoice,
            ttl_seconds=ttl_seconds,
            client_id=client_id,
            payee=payee,
            exp=exp,
        )
        if not any(marker in token for marker in _ALBY_HEADER_TOKENS):
            return token
    raise L402Error("invalid macaroon")


def _require_hex64(value: object, label: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise L402Error(f"invalid {label}")
    return value.lower()


def _require_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise L402Error(f"invalid {label}")
    return value


def _caveat_text(caveat: object) -> str:
    raw = getattr(caveat, "caveat_id_bytes", None)
    if raw is None:
        raw = getattr(caveat, "caveat_id", None)
    if isinstance(raw, str):
        return raw
    if isinstance(raw, bytes):
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise L402Error("invalid macaroon") from exc
    raise L402Error("invalid macaroon")


def _bindings_from_macaroon(mac: Macaroon) -> dict:
    """Read v2 bindings from a deserialized macaroon. Does not check the signature."""
    if mac.third_party_caveats():
        raise L402Error("invalid macaroon")

    fields: dict[str, str] = {}
    for caveat in mac.first_party_caveats():
        text = _caveat_text(caveat)
        if "=" not in text:
            raise L402Error("invalid macaroon")
        key, value = text.split("=", 1)
        if key not in _CAVEAT_KEYS or key in fields:
            raise L402Error("invalid macaroon")
        fields[key] = value

    if not _REQUIRED_CAVEATS.issubset(fields):
        raise L402Error("invalid macaroon")

    try:
        version = int(fields["v"])
    except ValueError as exc:
        raise L402Error("invalid macaroon") from exc
    if isinstance(version, bool):
        raise L402Error("invalid macaroon")

    identifier = bytes(mac.identifier_bytes)
    if len(identifier) != 2 + 32 + 32:
        raise L402Error("invalid macaroon")
    id_version = struct.unpack(">H", identifier[:2])[0]
    if id_version != L402_IDENTIFIER_VERSION:
        raise L402Error("invalid macaroon")
    payment_hash = identifier[2:34].hex()
    token_id = identifier[34:66].hex()
    if not _HEX64.fullmatch(fields["ph"]) or fields["ph"].lower() != payment_hash:
        raise L402Error("invalid macaroon")

    if not _DIGITS.fullmatch(fields["amt"]) or not _DIGITS.fullmatch(fields["exp"]):
        raise L402Error("invalid macaroon")
    if not _HEX64.fullmatch(fields["payee_h"]) or not _HEX64.fullmatch(fields["inv_h"]):
        raise L402Error("invalid macaroon")
    if fields["purpose"] not in _PURPOSES or not fields["kid"] or not fields["res"]:
        raise L402Error("invalid macaroon")

    cid: int | None = None
    if "cid" in fields:
        if not _DIGITS.fullmatch(fields["cid"]):
            raise L402Error("invalid macaroon")
        cid = int(fields["cid"])

    return {
        "v": version,
        "kid": fields["kid"],
        "purpose": fields["purpose"],
        "cid": cid,
        "ph": fields["ph"].lower(),
        "res": fields["res"],
        "amt": int(fields["amt"]),
        "payee_h": fields["payee_h"].lower(),
        "inv_h": fields["inv_h"].lower(),
        "exp": int(fields["exp"]),
        "nonce": token_id,
    }


def peek_bindings(macaroon_b64: str) -> dict:
    """Read bindings without checking the signature.

    Used by tests and by callers that need the resource name before verify.
    Authorization decisions must use parse_and_verify_macaroon.
    """
    raw = _decode_token(macaroon_b64)
    if raw.startswith(b"{"):
        try:
            payload_bytes, _sig = raw.rsplit(b".", 1)
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise L402Error("invalid macaroon") from exc
        if not isinstance(payload, dict):
            raise L402Error("invalid macaroon")
        return payload
    if raw[:1] != b"\x02":
        raise L402Error("invalid macaroon")
    try:
        mac = Macaroon.deserialize("".join(macaroon_b64.split()))
    except Exception as exc:  # noqa: BLE001
        raise L402Error("invalid macaroon") from exc
    return _bindings_from_macaroon(mac)


def _check_context(
    payload: dict,
    *,
    purpose: str,
    resource: str,
    client_id: int | None,
    skip_expiry: bool,
) -> None:
    if payload.get("v") != TOKEN_VERSION:
        raise L402Error("unsupported version")
    if payload.get("purpose") != purpose:
        raise L402Error("purpose mismatch")
    if not resource or payload.get("res") != resource:
        raise L402Error("resource mismatch")

    exp = _require_int(payload.get("exp"), "exp")
    if not skip_expiry and int(time.time()) > exp:
        raise L402Error("token expired")

    _require_hex64(payload.get("ph"), "payment_hash")
    _require_hex64(payload.get("payee_h"), "payee")
    _require_hex64(payload.get("inv_h"), "invoice")
    _require_int(payload.get("amt"), "amount")

    cid = payload.get("cid")
    if purpose == PURPOSE_PAYWALL:
        if client_id is None:
            raise L402Error("client mismatch")
        if isinstance(cid, bool) or not isinstance(cid, int) or int(cid) != int(client_id):
            raise L402Error("client mismatch")
    elif cid is not None:
        if isinstance(cid, bool) or not isinstance(cid, int):
            raise L402Error("client mismatch")
        if client_id is not None and int(cid) != int(client_id):
            raise L402Error("client mismatch")


def _parse_json_macaroon(
    *,
    keys: Mapping[str, str],
    raw: bytes,
    purpose: str,
    resource: str,
    client_id: int | None,
    skip_expiry: bool,
) -> dict:
    """Verify an in-flight v2 JSON token minted before macaroons were issued."""
    try:
        payload_bytes, sig_bytes = raw.rsplit(b".", 1)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise L402Error("invalid macaroon") from exc

    if not isinstance(payload, dict):
        raise L402Error("invalid macaroon")

    def _sig_ok(secret: str) -> bool:
        expected_sig = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest().encode("ascii")
        if len(sig_bytes) != len(expected_sig):
            return False
        return hmac.compare_digest(expected_sig, sig_bytes)

    kid = payload.get("kid")
    if isinstance(kid, str) and kid in keys:
        signed = _sig_ok(keys[kid])
    else:
        # No usable kid (v1 tokens omit it). A MAC under a configured key still
        # counts so the version check below can reject it as unsupported.
        signed = any(_sig_ok(secret) for secret in keys.values())
    if not signed:
        raise L402Error("invalid signature")

    _check_context(
        payload,
        purpose=purpose,
        resource=resource,
        client_id=client_id,
        skip_expiry=skip_expiry,
    )
    payload["ph"] = str(payload["ph"]).lower()
    payload["payee_h"] = str(payload["payee_h"]).lower()
    payload["inv_h"] = str(payload["inv_h"]).lower()
    return payload


def _parse_real_macaroon(
    *,
    keys: Mapping[str, str],
    macaroon_b64: str,
    purpose: str,
    resource: str,
    client_id: int | None,
    skip_expiry: bool,
) -> dict:
    try:
        mac = Macaroon.deserialize("".join(macaroon_b64.split()))
    except Exception as exc:  # noqa: BLE001
        raise L402Error("invalid macaroon") from exc

    payload = _bindings_from_macaroon(mac)
    kid = payload["kid"]
    secret = keys.get(kid) if isinstance(kid, str) else None
    if not isinstance(secret, str) or not secret:
        raise L402Error("invalid signature")

    verifier = Verifier()
    # Caveat policy is enforced below from the signed fields. The verifier's
    # job here is the HMAC chain, which already covers every caveat.
    verifier.satisfy_general(lambda _predicate: True)
    try:
        verifier.verify(mac, secret)
    except Exception as exc:  # noqa: BLE001
        raise L402Error("invalid signature") from exc

    _check_context(
        payload,
        purpose=purpose,
        resource=resource,
        client_id=client_id,
        skip_expiry=skip_expiry,
    )
    return payload


def parse_and_verify_macaroon(
    *,
    keys: Mapping[str, str],
    macaroon_b64: str,
    purpose: str,
    resource: str,
    client_id: int | None = None,
    skip_expiry: bool = False,
) -> dict:
    """Verify a v2 macaroon (or an in-flight v2 JSON token).

    Resource is required. Paywall checks also pass client_id. `client_id` when
    provided must equal the signed `cid`. A token minted for one client never
    verifies for another.

    `skip_expiry` still checks the signature and every binding. Top-up and
    paywall claims set it so a macaroon minted with the old 10-minute TTL can
    finish while the stored invoice window is still open. The caller then
    enforces that window. Ticket checks leave it false.
    """
    if not resource:
        raise L402Error("resource mismatch")

    raw = _decode_token(macaroon_b64)
    if raw.startswith(b"{"):
        return _parse_json_macaroon(
            keys=keys,
            raw=raw,
            purpose=purpose,
            resource=resource,
            client_id=client_id,
            skip_expiry=skip_expiry,
        )
    if raw[:1] == b"\x02":
        return _parse_real_macaroon(
            keys=keys,
            macaroon_b64=macaroon_b64,
            purpose=purpose,
            resource=resource,
            client_id=client_id,
            skip_expiry=skip_expiry,
        )
    raise L402Error("invalid macaroon")


def parse_authorization_header(auth: str | None) -> tuple[str, str | None]:
    """Return `(macaroon, preimage_hex)`.

    Accepts `L402` and legacy `LSAT`. The preimage is omitted for a
    macaroon-only claim (`L402 <macaroon>`), which the server can settle only
    from a stored LUD-21 verify URL.
    """
    if not auth or not str(auth).strip():
        raise L402Error("missing credentials")

    try:
        scheme, token = str(auth).strip().split(None, 1)
    except ValueError as exc:
        raise L402Error("malformed Authorization header") from exc

    if scheme.lower() not in {"l402", "lsat"}:
        raise L402Error("scheme is not L402")

    token = token.strip()
    if ":" in token:
        macaroon_b64, preimage_hex = token.split(":", 1)
    else:
        macaroon_b64, preimage_hex = token, ""

    if not macaroon_b64 or any(char.isspace() for char in macaroon_b64):
        raise L402Error("malformed L402 token")

    if preimage_hex == "":
        return macaroon_b64, None

    try:
        raw = bytes.fromhex(preimage_hex)
    except ValueError as exc:
        raise L402Error("preimage is not hex") from exc
    if len(raw) != 32:
        raise L402Error("preimage is not hex")

    return macaroon_b64, preimage_hex.lower()


def verify_preimage_matches_payment_hash(*, preimage_hex: str, payment_hash: str) -> None:
    preimage = bytes.fromhex(preimage_hex)
    got = hashlib.sha256(preimage).hexdigest()
    if got != payment_hash.lower():
        raise L402Error("preimage does not match payment_hash")
