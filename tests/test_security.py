"""Security regressions for stage 0.

The cross-tenant test is the 1-sat bypass: an attacker mints a challenge for the
victim's resource against the attacker's own account, pays it, and presents that
token to the victim's verify. It must fail and must not spend the victim's credits.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_app(tmp_path: Path, **env: str):
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))

    base = {
        "SATSGATE_ENV": "development",
        "SATSGATE_WALLET_MODE": "mock",
        "SATSGATE_DEV_MODE": "1",
        "SATSGATE_RL_ENABLED": "0",
        "SATSGATE_MACAROON_SECRET": "test-secret",
        "SATSGATE_MACAROON_KEY_ID": "1",
        "SATSGATE_MACAROON_PREVIOUS_KEYS": "",
        "SATSGATE_DB_PATH": str(tmp_path / "satsgate_test.sqlite3"),
        "SATSGATE_ADMIN_TOKEN": "test-admin-token",
        "SATSGATE_TRUSTED_PROXIES": "",
        "SATSGATE_LN_NETWORK": "mainnet",
        "SATSGATE_RL_WINDOW_SECONDS": "60",
        "SATSGATE_RL_MAX_ANON": "60",
        "SATSGATE_RL_MAX_AUTH": "600",
        "SATSGATE_RL_MAX_CHALLENGE": "30",
        "SATSGATE_RL_MAX_TOPUP": "10",
        "SATSGATE_RL_MAX_KEYS": "10000",
    }
    base.update(env)
    for key, value in base.items():
        os.environ[key] = value

    for name in list(sys.modules.keys()):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)

    return importlib.import_module("app.main")


def _auth(macaroon: str, preimage_hex: str) -> str:
    return f"L402 {macaroon}:{preimage_hex}"


def _buy_client(client) -> str:
    started = client.get("/v1/topup/trial")
    assert started.status_code == 402, started.text
    body = started.json()
    preimage = client.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
    settled = client.get("/v1/topup/trial", headers={"Authorization": _auth(body["macaroon"], preimage)})
    assert settled.status_code == 200, settled.text
    return settled.json()["api_key"]


def _challenge(client, api_key: str, *, resource: str, amount_sats: int = 1) -> dict:
    response = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": api_key},
        json={"resource": resource, "amount_sats": amount_sats},
    )
    assert response.status_code == 200, response.text
    return response.json()


def _pay(client, challenge: dict) -> str:
    paid = client.get(f"/dev/mock/pay/{challenge['payment_hash']}")
    assert paid.status_code == 200, paid.text
    return _auth(challenge["macaroon"], paid.json()["preimage"])


@pytest.fixture()
def client(tmp_path):
    from fastapi.testclient import TestClient

    module = _load_app(tmp_path)
    with TestClient(module.app) as http:
        yield http


def test_one_sat_cross_tenant_token_does_not_verify(client):
    """Regression: paying yourself 1 sat must not unlock another merchant's resource."""
    resource = "api/premium"
    victim_key = _buy_client(client)
    attacker_key = _buy_client(client)

    victim_before = client.get("/v1/balance", headers={"X-Api-Key": victim_key}).json()["credits"]
    attacker_before = client.get("/v1/balance", headers={"X-Api-Key": attacker_key}).json()["credits"]

    # The attacker chooses the victim's public resource name and the minimum amount.
    stolen = _challenge(client, attacker_key, resource=resource, amount_sats=1)
    stolen_auth = _pay(client, stolen)

    padded = stolen["macaroon"] + "=" * ((4 - len(stolen["macaroon"]) % 4) % 4)
    payload_raw = base64.urlsafe_b64decode(padded)
    payload = json.loads(payload_raw.split(b".", 1)[0])
    assert payload["v"] == 2
    assert payload["cid"] != client.get("/v1/client", headers={"X-Api-Key": victim_key}).json()["client_id"]
    assert "amt" in payload and payload["amt"] == 1
    assert "payee_h" in payload and "inv_h" in payload

    rejected = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": victim_key, "Authorization": stolen_auth},
        json={"expected_resource": resource, "cost_credits": 1},
    )
    assert rejected.status_code == 401
    assert rejected.json()["error"] == "client mismatch"

    victim_after = client.get("/v1/balance", headers={"X-Api-Key": victim_key}).json()["credits"]
    assert victim_after == victim_before

    # The same token is a real payment for the account that minted it.
    accepted = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": attacker_key, "Authorization": stolen_auth},
        json={"expected_resource": resource, "cost_credits": 1},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["charged_credits"] == 1
    attacker_after = client.get("/v1/balance", headers={"X-Api-Key": attacker_key}).json()["credits"]
    assert attacker_after == attacker_before - 1


def test_resource_is_required_and_must_match(client):
    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/premium", amount_sats=5)
    auth = _pay(client, challenge)
    before = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]

    missing = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": auth},
        json={"cost_credits": 1},
    )
    assert missing.status_code == 422

    mismatched = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": auth},
        json={"expected_resource": "api/other", "cost_credits": 1},
    )
    assert mismatched.status_code == 401
    assert mismatched.json()["error"] == "resource mismatch"

    after = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]
    assert after == before


def test_bad_preimage_expired_token_and_bad_signature_are_rejected(client):
    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/premium")
    preimage = client.get(f"/dev/mock/pay/{challenge['payment_hash']}").json()["preimage"]
    before = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]

    flipped = ("0" if preimage[0] != "0" else "1") + preimage[1:]
    bad_preimage = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": _auth(challenge["macaroon"], flipped)},
        json={"expected_resource": "api/premium"},
    )
    assert bad_preimage.status_code == 401
    assert bad_preimage.json()["error"] == "preimage does not match payment_hash"

    padded = challenge["macaroon"] + "=" * ((4 - len(challenge["macaroon"]) % 4) % 4)
    raw = bytearray(base64.urlsafe_b64decode(padded))
    raw[-2] ^= 0x01
    tampered = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    bad_sig = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": _auth(tampered, preimage)},
        json={"expected_resource": "api/premium"},
    )
    assert bad_sig.status_code == 401
    assert bad_sig.json()["error"] == "invalid signature"

    from app import config, l402

    client_id = client.get("/v1/client", headers={"X-Api-Key": api_key}).json()["client_id"]
    expired = l402.make_macaroon(
        secret=config.MACAROON_SECRET,
        kid=config.MACAROON_KEY_ID,
        purpose=l402.PURPOSE_PAYWALL,
        payment_hash=challenge["payment_hash"],
        resource="api/premium",
        amount_sats=1,
        invoice=challenge["invoice"],
        ttl_seconds=-30,
        client_id=client_id,
        payee=None,
    )
    expired_res = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": _auth(expired, preimage)},
        json={"expected_resource": "api/premium"},
    )
    assert expired_res.status_code == 401
    assert expired_res.json()["error"] == "token expired"

    after = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]
    assert after == before


def test_v1_token_is_rejected(client):
    api_key = _buy_client(client)
    payload = {
        "v": 1,
        "ph": "ab" * 32,
        "res": "api/premium",
        "exp": int(time.time()) + 600,
        "nonce": "legacy",
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
    token = base64.urlsafe_b64encode(body + b"." + sig.encode()).decode().rstrip("=")
    preimage = "11" * 32
    response = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": _auth(token, preimage)},
        json={"expected_resource": "api/premium"},
    )
    assert response.status_code == 401
    assert response.json()["error"] == "unsupported version"


def test_tickets_demo_still_works_in_local_dev(client):
    challenge = client.get("/v1/tickets")
    assert challenge.status_code == 402
    body = challenge.json()
    preimage = client.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
    granted = client.get("/v1/tickets", headers={"Authorization": _auth(body["macaroon"], preimage)})
    assert granted.status_code == 200, granted.text
    assert granted.json()["ok"] is True


def test_previous_signing_key_verifies_and_unknown_key_does_not():
    from app import l402

    macaroon = l402.make_macaroon(
        secret="old-secret",
        kid="1",
        purpose=l402.PURPOSE_PAYWALL,
        payment_hash="ab" * 32,
        resource="api/premium",
        amount_sats=21,
        invoice="lnmock",
        ttl_seconds=60,
        client_id=4,
        payee="merchant@pay.example",
    )
    keys = {"2": "current-secret", "1": "old-secret"}
    payload = l402.parse_and_verify_macaroon(
        keys=keys,
        macaroon_b64=macaroon,
        purpose=l402.PURPOSE_PAYWALL,
        resource="api/premium",
        client_id=4,
    )
    assert payload["kid"] == "1"
    assert payload["amt"] == 21
    with pytest.raises(l402.L402Error):
        l402.parse_and_verify_macaroon(
            keys={"2": "current-secret"},
            macaroon_b64=macaroon,
            purpose=l402.PURPOSE_PAYWALL,
            resource="api/premium",
            client_id=4,
        )


def test_health_does_not_leak_internals(client):
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"ok", "version"}
    assert body["ok"] is True
    assert body["version"] == "0.3.0"
    serialized = json.dumps(body).lower()
    assert "sqlite" not in serialized
    assert "db_path" not in serialized
    assert "lightning" not in serialized
    assert "secret" not in serialized


def test_dev_routes_hidden_without_dev_mode(tmp_path):
    from fastapi.testclient import TestClient

    module = _load_app(tmp_path, SATSGATE_DEV_MODE="0")
    with TestClient(module.app) as http:
        assert http.get("/dev/mock/pay/abcd").status_code == 404
        assert http.get("/v1/tickets").status_code == 404
        assert http.post("/v1/spend").status_code == 404
        health = http.get("/health").json()
        assert "db_path" not in health


def test_invalid_api_key_does_not_get_its_own_bucket(tmp_path):
    from fastapi.testclient import TestClient

    shared = _load_app(
        tmp_path,
        SATSGATE_RL_ENABLED="1",
        SATSGATE_RL_MAX_ANON="2",
        SATSGATE_RL_MAX_AUTH="50",
        SATSGATE_RL_MAX_TOPUP="20",
    )
    with TestClient(shared.app) as http:
        first = http.get("/v1/balance", headers={"X-Api-Key": "sg_unknown-a"})
        second = http.get("/v1/balance", headers={"X-Api-Key": "sg_unknown-b"})
        third = http.get("/v1/balance", headers={"X-Api-Key": "sg_unknown-c"})
        assert first.status_code == 401
        assert second.status_code == 401
        # A third distinct unknown key shares the IP bucket instead of opening another auth bucket.
        assert third.status_code == 429

    isolated = _load_app(
        tmp_path,
        SATSGATE_RL_ENABLED="1",
        SATSGATE_RL_MAX_ANON="30",
        SATSGATE_RL_MAX_AUTH="2",
        SATSGATE_RL_MAX_TOPUP="20",
    )
    with TestClient(isolated.app) as http:
        api_key = _buy_client(http)
        for i in range(5):
            rejected = http.get("/v1/balance", headers={"X-Api-Key": f"sg_not-a-real-key-{i}"})
            assert rejected.status_code == 401

        first = http.get("/v1/balance", headers={"X-Api-Key": api_key})
        second = http.get("/v1/balance", headers={"X-Api-Key": api_key})
        third = http.get("/v1/balance", headers={"X-Api-Key": api_key})
        assert first.status_code == 200
        assert second.status_code == 200
        assert third.status_code == 429


def test_forwarded_for_is_ignored_unless_peer_is_trusted(tmp_path):
    from fastapi.testclient import TestClient

    module = _load_app(
        tmp_path,
        SATSGATE_RL_ENABLED="1",
        SATSGATE_RL_MAX_ANON="1",
        SATSGATE_RL_MAX_TOPUP="50",
        SATSGATE_TRUSTED_PROXIES="",
    )
    with TestClient(module.app) as http:
        first = http.get("/v1/plans", headers={"X-Forwarded-For": "1.1.1.1"})
        second = http.get("/v1/plans", headers={"X-Forwarded-For": "8.8.8.8"})
        assert first.status_code == 200
        assert second.status_code == 429

    module = _load_app(
        tmp_path,
        SATSGATE_RL_ENABLED="1",
        SATSGATE_RL_MAX_ANON="1",
        SATSGATE_RL_MAX_TOPUP="50",
        SATSGATE_TRUSTED_PROXIES="testclient",
    )
    with TestClient(module.app) as http:
        one = http.get("/v1/plans", headers={"X-Forwarded-For": "1.1.1.1"})
        one_again = http.get("/v1/plans", headers={"X-Forwarded-For": "1.1.1.1"})
        other = http.get("/v1/plans", headers={"X-Forwarded-For": "8.8.8.8"})
        garbage = http.get("/v1/plans", headers={"X-Forwarded-For": "not-an-ip"})
        assert one.status_code == 200
        assert one_again.status_code == 429
        assert other.status_code == 200
        # Unparseable forwarded values fall back to the proxy peer, which is a new bucket here.
        assert garbage.status_code == 200


def test_rate_limiter_bounds_tracked_keys():
    from app.rate_limit import RateLimiter

    limiter = RateLimiter(window_seconds=60, max_requests=5, max_keys=3)
    for i in range(10):
        assert limiter.allow(f"ip:{i}")[0] is True
    assert limiter.tracked_keys() <= 3


def test_concurrent_verify_charges_once(client):
    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/premium", amount_sats=3)
    client.get(f"/dev/mock/pay/{challenge['payment_hash']}")
    from app import config, db_verify

    client_id = client.get("/v1/client", headers={"X-Api-Key": api_key}).json()["client_id"]
    before = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]
    barrier = threading.Barrier(2)
    results: list[dict] = []
    errors: list[BaseException] = []

    def _once() -> None:
        try:
            barrier.wait(timeout=5)
            results.append(
                db_verify.verify_once_and_spend(
                    config.DB_PATH,
                    client_id=client_id,
                    payment_hash=challenge["payment_hash"],
                    cost=1,
                    resource="api/premium",
                )
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_once) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert errors == []
    assert sum(item["charged"] for item in results) == 1
    after = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]
    assert after == before - 1


def test_lud21_is_optional_and_enforced_when_advertised(client):
    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/premium")
    preimage = client.get(f"/dev/mock/pay/{challenge['payment_hash']}").json()["preimage"]
    auth = _auth(challenge["macaroon"], preimage)
    before = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]

    from app import config, db

    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE paywall_challenges SET verify_url = ? WHERE payment_hash = ?",
            ("https://ln.example/verify/" + challenge["payment_hash"], challenge["payment_hash"]),
        )

    from app import wallet_lnaddr
    from app.invoices import InvoiceValidationError

    def _not_settled(**_kwargs):
        raise InvoiceValidationError("lud21_not_settled")

    original = wallet_lnaddr.confirm_lud21
    wallet_lnaddr.confirm_lud21 = _not_settled
    try:
        rejected = client.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": api_key, "Authorization": auth},
            json={"expected_resource": "api/premium"},
        )
    finally:
        wallet_lnaddr.confirm_lud21 = original

    assert rejected.status_code == 401
    assert rejected.json()["error"] == "lud21_not_settled"
    assert client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"] == before

    def _settled(**_kwargs):
        return None

    wallet_lnaddr.confirm_lud21 = _settled
    try:
        accepted = client.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": api_key, "Authorization": auth},
            json={"expected_resource": "api/premium"},
        )
    finally:
        wallet_lnaddr.confirm_lud21 = original

    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["charged_credits"] == 1
    # A repeat does not call LUD-21 again and does not charge.
    wallet_lnaddr.confirm_lud21 = _not_settled
    try:
        again = client.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": api_key, "Authorization": auth},
            json={"expected_resource": "api/premium"},
        )
    finally:
        wallet_lnaddr.confirm_lud21 = original
    assert again.status_code == 200, again.text
    assert again.json()["charged_credits"] == 0


def _resolver(mapping: dict[str, str]):
    def _lookup(host, port, *_args, **_kwargs):
        ip = mapping.get(str(host).lower().rstrip("."))
        if ip is None:
            raise socket.gaierror(host)
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sockaddr = (ip, port, 0, 0) if family == socket.AF_INET6 else (ip, port)
        return [(family, socket.SOCK_STREAM, 6, "", sockaddr)]

    return _lookup


def _metadata() -> str:
    return '[["text/plain","satsgate"]]'


def _bolt11(
    *,
    amount_sats: int | None = 1,
    metadata: str | None = None,
    currency: str = "bc",
    expiry: int = 3600,
    timestamp: int | None = None,
    description_hash: str | None = None,
) -> str:
    import os

    from bolt11 import Bolt11, MilliSatoshi, Tags, encode
    from bolt11.models.tags import TagChar

    meta = _metadata() if metadata is None else metadata
    tags = Tags()
    tags.add(TagChar.payment_hash, os.urandom(32).hex())
    tags.add(TagChar.payment_secret, os.urandom(32).hex())
    tags.add(TagChar.description_hash, description_hash or hashlib.sha256(meta.encode()).hexdigest())
    tags.add(TagChar.expire_time, expiry)
    invoice = Bolt11(
        currency=currency,
        amount_msat=None if amount_sats is None else MilliSatoshi(int(amount_sats) * 1000),
        date=int(time.time()) if timestamp is None else int(timestamp),
        tags=tags,
    )
    return encode(invoice, private_key=os.urandom(32).hex())


def _payreq(callback: str, metadata: str | None = None) -> dict:
    return {
        "tag": "payRequest",
        "callback": callback,
        "minSendable": 1000,
        "maxSendable": 100_000_000_000,
        "metadata": _metadata() if metadata is None else metadata,
        "commentAllowed": 0,
    }


def test_bolt11_validation_rejects_bad_invoices():
    from app.invoices import InvoiceValidationError, validate_bolt11

    metadata = _metadata()
    now = int(time.time())
    good = _bolt11(amount_sats=5, metadata=metadata, timestamp=now)
    validated = validate_bolt11(
        good, amount_sats=5, metadata=metadata, network="mainnet", min_expiry_seconds=600, now=now
    )
    assert validated.amount_sats == 5
    assert len(validated.payment_hash) == 64

    cases = [
        (_bolt11(amount_sats=2, metadata=metadata, timestamp=now), "amount_mismatch"),
        (_bolt11(amount_sats=None, metadata=metadata, timestamp=now), "amount_mismatch"),
        (
            _bolt11(amount_sats=5, metadata=metadata, timestamp=now, description_hash="ab" * 32),
            "description_hash_mismatch",
        ),
        (_bolt11(amount_sats=5, metadata=metadata, timestamp=now, currency="tb"), "network_mismatch"),
        (
            _bolt11(amount_sats=5, metadata=metadata, timestamp=now - 7200, expiry=3600),
            "invoice_expired",
        ),
        (_bolt11(amount_sats=5, metadata=metadata, timestamp=now, expiry=60), "invoice_expires_too_soon"),
        ("lnbc1notaninvoice", "invalid_bolt11"),
    ]
    for invoice, code in cases:
        with pytest.raises(InvoiceValidationError) as caught:
            validate_bolt11(
                invoice,
                amount_sats=5,
                metadata=metadata,
                network="mainnet",
                min_expiry_seconds=600,
                now=now,
            )
        assert caught.value.code == code


def test_lud21_verify_url_must_match_payment_hash():
    from app.invoices import InvoiceValidationError, assert_lud21_settled, assert_verify_url_consistent

    assert_verify_url_consistent("https://ln.example/verify/not-a-hash", "ab" * 32)
    with pytest.raises(InvoiceValidationError) as caught:
        assert_verify_url_consistent("https://ln.example/verify/" + ("cd" * 32), "ab" * 32)
    assert caught.value.code == "verify_url_mismatch"
    assert_verify_url_consistent("https://ln.example/verify/" + ("ab" * 32), "ab" * 32)

    with pytest.raises(InvoiceValidationError) as caught:
        assert_lud21_settled({"status": "OK", "settled": False}, payment_hash="ab" * 32, preimage_hex="11" * 32)
    assert caught.value.code == "lud21_not_settled"


def test_wallet_rejects_bad_invoices_and_private_callbacks():
    from app.invoices import InvoiceValidationError
    from app.ssrf import SSRFError
    from app.wallet_lnaddr import LightningAddressWallet

    metadata = _metadata()
    public = {"pay.example": "1.1.1.1", "cb.example": "8.8.8.8"}

    def _wallet(fetch, mapping=None):
        return LightningAddressWallet(
            "merchant@pay.example",
            fetch_json=fetch,
            resolver=_resolver(public if mapping is None else mapping),
            network="mainnet",
        )

    def fetch_amount(url, _params=None):
        if "/.well-known/" in url:
            return _payreq("https://cb.example/lnurl", metadata)
        return {"pr": _bolt11(amount_sats=9, metadata=metadata), "routes": []}

    with pytest.raises(InvoiceValidationError) as caught:
        _wallet(fetch_amount).create_invoice(amount_sats=1, min_expiry_seconds=60)
    assert caught.value.code == "amount_mismatch"

    def fetch_hash(url, _params=None):
        if "/.well-known/" in url:
            return _payreq("https://cb.example/lnurl", metadata)
        return {
            "pr": _bolt11(amount_sats=1, metadata=metadata, description_hash="12" * 32),
            "routes": [],
        }

    with pytest.raises(InvoiceValidationError) as caught:
        _wallet(fetch_hash).create_invoice(amount_sats=1, min_expiry_seconds=60)
    assert caught.value.code == "description_hash_mismatch"

    calls: list[str] = []

    def fetch_loopback(url, _params=None):
        calls.append(url)
        return _payreq("http://127.0.0.1/callback", metadata)

    with pytest.raises(SSRFError):
        _wallet(fetch_loopback).create_invoice(amount_sats=1, min_expiry_seconds=60)
    assert calls == ["https://pay.example/.well-known/lnurlp/merchant"]

    calls.clear()

    def fetch_rfc1918(url, _params=None):
        calls.append(url)
        return _payreq("https://internal.evil/callback", metadata)

    mapping = dict(public)
    mapping["internal.evil"] = "10.1.2.3"
    with pytest.raises(SSRFError):
        _wallet(fetch_rfc1918, mapping).create_invoice(amount_sats=1, min_expiry_seconds=60)
    assert all("internal.evil" not in url for url in calls)

    def fetch_ok(url, _params=None):
        if "/.well-known/" in url:
            return _payreq("https://cb.example/lnurl", metadata)
        invoice = _bolt11(amount_sats=1, metadata=metadata)
        from bolt11 import decode

        payment_hash = decode(invoice).payment_hash
        return {
            "pr": invoice,
            "routes": [],
            "verify": f"https://cb.example/lnurlp/verify/{payment_hash}",
        }

    issued = _wallet(fetch_ok).create_invoice(amount_sats=1, min_expiry_seconds=60)
    assert issued.verify_url is not None
    assert issued.verify_url.endswith(issued.payment_hash)

    def fetch_no_verify(url, _params=None):
        if "/.well-known/" in url:
            return _payreq("https://cb.example/lnurl", metadata)
        return {"pr": _bolt11(amount_sats=1, metadata=metadata), "routes": []}

    plain = _wallet(fetch_no_verify).create_invoice(amount_sats=1, min_expiry_seconds=60)
    assert plain.verify_url is None


def test_ssrf_blocks_private_targets_redirects_and_oversized_bodies():
    from app.ssrf import SSRFError, guard_url, is_public_ip, safe_get_json

    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("1.1.1.1") is True
    for blocked in (
        "127.0.0.1",
        "10.1.2.3",
        "192.168.1.1",
        "172.16.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "::1",
        "fe80::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "0.0.0.0",
    ):
        assert is_public_ip(blocked) is False

    for url in (
        "http://example.com/lnurl",
        "https://user:pass@example.com/lnurl",
        "https://127.0.0.1/.well-known/lnurlp/a",
        "https://10.1.2.3/callback",
        "https://169.254.169.254/latest/meta-data",
        "https://localhost/secret",
        "https://[::1]/secret",
    ):
        with pytest.raises(SSRFError) as caught:
            guard_url(url)
        assert caught.value.code == "destination_rejected"

    with pytest.raises(SSRFError):
        guard_url("https://pay.example/cb", resolver=_resolver({"pay.example": "10.0.0.8"}))
    with pytest.raises(SSRFError):
        guard_url("https://pay.example/cb", resolver=_resolver({"pay.example": "169.254.169.254"}))
    guarded = guard_url("https://pay.example/cb", resolver=_resolver({"pay.example": "8.8.8.8"}))
    assert guarded.ip == "8.8.8.8"

    mixed_called = {"n": 0}

    def _mixed(host, port, *_args, **_kwargs):
        mixed_called["n"] += 1
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", port)),
        ]

    with pytest.raises(SSRFError):
        guard_url("https://pay.example/cb", resolver=_mixed)

    calls: list[str] = []

    def _redirect(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "http://127.0.0.1/admin"})

    with pytest.raises(SSRFError) as caught:
        safe_get_json(
            "https://ln.example/callback",
            client=httpx.Client(transport=httpx.MockTransport(_redirect)),
            resolver=_resolver({"ln.example": "1.1.1.1"}),
        )
    assert caught.value.code == "redirects_not_allowed"
    assert len(calls) == 1
    assert "127.0.0.1" not in calls[0]

    def _huge(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * (64 * 1024 + 8))

    with pytest.raises(SSRFError) as caught:
        safe_get_json(
            "https://ln.example/callback",
            client=httpx.Client(transport=httpx.MockTransport(_huge)),
            resolver=_resolver({"ln.example": "1.1.1.1"}),
        )
    assert caught.value.code == "response_too_large"


def _run_config(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    child_env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": os.environ.get("HOME", ""),
        "PYTHONPATH": str(REPO_ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    child_env.update(env)
    return subprocess.run(
        [sys.executable, "-c", "import app.config"],
        cwd=REPO_ROOT,
        env=child_env,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.mark.parametrize(
    ("env", "snippet"),
    [
        (
            {
                "SATSGATE_ENV": "production",
                "SATSGATE_MACAROON_SECRET": "dev-change-me",
                "SATSGATE_DEV_MODE": "0",
                "SATSGATE_WALLET_MODE": "lnaddr",
                "SATSGATE_LIGHTNING_ADDRESS": "ops@example.com",
            },
            "known default",
        ),
        (
            {
                "SATSGATE_ENV": "production",
                "SATSGATE_MACAROON_SECRET": "short-secret",
                "SATSGATE_DEV_MODE": "0",
                "SATSGATE_WALLET_MODE": "lnaddr",
            },
            "32 bytes",
        ),
        (
            {
                "SATSGATE_ENV": "production",
                "SATSGATE_MACAROON_SECRET": "",
                "SATSGATE_DEV_MODE": "0",
                "SATSGATE_WALLET_MODE": "lnaddr",
            },
            "unset or a known default",
        ),
        (
            {
                "SATSGATE_ENV": "production",
                "SATSGATE_MACAROON_SECRET": "a" * 32,
                "SATSGATE_DEV_MODE": "1",
                "SATSGATE_WALLET_MODE": "lnaddr",
            },
            "SATSGATE_DEV_MODE",
        ),
        (
            {
                "SATSGATE_ENV": "production",
                "SATSGATE_MACAROON_SECRET": "a" * 32,
                "SATSGATE_DEV_MODE": "0",
                "SATSGATE_WALLET_MODE": "mock",
            },
            "WALLET_MODE=mock",
        ),
        (
            {
                "SATSGATE_ENV": "development",
                "SATSGATE_MACAROON_SECRET": "test-secret",
                "SATSGATE_TRUSTED_PROXIES": "*",
            },
            "TRUSTED_PROXIES",
        ),
    ],
)
def test_startup_refuses_unsafe_production_config(env, snippet):
    result = _run_config(env)
    assert result.returncode != 0
    assert snippet in (result.stderr + result.stdout)


def test_startup_allows_explicit_local_dev_and_strong_production_secret(tmp_path):
    local = _run_config(
        {
            "SATSGATE_ENV": "development",
            "SATSGATE_MACAROON_SECRET": "test-secret",
            "SATSGATE_DEV_MODE": "1",
            "SATSGATE_WALLET_MODE": "mock",
        }
    )
    assert local.returncode == 0, local.stderr

    production = _run_config(
        {
            "SATSGATE_ENV": "production",
            "SATSGATE_MACAROON_SECRET": "ab" * 32,
            "SATSGATE_DEV_MODE": "0",
            "SATSGATE_WALLET_MODE": "lnaddr",
            "SATSGATE_LIGHTNING_ADDRESS": "ops@example.com",
            "SATSGATE_DB_PATH": str(tmp_path / "prod.sqlite3"),
            "SATSGATE_TRUSTED_PROXIES": "172.28.0.2",
        }
    )
    assert production.returncode == 0, production.stderr
