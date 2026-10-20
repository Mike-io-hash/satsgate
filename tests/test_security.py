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
import re
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
        "SATSGATE_GATE_TOKEN": "",
        "SATSGATE_GATE_PEERS": "",
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

    from app import l402

    payload = l402.peek_bindings(stolen["macaroon"])
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
    assert "resource" not in rejected.json()

    # A different expected_resource must not reveal the attacker's challenge resource.
    hidden = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": victim_key, "Authorization": stolen_auth},
        json={"expected_resource": "api/other", "cost_credits": 1},
    )
    assert hidden.status_code == 401
    assert hidden.json()["error"] == "client mismatch"
    assert "resource" not in hidden.json()

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
    mismatch_body = mismatched.json()
    assert mismatch_body["error"] == "resource mismatch"
    assert mismatch_body["resource"] == "api/premium"
    assert mismatch_body["expected_resource"] == "api/other"
    assert "exactly match" in mismatch_body["detail"]

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

    raw = bytearray(base64.b64decode(challenge["macaroon"]))
    raw[-1] ^= 0x01
    tampered = base64.b64encode(bytes(raw)).decode("ascii")
    bad_sig = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": _auth(tampered, preimage)},
        json={"expected_resource": "api/premium"},
    )
    assert bad_sig.status_code == 401
    assert bad_sig.json()["error"] == "invalid signature"

    from app import config, db, l402

    client_id = client.get("/v1/client", headers={"X-Api-Key": api_key}).json()["client_id"]
    # The claim window, not the caveat, limits a first unlock. Close that window.
    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE paywall_challenges SET expires_at = ?, created_at = ? WHERE payment_hash = ?",
            (
                int(time.time()) - config.PAYWALL_CLAIM_GRACE_SECONDS - 10,
                int(time.time()) - config.PAYWALL_TOKEN_TTL_CAP_SECONDS - 10,
                challenge["payment_hash"],
            ),
        )
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
    assert expired_res.json()["error"] == "invoice expired"

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
    assert body["version"] == "0.13.0"
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

    # A settled flag without the provider preimage is not enough to auto-confirm.
    with pytest.raises(InvoiceValidationError) as caught:
        assert_lud21_settled({"status": "OK", "settled": True}, payment_hash="ab" * 32, preimage_hex=None)
    assert caught.value.code == "lud21_not_settled"

    preimage = bytes.fromhex("11" * 32)
    payment_hash = hashlib.sha256(preimage).hexdigest()
    assert_lud21_settled(
        {"status": "OK", "settled": True, "preimage": preimage.hex()},
        payment_hash=payment_hash,
        preimage_hex=None,
    )
    with pytest.raises(InvoiceValidationError) as caught:
        assert_lud21_settled(
            {"status": "OK", "settled": True, "preimage": "22" * 32},
            payment_hash=payment_hash,
            preimage_hex=None,
        )
    assert caught.value.code == "lud21_mismatch"
    # The preimage path still accepts a settled response that omits the preimage.
    assert_lud21_settled({"status": "OK", "settled": True}, payment_hash=payment_hash, preimage_hex=preimage.hex())


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


def test_lnurl_callback_omits_comment_by_default():
    """Alby copies a LUD-12 comment into the BOLT11 description. Do not send one."""
    from app.wallet_lnaddr import LightningAddressWallet

    metadata = _metadata()
    seen: dict = {}

    def fetch(url, params=None):
        if "/.well-known/" in url:
            payreq = _payreq("https://cb.example/lnurl", metadata)
            payreq["commentAllowed"] = 255
            return payreq
        seen["params"] = dict(params or {})
        return {"pr": _bolt11(amount_sats=1, metadata=metadata), "routes": []}

    wallet = LightningAddressWallet(
        "satsgate@getalby.com",
        fetch_json=fetch,
        resolver=_resolver({"getalby.com": "1.1.1.1", "cb.example": "8.8.8.8"}),
        network="mainnet",
    )
    issued = wallet.create_invoice(amount_sats=1, memo="satsgate paywall", min_expiry_seconds=60)
    assert seen["params"] == {"amount": 1000}
    assert "comment" not in seen["params"]
    assert issued.amount_sats == 1


def test_lnurl_description_hash_mismatch_still_rejected():
    """A comment must not relax description_hash = SHA256(metadata)."""
    from app.invoices import InvoiceValidationError
    from app.wallet_lnaddr import LightningAddressWallet

    metadata = _metadata()
    seen: dict = {}

    def fetch(url, params=None):
        if "/.well-known/" in url:
            payreq = _payreq("https://cb.example/lnurl", metadata)
            payreq["commentAllowed"] = 255
            return payreq
        seen["params"] = dict(params or {})
        return {
            "pr": _bolt11(amount_sats=1, metadata=metadata, description_hash="12" * 32),
            "routes": [],
        }

    wallet = LightningAddressWallet(
        "merchant@pay.example",
        fetch_json=fetch,
        resolver=_resolver({"pay.example": "1.1.1.1", "cb.example": "8.8.8.8"}),
        network="mainnet",
        send_comment=True,
    )
    with pytest.raises(InvoiceValidationError) as caught:
        wallet.create_invoice(amount_sats=1, memo="satsgate topup trial", min_expiry_seconds=60)
    assert caught.value.code == "description_hash_mismatch"
    assert seen["params"]["comment"] == "satsgate topup trial"
    assert seen["params"]["amount"] == 1000


def test_lnurl_comment_sent_only_when_enabled_and_allowed():
    from app.wallet_lnaddr import LightningAddressWallet

    metadata = _metadata()
    public = {"pay.example": "1.1.1.1", "cb.example": "8.8.8.8"}

    def _fetch(comment_allowed: int, seen: list[dict]):
        def fetch(url, params=None):
            if "/.well-known/" in url:
                payreq = _payreq("https://cb.example/lnurl", metadata)
                payreq["commentAllowed"] = comment_allowed
                return payreq
            seen.append(dict(params or {}))
            return {"pr": _bolt11(amount_sats=1, metadata=metadata), "routes": []}

        return fetch

    allowed: list[dict] = []
    LightningAddressWallet(
        "merchant@pay.example",
        fetch_json=_fetch(8, allowed),
        resolver=_resolver(public),
        network="mainnet",
        send_comment=True,
    ).create_invoice(amount_sats=1, memo="satsgate paywall", min_expiry_seconds=60)
    assert allowed[-1]["comment"] == "satsgate"

    blocked: list[dict] = []
    LightningAddressWallet(
        "other@pay.example",
        fetch_json=_fetch(0, blocked),
        resolver=_resolver(public),
        network="mainnet",
        send_comment=True,
    ).create_invoice(amount_sats=1, memo="satsgate paywall", min_expiry_seconds=60)
    assert "comment" not in blocked[-1]


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
        (
            {
                "SATSGATE_ENV": "production",
                "SATSGATE_MACAROON_SECRET": "ab" * 32,
                "SATSGATE_DEV_MODE": "0",
                "SATSGATE_WALLET_MODE": "lnaddr",
                "SATSGATE_LIGHTNING_ADDRESS": "ops@example.com",
                "SATSGATE_GATE_TOKEN": "too-short",
            },
            "SATSGATE_GATE_TOKEN",
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


def _decode_uvarint(data: bytes) -> tuple[int, int]:
    value = 0
    shift = 0
    for index, byte in enumerate(data, start=1):
        if byte < 0x80:
            return value | (byte << shift), index
        value |= (byte & 0x7F) << shift
        shift += 7
    raise AssertionError("bad uvarint")


def _lnget_identifier(raw: bytes) -> bytes:
    """Independent V2 macaroon walk, the same steps lnget does after base64."""
    assert raw[:1] == b"\x02"
    data = raw[1:]
    fields: list[tuple[int, bytes]] = []
    while True:
        field_type, used = _decode_uvarint(data)
        data = data[used:]
        if field_type == 0:
            break
        length, used = _decode_uvarint(data)
        data = data[used:]
        fields.append((field_type, data[:length]))
        data = data[length:]
    identifier = dict(fields)[2]
    assert len(identifier) == 66
    assert int.from_bytes(identifier[:2], "big") == 0
    return identifier


def _alby_parse_l402(header: str) -> dict[str, str]:
    """@getalby/lightning-tools parseL402: first L402/LSAT stripped, then key=value."""
    text = header.replace("L402", "", 1).replace("LSAT", "", 1).strip()
    pairs: dict[str, str] = {}
    for match in re.finditer(r'(\w+)=("([^"]*)"|\'([^\']*)\'|([^,]*))', text):
        pairs[match.group(1)] = match.group(3) or match.group(4) or match.group(5)
    if "token" not in pairs and "macaroon" in pairs:
        pairs["token"] = pairs.pop("macaroon")
    return pairs


def test_l402_challenge_parses_like_lnget_and_alby(client):
    import re as _re

    started = client.get("/v1/topup/trial")
    assert started.status_code == 402, started.text
    body = started.json()
    header = started.headers["www-authenticate"]

    # lnget ParseChallenge
    challenge_re = _re.compile(r'(?i)(LSAT|L402)\s+macaroon="([^"]+)",\s*invoice="([^"]+)"')
    match = challenge_re.search(header)
    assert match is not None, header
    assert match.group(1).upper() == "L402"
    mac_b64 = match.group(2)
    assert match.group(3) == body["invoice"]
    assert _re.fullmatch(r"[A-Za-z0-9+/=]+", mac_b64)
    assert "L402" not in mac_b64 and "LSAT" not in mac_b64
    raw = base64.standard_b64decode(mac_b64)
    identifier = _lnget_identifier(raw)
    assert identifier[2:34].hex() == body["payment_hash"]

    # Aperture FromHeader credential grammar, including the legacy LSAT prefix.
    preimage = client.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
    for scheme in ("L402", "LSAT"):
        auth = f"{scheme} {mac_b64}:{preimage}"
        assert _re.fullmatch(r"(?i:(LSAT|L402))[ ]+([A-Za-z0-9+/=]+):([0-9a-fA-F]{64})", auth)

    # Alby fetch402 treats the macaroon as an opaque token.
    parsed = _alby_parse_l402(header)
    assert parsed["token"] == body["macaroon"] == mac_b64
    assert parsed["invoice"] == body["invoice"]

    settled = client.get("/v1/topup/trial", headers={"Authorization": f"LSAT {mac_b64}:{preimage}"})
    assert settled.status_code == 200, settled.text
    assert settled.json()["api_key"].startswith("sg_")


def test_in_flight_v2_json_token_still_verifies(client):
    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/premium", amount_sats=5)
    client_id = client.get("/v1/client", headers={"X-Api-Key": api_key}).json()["client_id"]
    from app.l402 import invoice_binding, payee_binding

    payload = {
        "v": 2,
        "kid": "1",
        "purpose": "paywall",
        "cid": client_id,
        "ph": challenge["payment_hash"],
        "res": "api/premium",
        "amt": 5,
        "payee_h": payee_binding(challenge.get("payee_lightning_address")),
        "inv_h": invoice_binding(challenge["invoice"]),
        "exp": int(time.time()) + 600,
        "nonce": "legacy-json",
    }
    body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(b"test-secret", body, hashlib.sha256).hexdigest()
    token = base64.urlsafe_b64encode(body + b"." + sig.encode()).decode().rstrip("=")
    preimage = client.get(f"/dev/mock/pay/{challenge['payment_hash']}").json()["preimage"]
    accepted = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": _auth(token, preimage)},
        json={"expected_resource": "api/premium"},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["charged_credits"] == 1


def test_topup_claim_without_preimage_is_idempotent_and_bound(client):
    from app import config, db
    from app.invoices import InvoiceValidationError
    from app import wallet_lnaddr

    started = client.get("/v1/topup/trial")
    assert started.status_code == 402, started.text
    body = started.json()
    payment_hash = body["payment_hash"]
    macaroon = body["macaroon"]

    # No verify URL: the macaroon alone cannot mint an API key.
    refused = client.get(
        f"/v1/topup/status/{payment_hash}",
        headers={"Authorization": f"L402 {macaroon}"},
    )
    assert refused.status_code == 401
    assert refused.json()["error"] == "preimage_required"

    naked = client.get(f"/v1/topup/status/{payment_hash}")
    assert naked.status_code == 401

    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE topups SET verify_url = ? WHERE payment_hash = ?",
            ("https://ln.example/verify/" + payment_hash, payment_hash),
        )

    calls = {"n": 0}

    def _later(**kwargs):
        assert kwargs["verify_url"].endswith(payment_hash)
        assert kwargs["preimage_hex"] is None
        calls["n"] += 1
        if calls["n"] == 1:
            raise InvoiceValidationError("lud21_not_settled")
        return None

    original = wallet_lnaddr.confirm_lud21
    wallet_lnaddr.confirm_lud21 = _later
    try:
        pending = client.get(
            f"/v1/topup/status/{payment_hash}",
            headers={"Authorization": f"L402 {macaroon}"},
        )
        assert pending.status_code == 200, pending.text
        assert pending.json()["settled"] is False
        assert "api_key" not in pending.json()

        # A macaroon for a different invoice cannot claim this payment hash.
        other = client.get("/v1/topup/trial")
        stolen = client.get(
            f"/v1/topup/status/{payment_hash}",
            headers={"Authorization": f"L402 {other.json()['macaroon']}"},
        )
        assert stolen.status_code == 401

        settled = client.get(
            f"/v1/topup/status/{payment_hash}",
            headers={"Authorization": f"L402 {macaroon}"},
        )
    finally:
        wallet_lnaddr.confirm_lud21 = original

    assert settled.status_code == 200, settled.text
    first = settled.json()
    assert first["settled"] is True
    assert first["credits_added"] == body["plan"]["credits"]
    assert first["api_key"].startswith("sg_")

    again = client.get(
        f"/v1/topup/status/{payment_hash}",
        headers={"Authorization": f"L402 {macaroon}"},
    )
    assert again.status_code == 200, again.text
    replay = again.json()
    assert replay["credits_added"] == 0
    assert "api_key" not in replay
    assert replay["new_balance"] == first["new_balance"]

    # The preimage form still settles a fresh top-up, including under LSAT above.
    # A stored private verify URL must not be fetched and must not credit anyone.
    poisoned = client.get("/v1/topup/starter")
    poisoned_body = poisoned.json()
    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE topups SET verify_url = ? WHERE payment_hash = ?",
            ("http://127.0.0.1/verify", poisoned_body["payment_hash"]),
        )
    blocked = client.get(
        f"/v1/topup/status/{poisoned_body['payment_hash']}",
        headers={"Authorization": f"L402 {poisoned_body['macaroon']}", "verify_url": "https://ln.example/verify"},
    )
    assert blocked.status_code == 502
    assert blocked.json()["error"] == "payee_destination_rejected"
    assert "api_key" not in blocked.json()

    # Preimage flow remains available when no verify URL was stored.
    plain = client.get("/v1/topup/growth")
    plain_body = plain.json()
    plain_preimage = client.get(f"/dev/mock/pay/{plain_body['payment_hash']}").json()["preimage"]
    credited = client.get(
        "/v1/topup/growth",
        headers={"Authorization": _auth(plain_body["macaroon"], plain_preimage)},
    )
    assert credited.status_code == 200, credited.text
    assert credited.json()["api_key"].startswith("sg_")


def test_topup_claim_does_not_double_credit(client):
    from app import config, db

    started = client.get("/v1/topup/trial")
    body = started.json()
    barrier = threading.Barrier(2)
    results: list[dict] = []
    errors: list[BaseException] = []

    def _once() -> None:
        try:
            barrier.wait(timeout=5)
            results.append(
                db.settle_topup_and_credit(config.DB_PATH, payment_hash=body["payment_hash"], client_id=None)
            )
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=_once) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert errors == []
    assert sum(item["credits_added"] for item in results) == body["plan"]["credits"]
    assert sum(1 for item in results if item["api_key"]) == 1
    assert results[0]["client_id"] == results[1]["client_id"]
    balance = db.get_balance(config.DB_PATH, client_id=results[0]["client_id"])
    assert balance == body["plan"]["credits"]


def _with_topup_invoice_lifetime(seconds: int):
    """Point mock top-up invoices at a BOLT11-like lifetime. Paywall invoices stay put."""
    from app.main import WALLET

    original = WALLET.create_invoice

    def create_invoice(**kwargs):
        if "topup" in str(kwargs.get("memo", "")):
            kwargs = dict(kwargs)
            kwargs["expiry_seconds"] = int(seconds)
            kwargs["min_expiry_seconds"] = int(seconds)
        return original(**kwargs)

    WALLET.create_invoice = create_invoice
    return WALLET, original


def _restore_wallet(wallet, original) -> None:
    wallet.create_invoice = original


def _set_topup_window(payment_hash: str, *, expires_at: int, created_at: int | None = None) -> None:
    from app import config, db

    with db._connect(config.DB_PATH) as conn:
        if created_at is None:
            conn.execute(
                "UPDATE topups SET expires_at = ? WHERE payment_hash = ?",
                (int(expires_at), payment_hash),
            )
        else:
            conn.execute(
                "UPDATE topups SET expires_at = ?, created_at = ? WHERE payment_hash = ?",
                (int(expires_at), int(created_at), payment_hash),
            )


def _expired_topup_macaroon(body: dict, *, ttl_seconds: int = -601) -> str:
    """A 0.4.0 macaroon whose caveat expired well after the old 600s TTL."""
    from app import config, l402

    return l402.make_macaroon(
        secret=config.MACAROON_SECRET,
        kid=config.MACAROON_KEY_ID,
        purpose=l402.PURPOSE_TOPUP,
        payment_hash=body["payment_hash"],
        resource=f"v1/topup/{body['plan']['id']}",
        amount_sats=int(body["plan"]["price_sats"]),
        invoice=body["invoice"],
        ttl_seconds=ttl_seconds,
        client_id=None,
        payee=config.LIGHTNING_ADDRESS or None,
    )


def _expired_json_topup_token(body: dict) -> str:
    """In-flight 0.3.0 JSON token, expired by more than the old 10-minute TTL."""
    from app.l402 import invoice_binding, payee_binding

    payload = {
        "v": 2,
        "kid": "1",
        "purpose": "topup",
        "cid": None,
        "ph": body["payment_hash"],
        "res": f"v1/topup/{body['plan']['id']}",
        "amt": int(body["plan"]["price_sats"]),
        "payee_h": payee_binding(None),
        "inv_h": invoice_binding(body["invoice"]),
        "exp": int(time.time()) - 601,
        "nonce": "legacy-topup",
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(b"test-secret", raw, hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(raw + b"." + sig.encode()).decode().rstrip("=")


def test_topup_paid_after_ten_minutes_still_claims(client):
    """A 24h invoice can be paid after the old 10-minute token TTL, then finished.

    Covers a macaroon minted for that invoice, a 0.4.0 macaroon whose `exp` has
    already passed, and an in-flight 0.3.0 JSON token in the same state. The
    status poll (no preimage) and the preimage claim both credit once.
    """
    from app import config, l402
    from app import wallet_lnaddr
    from app.invoices import InvoiceValidationError

    wallet, original = _with_topup_invoice_lifetime(24 * 60 * 60)
    try:
        started = client.get("/v1/topup/trial")
    finally:
        _restore_wallet(wallet, original)

    assert started.status_code == 402, started.text
    body = started.json()
    now = int(time.time())
    minted = l402.peek_bindings(body["macaroon"])
    # The caveat follows the invoice (plus grace), so 11 minutes is still inside it.
    assert body["expires_at"] - now > 23 * 60 * 60
    assert abs(minted["exp"] - (body["expires_at"] + config.TOPUP_CLAIM_GRACE_SECONDS)) <= 3
    assert minted["exp"] - now > 11 * 60
    assert minted["exp"] - now < config.TOPUP_TOKEN_TTL_CAP_SECONDS + 5

    import app.main as mainmod

    frozen = time.time() + 11 * 60
    mainmod.time.time = lambda: frozen
    try:
        preimage = client.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
        paid_late = client.get(
            "/v1/topup/trial",
            headers={"Authorization": _auth(body["macaroon"], preimage)},
        )
    finally:
        mainmod.time.time = time.time
    assert paid_late.status_code == 200, paid_late.text
    assert paid_late.json()["credits_added"] == body["plan"]["credits"]
    assert paid_late.json()["api_key"].startswith("sg_")

    # Tokens already issued with the 600s TTL: the caveat is in the past, the
    # stored invoice is still the Alby-style one, and the ledger row is pending.
    issued_at = now - 1201
    wallet, original = _with_topup_invoice_lifetime(24 * 60 * 60)
    try:
        legacy = client.get("/v1/topup/starter")
        polling = client.get("/v1/topup/growth")
        json_topup = client.get("/v1/topup/scale")
    finally:
        _restore_wallet(wallet, original)

    for stale in (legacy, polling, json_topup):
        assert stale.status_code == 402, stale.text
        _set_topup_window(
            stale.json()["payment_hash"],
            expires_at=issued_at + 24 * 60 * 60,
            created_at=issued_at,
        )

    legacy_body = legacy.json()
    legacy_mac = _expired_topup_macaroon(legacy_body)
    assert l402.peek_bindings(legacy_mac)["exp"] < time.time() - 600
    legacy_preimage = client.get(f"/dev/mock/pay/{legacy_body['payment_hash']}").json()["preimage"]
    legacy_paid = client.get(
        "/v1/topup/starter",
        headers={"Authorization": _auth(legacy_mac, legacy_preimage)},
    )
    assert legacy_paid.status_code == 200, legacy_paid.text
    assert legacy_paid.json()["credits_added"] == legacy_body["plan"]["credits"]
    again = client.get(
        "/v1/topup/starter",
        headers={"Authorization": _auth(legacy_mac, legacy_preimage)},
    )
    assert again.status_code == 200, again.text
    assert again.json()["credits_added"] == 0
    assert "api_key" not in again.json()

    # No payment proof: the expired macaroon does not mint credits.
    poll_body = polling.json()
    poll_mac = _expired_topup_macaroon(poll_body)
    refused = client.get(
        f"/v1/topup/status/{poll_body['payment_hash']}",
        headers={"Authorization": f"L402 {poll_mac}"},
    )
    assert refused.status_code == 401
    assert refused.json()["error"] == "preimage_required"
    assert "api_key" not in refused.json()

    from app import db

    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE topups SET verify_url = ? WHERE payment_hash = ?",
            ("https://ln.example/verify/" + poll_body["payment_hash"], poll_body["payment_hash"]),
        )

    calls = {"n": 0}

    def _settle_on_second(**kwargs):
        assert kwargs["preimage_hex"] is None
        assert kwargs["verify_url"].endswith(poll_body["payment_hash"])
        calls["n"] += 1
        if calls["n"] == 1:
            raise InvoiceValidationError("lud21_not_settled")
        return None

    original_confirm = wallet_lnaddr.confirm_lud21
    wallet_lnaddr.confirm_lud21 = _settle_on_second
    try:
        pending = client.get(
            f"/v1/topup/status/{poll_body['payment_hash']}",
            headers={"Authorization": f"L402 {poll_mac}"},
        )
        assert pending.status_code == 200, pending.text
        assert pending.json()["settled"] is False
        assert "api_key" not in pending.json()
        settled = client.get(
            f"/v1/topup/status/{poll_body['payment_hash']}",
            headers={"Authorization": f"L402 {poll_mac}"},
        )
    finally:
        wallet_lnaddr.confirm_lud21 = original_confirm

    assert settled.status_code == 200, settled.text
    assert settled.json()["settled"] is True
    assert settled.json()["credits_added"] == poll_body["plan"]["credits"]
    assert settled.json()["api_key"].startswith("sg_")
    assert calls["n"] == 2

    # 0.3.0 JSON tokens use the same claim window.
    json_body = json_topup.json()
    json_mac = _expired_json_topup_token(json_body)
    json_preimage = client.get(f"/dev/mock/pay/{json_body['payment_hash']}").json()["preimage"]
    json_paid = client.get(
        "/v1/topup/scale",
        headers={"Authorization": _auth(json_mac, json_preimage)},
    )
    assert json_paid.status_code == 200, json_paid.text
    assert json_paid.json()["api_key"].startswith("sg_")


def test_topup_rejects_expired_invoice_even_with_payment_proof(client):
    from app import config, db
    from app import wallet_lnaddr

    started = client.get("/v1/topup/trial")
    body = started.json()
    preimage = client.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
    now = int(time.time())
    _set_topup_window(body["payment_hash"], expires_at=now - config.TOPUP_CLAIM_GRACE_SECONDS - 5)

    rejected = client.get("/v1/topup/trial", headers={"Authorization": _auth(body["macaroon"], preimage)})
    assert rejected.status_code == 401
    assert rejected.json()["error"] == "invoice expired"
    assert "api_key" not in rejected.json()
    assert db.get_topup(config.DB_PATH, body["payment_hash"])["status"] == "pending"

    # Inside the grace window the same preimage still completes.
    grace = client.get("/v1/topup/starter")
    grace_body = grace.json()
    grace_preimage = client.get(f"/dev/mock/pay/{grace_body['payment_hash']}").json()["preimage"]
    _set_topup_window(grace_body["payment_hash"], expires_at=int(time.time()) - 30)
    # A later top-up must not delete a row that is still inside the grace window.
    client.get("/v1/topup/growth")
    assert db.get_topup(config.DB_PATH, grace_body["payment_hash"])["status"] == "pending"
    finished = client.get(
        "/v1/topup/starter",
        headers={"Authorization": _auth(grace_body["macaroon"], grace_preimage)},
    )
    assert finished.status_code == 200, finished.text
    assert finished.json()["credits_added"] == grace_body["plan"]["credits"]

    # Past the window, a settled LUD-21 response is not consulted and does not credit.
    late = client.get("/v1/topup/scale")
    late_body = late.json()
    _set_topup_window(
        late_body["payment_hash"],
        expires_at=int(time.time()) - config.TOPUP_CLAIM_GRACE_SECONDS - 5,
    )
    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE topups SET verify_url = ? WHERE payment_hash = ?",
            ("https://ln.example/verify/" + late_body["payment_hash"], late_body["payment_hash"]),
        )

    def _should_not_run(**_kwargs):
        raise AssertionError("LUD-21 must not be fetched after the invoice window")

    original = wallet_lnaddr.confirm_lud21
    wallet_lnaddr.confirm_lud21 = _should_not_run
    try:
        blocked = client.get(
            f"/v1/topup/status/{late_body['payment_hash']}",
            headers={"Authorization": f"L402 {late_body['macaroon']}"},
        )
    finally:
        wallet_lnaddr.confirm_lud21 = original
    assert blocked.status_code == 401
    assert blocked.json()["error"] == "invoice expired"
    assert db.get_topup(config.DB_PATH, late_body["payment_hash"])["status"] == "pending"


def test_topup_without_stored_expiry_keeps_the_macaroon_exp(client):
    """Rows from before expires_at existed must not become open-ended claims."""
    from app import config, db

    started = client.get("/v1/topup/trial")
    body = started.json()
    preimage = client.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
    with db._connect(config.DB_PATH) as conn:
        conn.execute("UPDATE topups SET expires_at = NULL WHERE payment_hash = ?", (body["payment_hash"],))
    credited = client.get("/v1/topup/trial", headers={"Authorization": _auth(body["macaroon"], preimage)})
    assert credited.status_code == 200, credited.text

    stale = client.get("/v1/topup/starter")
    stale_body = stale.json()
    stale_preimage = client.get(f"/dev/mock/pay/{stale_body['payment_hash']}").json()["preimage"]
    with db._connect(config.DB_PATH) as conn:
        conn.execute("UPDATE topups SET expires_at = NULL WHERE payment_hash = ?", (stale_body["payment_hash"],))
    rejected = client.get(
        "/v1/topup/starter",
        headers={"Authorization": _auth(_expired_topup_macaroon(stale_body), stale_preimage)},
    )
    assert rejected.status_code == 401
    assert rejected.json()["error"] == "token expired"
    assert db.get_topup(config.DB_PATH, stale_body["payment_hash"])["status"] == "pending"


def test_topup_token_cap_bounds_a_long_invoice(client):
    from app import config, l402

    previous = config.TOPUP_TOKEN_TTL_CAP_SECONDS
    config.TOPUP_TOKEN_TTL_CAP_SECONDS = 3600
    wallet, original = _with_topup_invoice_lifetime(10 * 24 * 60 * 60)
    try:
        started = client.get("/v1/topup/trial")
    finally:
        _restore_wallet(wallet, original)
        config.TOPUP_TOKEN_TTL_CAP_SECONDS = previous

    assert started.status_code == 402, started.text
    body = started.json()
    now = time.time()
    minted = l402.peek_bindings(body["macaroon"])
    assert body["expires_at"] - now > 9 * 24 * 60 * 60
    assert abs(minted["exp"] - (now + 3600)) <= 3

    # The server cap still applies if the row is older than the cap, even when
    # the caveat itself has not expired and the BOLT11 expiry is days away.
    config.TOPUP_TOKEN_TTL_CAP_SECONDS = 3600
    try:
        _set_topup_window(
            body["payment_hash"],
            expires_at=int(now) + 10 * 24 * 60 * 60,
            created_at=int(now) - 3601,
        )
        preimage = client.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
        rejected = client.get("/v1/topup/trial", headers={"Authorization": _auth(body["macaroon"], preimage)})
    finally:
        config.TOPUP_TOKEN_TTL_CAP_SECONDS = previous
    assert rejected.status_code == 401
    assert rejected.json()["error"] == "invoice expired"


def _with_paywall_invoice_lifetime(seconds: int):
    """Point mock paywall invoices at a BOLT11-like lifetime. Top-ups stay put."""
    from app.main import WALLET

    original = WALLET.create_invoice

    def create_invoice(**kwargs):
        if "paywall" in str(kwargs.get("memo", "")):
            kwargs = dict(kwargs)
            kwargs["expiry_seconds"] = int(seconds)
            kwargs["min_expiry_seconds"] = int(seconds)
        return original(**kwargs)

    WALLET.create_invoice = create_invoice
    return WALLET, original


def _set_paywall_window(payment_hash: str, *, expires_at: int, created_at: int | None = None) -> None:
    from app import config, db

    with db._connect(config.DB_PATH) as conn:
        if created_at is None:
            conn.execute(
                "UPDATE paywall_challenges SET expires_at = ? WHERE payment_hash = ?",
                (int(expires_at), payment_hash),
            )
        else:
            conn.execute(
                "UPDATE paywall_challenges SET expires_at = ?, created_at = ? WHERE payment_hash = ?",
                (int(expires_at), int(created_at), payment_hash),
            )


def test_paywall_claim_follows_invoice_expiry(client):
    """A paywall macaroon lives with the invoice, plus grace, and never past the cap.

    `ttl_seconds` is only the minimum invoice lifetime. A short value must not
    bring back the 10-minute trap when the invoice itself is still payable.
    """
    from app import config, l402

    api_key = _buy_client(client)
    wallet, original = _with_paywall_invoice_lifetime(24 * 60 * 60)
    try:
        challenge = _challenge(client, api_key, resource="api/premium", amount_sats=21)
        custom = client.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": api_key},
            json={"resource": "api/short", "amount_sats": 2, "ttl_seconds": 90},
        )
    finally:
        _restore_wallet(wallet, original)

    assert custom.status_code == 200, custom.text
    now = time.time()
    for body in (challenge, custom.json()):
        minted = l402.peek_bindings(body["macaroon"])
        assert body["invoice_expires_at"] - now > 23 * 60 * 60
        assert abs(minted["exp"] - (body["invoice_expires_at"] + config.PAYWALL_CLAIM_GRACE_SECONDS)) <= 3
        assert body["claim_until"] == minted["exp"]
        assert body["valid_until"] == minted["exp"]
        assert body["cache_until"] == minted["exp"]
        assert "invoice_expires_at" in body["note"]
        assert "content" not in body["note"] or "your decision" in body["note"]
        assert body["payee_saved"] is False

    # The default mock invoice (no stub) still follows its own expiry plus grace,
    # which is longer than the old 600s token TTL.
    plain = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": api_key},
        json={"resource": "api/plain", "amount_sats": 1},
    )
    assert plain.status_code == 200, plain.text
    plain_body = plain.json()
    plain_exp = l402.peek_bindings(plain_body["macaroon"])["exp"]
    assert abs(plain_body["invoice_expires_at"] - (time.time() + config.TOKEN_TTL_SECONDS)) <= 3
    assert abs(plain_exp - (plain_body["invoice_expires_at"] + config.PAYWALL_CLAIM_GRACE_SECONDS)) <= 3


def test_paywall_paid_after_ten_minutes_still_unlocks(client):
    """Paying a 24h invoice after the old 10-minute TTL still unlocks, once.

    Covers a macaroon minted for that invoice and a macaroon whose caveat has
    already expired. No preimage and no settled LUD-21 check does not spend a
    credit. Past the claim window the route returns invoice expired.
    """
    from app import config, l402
    from app import wallet_lnaddr

    api_key = _buy_client(client)
    wallet, original = _with_paywall_invoice_lifetime(24 * 60 * 60)
    try:
        challenge = _challenge(client, api_key, resource="api/premium", amount_sats=21)
    finally:
        _restore_wallet(wallet, original)

    before = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]
    import app.main as mainmod

    frozen = time.time() + 11 * 60
    mainmod.time.time = lambda: frozen
    try:
        preimage = client.get(f"/dev/mock/pay/{challenge['payment_hash']}").json()["preimage"]
        paid_late = client.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": api_key, "Authorization": _auth(challenge["macaroon"], preimage)},
            json={"expected_resource": "api/premium"},
        )
    finally:
        mainmod.time.time = time.time
    assert paid_late.status_code == 200, paid_late.text
    assert paid_late.json()["charged_credits"] == 1
    assert paid_late.json()["cache_until"] == paid_late.json()["claim_until"]
    assert "cache_until" in paid_late.json()["note"]
    assert client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"] == before - 1

    # In-flight 10-minute caveat: the stored invoice is still open, so proof unlocks it.
    wallet, original = _with_paywall_invoice_lifetime(24 * 60 * 60)
    try:
        legacy = _challenge(client, api_key, resource="api/legacy", amount_sats=4)
    finally:
        _restore_wallet(wallet, original)
    client_id = client.get("/v1/client", headers={"X-Api-Key": api_key}).json()["client_id"]
    legacy_mac = l402.make_macaroon(
        secret=config.MACAROON_SECRET,
        kid=config.MACAROON_KEY_ID,
        purpose=l402.PURPOSE_PAYWALL,
        payment_hash=legacy["payment_hash"],
        resource="api/legacy",
        amount_sats=4,
        invoice=legacy["invoice"],
        ttl_seconds=-601,
        client_id=client_id,
        payee=legacy.get("payee_lightning_address"),
    )
    assert l402.peek_bindings(legacy_mac)["exp"] < time.time() - 600
    legacy_before = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]
    no_proof = client.get(
        f"/v1/paywall/status/{legacy['payment_hash']}",
        headers={"X-Api-Key": api_key, "Authorization": f"L402 {legacy_mac}"},
        params={"expected_resource": "api/legacy"},
    )
    assert no_proof.status_code == 401
    assert no_proof.json()["error"] == "preimage_required"
    assert client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"] == legacy_before

    legacy_preimage = client.get(f"/dev/mock/pay/{legacy['payment_hash']}").json()["preimage"]
    unlocked = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": _auth(legacy_mac, legacy_preimage)},
        json={"expected_resource": "api/legacy"},
    )
    assert unlocked.status_code == 200, unlocked.text
    assert unlocked.json()["charged_credits"] == 1
    assert unlocked.json()["valid_until"] < time.time()
    assert unlocked.json()["claim_until"] > time.time()
    assert client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"] == legacy_before - 1

    # A closed window does not unlock, even if LUD-21 would report the invoice settled.
    wallet, original = _with_paywall_invoice_lifetime(24 * 60 * 60)
    try:
        closed = _challenge(client, api_key, resource="api/closed", amount_sats=3)
    finally:
        _restore_wallet(wallet, original)
    from app import db

    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE paywall_challenges SET verify_url = ? WHERE payment_hash = ?",
            ("https://ln.example/verify/" + closed["payment_hash"], closed["payment_hash"]),
        )
    _set_paywall_window(
        closed["payment_hash"],
        expires_at=int(time.time()) - config.PAYWALL_CLAIM_GRACE_SECONDS - 5,
        created_at=int(time.time()) - config.PAYWALL_TOKEN_TTL_CAP_SECONDS - 5,
    )
    closed_before = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]
    original_confirm = wallet_lnaddr.confirm_lud21
    wallet_lnaddr.confirm_lud21 = lambda **_kwargs: None
    try:
        rejected = client.get(
            f"/v1/paywall/status/{closed['payment_hash']}",
            headers={"X-Api-Key": api_key, "Authorization": f"L402 {closed['macaroon']}"},
            params={"expected_resource": "api/closed"},
        )
    finally:
        wallet_lnaddr.confirm_lud21 = original_confirm
    assert rejected.status_code == 401
    assert rejected.json()["error"] == "invoice expired"
    assert client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"] == closed_before

    # Grace still covers a payment made just as the invoice expired.
    wallet, original = _with_paywall_invoice_lifetime(24 * 60 * 60)
    try:
        grace = _challenge(client, api_key, resource="api/grace", amount_sats=2)
    finally:
        _restore_wallet(wallet, original)
    _set_paywall_window(grace["payment_hash"], expires_at=int(time.time()) - 30)
    grace_preimage = client.get(f"/dev/mock/pay/{grace['payment_hash']}").json()["preimage"]
    grace_before = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]
    grace_paid = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": _auth(grace["macaroon"], grace_preimage)},
        json={"expected_resource": "api/grace"},
    )
    assert grace_paid.status_code == 200, grace_paid.text
    assert grace_paid.json()["charged_credits"] == 1
    assert client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"] == grace_before - 1


def test_paywall_claim_cap_bounds_a_long_invoice(client):
    from app import config, l402

    api_key = _buy_client(client)
    previous = config.PAYWALL_TOKEN_TTL_CAP_SECONDS
    config.PAYWALL_TOKEN_TTL_CAP_SECONDS = 3600
    wallet, original = _with_paywall_invoice_lifetime(10 * 24 * 60 * 60)
    try:
        challenge = _challenge(client, api_key, resource="api/capped", amount_sats=5)
    finally:
        _restore_wallet(wallet, original)
        config.PAYWALL_TOKEN_TTL_CAP_SECONDS = previous

    now = time.time()
    minted = l402.peek_bindings(challenge["macaroon"])
    assert challenge["invoice_expires_at"] - now > 9 * 24 * 60 * 60
    assert abs(minted["exp"] - (now + 3600)) <= 3
    assert challenge["claim_until"] < challenge["invoice_expires_at"]
    assert "claim cap" in challenge["note"]

    config.PAYWALL_TOKEN_TTL_CAP_SECONDS = 3600
    try:
        _set_paywall_window(
            challenge["payment_hash"],
            expires_at=int(now) + 10 * 24 * 60 * 60,
            created_at=int(now) - 3601,
        )
        preimage = client.get(f"/dev/mock/pay/{challenge['payment_hash']}").json()["preimage"]
        before = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]
        rejected = client.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": api_key, "Authorization": _auth(challenge["macaroon"], preimage)},
            json={"expected_resource": "api/capped"},
        )
    finally:
        config.PAYWALL_TOKEN_TTL_CAP_SECONDS = previous
    assert rejected.status_code == 401
    assert rejected.json()["error"] == "invoice expired"
    assert client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"] == before


def test_paywall_old_row_uses_decoded_invoice_expiry(client):
    """A pre-0.4.2 row stored the 10-minute TTL. The BOLT11 expiry still opens the claim."""
    from app import config, l402
    import app.main as mainmod

    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/old-row", amount_sats=6)
    issued_at = int(time.time()) - 1201
    _set_paywall_window(challenge["payment_hash"], expires_at=issued_at + config.TOKEN_TTL_SECONDS, created_at=issued_at)
    client_id = client.get("/v1/client", headers={"X-Api-Key": api_key}).json()["client_id"]
    expired = l402.make_macaroon(
        secret=config.MACAROON_SECRET,
        kid=config.MACAROON_KEY_ID,
        purpose=l402.PURPOSE_PAYWALL,
        payment_hash=challenge["payment_hash"],
        resource="api/old-row",
        amount_sats=6,
        invoice=challenge["invoice"],
        ttl_seconds=-601,
        client_id=client_id,
        payee=challenge.get("payee_lightning_address"),
    )
    original = mainmod.bolt11_expiry_unix
    mainmod.bolt11_expiry_unix = lambda _invoice: issued_at + 24 * 60 * 60
    try:
        preimage = client.get(f"/dev/mock/pay/{challenge['payment_hash']}").json()["preimage"]
        before = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]
        unlocked = client.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": api_key, "Authorization": _auth(expired, preimage)},
            json={"expected_resource": "api/old-row"},
        )
    finally:
        mainmod.bolt11_expiry_unix = original
    assert unlocked.status_code == 200, unlocked.text
    assert unlocked.json()["charged_credits"] == 1
    assert unlocked.json()["invoice_expires_at"] == issued_at + 24 * 60 * 60
    assert client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"] == before - 1


def test_first_challenge_saves_payee_and_mismatch_explains_how_to_change_it(client):
    api_key = _buy_client(client)
    first = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": api_key},
        json={"resource": "api/premium", "amount_sats": 1, "payee_lightning_address": "merchant@pay.example"},
    )
    assert first.status_code == 200, first.text
    saved = first.json()
    assert saved["payee_saved"] is True
    assert saved["payee_lightning_address"] == "merchant@pay.example"
    assert "POST /v1/client/payee" in saved["payee_note"]
    info = client.get("/v1/client", headers={"X-Api-Key": api_key}).json()
    assert info["payee_lightning_address"] == "merchant@pay.example"

    second = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": api_key},
        json={"resource": "api/premium", "amount_sats": 1, "payee_lightning_address": "other@pay.example"},
    )
    assert second.status_code == 400
    mismatch = second.json()
    assert mismatch["error"] == "payee_mismatch"
    assert mismatch["registered_payee_lightning_address"] == "merchant@pay.example"
    assert "saved" in mismatch["detail"]
    assert "POST /v1/client/payee" in mismatch["hint"]
    assert client.get("/v1/client", headers={"X-Api-Key": api_key}).json()["payee_lightning_address"] == "merchant@pay.example"

    changed = client.post(
        "/v1/client/payee",
        headers={"X-Api-Key": api_key},
        json={"payee_lightning_address": "other@pay.example"},
    )
    assert changed.status_code == 200, changed.text
    third = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": api_key},
        json={"resource": "api/next", "amount_sats": 1, "payee_lightning_address": "other@pay.example"},
    )
    assert third.status_code == 200, third.text
    assert third.json()["payee_saved"] is False
    assert third.json()["payee_note"] is None
    assert third.json()["payee_lightning_address"] == "other@pay.example"


def test_status_and_verify_share_one_charge_and_document_pending_codes(client):
    from app import config, db
    from app import wallet_lnaddr
    from app.invoices import InvoiceValidationError

    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/premium", amount_sats=21)
    before = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]
    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE paywall_challenges SET verify_url = ? WHERE payment_hash = ?",
            ("https://ln.example/verify/" + challenge["payment_hash"], challenge["payment_hash"]),
        )

    def _not_settled(**kwargs):
        assert kwargs["preimage_hex"] is None
        raise InvoiceValidationError("lud21_not_settled")

    original = wallet_lnaddr.confirm_lud21
    wallet_lnaddr.confirm_lud21 = _not_settled
    try:
        pending_status = client.get(
            f"/v1/paywall/status/{challenge['payment_hash']}",
            headers={"X-Api-Key": api_key, "Authorization": f"L402 {challenge['macaroon']}"},
            params={"expected_resource": "api/premium"},
        )
        pending_verify = client.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": api_key, "Authorization": f"L402 {challenge['macaroon']}"},
            json={"expected_resource": "api/premium"},
        )
    finally:
        wallet_lnaddr.confirm_lud21 = original

    assert pending_status.status_code == 200, pending_status.text
    status_body = pending_status.json()
    assert status_body["status"] == "pending"
    assert status_body["settled"] is False
    assert status_body["charged_credits"] == 0
    assert "402" in status_body["note"]
    assert "payment_pending" in status_body["note"]

    assert pending_verify.status_code == 402
    verify_body = pending_verify.json()
    assert verify_body["error"] == "payment_pending"
    assert verify_body["status"] == "pending"
    assert verify_body["charged_credits"] == 0
    assert "200" in verify_body["note"]
    assert client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"] == before

    wallet_lnaddr.confirm_lud21 = lambda **_kwargs: None
    try:
        unlocked = client.get(
            f"/v1/paywall/status/{challenge['payment_hash']}",
            headers={"X-Api-Key": api_key, "Authorization": f"L402 {challenge['macaroon']}"},
            params={"expected_resource": "api/premium", "cost_credits": 1},
        )
    finally:
        wallet_lnaddr.confirm_lud21 = original
    assert unlocked.status_code == 200, unlocked.text
    assert unlocked.json()["charged_credits"] == 1
    assert unlocked.json()["settled"] is True
    assert "GET /v1/paywall/status" in unlocked.json()["note"]
    assert client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"] == before - 1

    replay = client.post(
        "/v1/paywall/verify",
        headers={
            "X-Api-Key": api_key,
            "Authorization": _auth(
                challenge["macaroon"],
                client.get(f"/dev/mock/pay/{challenge['payment_hash']}").json()["preimage"],
            ),
        },
        json={"expected_resource": "api/premium"},
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["charged_credits"] == 0
    assert client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"] == before - 1


def test_paywall_window_env_rejects_bad_values(tmp_path):
    keys = ("SATSGATE_PAYWALL_TOKEN_TTL_CAP_SECONDS", "SATSGATE_PAYWALL_CLAIM_GRACE_SECONDS")
    try:
        with pytest.raises(RuntimeError, match="SATSGATE_PAYWALL_TOKEN_TTL_CAP_SECONDS must be an integer"):
            _load_app(tmp_path / "bad-int", SATSGATE_PAYWALL_TOKEN_TTL_CAP_SECONDS="abc")
        with pytest.raises(RuntimeError, match="SATSGATE_PAYWALL_CLAIM_GRACE_SECONDS cannot exceed"):
            _load_app(
                tmp_path / "grace",
                SATSGATE_PAYWALL_TOKEN_TTL_CAP_SECONDS="3600",
                SATSGATE_PAYWALL_CLAIM_GRACE_SECONDS="7200",
            )
    finally:
        for key in keys:
            os.environ.pop(key, None)


def test_topup_window_env_rejects_bad_values(tmp_path):
    keys = ("SATSGATE_TOPUP_TOKEN_TTL_CAP_SECONDS", "SATSGATE_TOPUP_CLAIM_GRACE_SECONDS")
    try:
        with pytest.raises(RuntimeError, match="must be an integer"):
            _load_app(tmp_path / "bad-int", SATSGATE_TOPUP_TOKEN_TTL_CAP_SECONDS="abc")
        with pytest.raises(RuntimeError, match="cannot exceed"):
            _load_app(
                tmp_path / "grace",
                SATSGATE_TOPUP_TOKEN_TTL_CAP_SECONDS="3600",
                SATSGATE_TOPUP_CLAIM_GRACE_SECONDS="7200",
            )
    finally:
        for key in keys:
            os.environ.pop(key, None)


def test_paywall_and_ticket_can_settle_from_stored_verify_url(client):
    from app import config, db
    from app.invoices import InvoiceValidationError
    from app import wallet_lnaddr

    api_key = _buy_client(client)
    challenge = _challenge(client, api_key, resource="api/premium", amount_sats=4)
    before = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]
    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE paywall_challenges SET verify_url = ? WHERE payment_hash = ?",
            ("https://ln.example/verify/" + challenge["payment_hash"], challenge["payment_hash"]),
        )

    def _not_settled(**kwargs):
        assert kwargs["preimage_hex"] is None
        raise InvoiceValidationError("lud21_not_settled")

    original = wallet_lnaddr.confirm_lud21
    wallet_lnaddr.confirm_lud21 = _not_settled
    try:
        pending = client.get(
            f"/v1/paywall/status/{challenge['payment_hash']}",
            headers={"X-Api-Key": api_key, "Authorization": f"L402 {challenge['macaroon']}"},
            params={"expected_resource": "api/premium"},
        )
    finally:
        wallet_lnaddr.confirm_lud21 = original
    assert pending.status_code == 200, pending.text
    assert pending.json()["settled"] is False
    assert client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"] == before

    stranger = _buy_client(client)
    rejected = client.get(
        f"/v1/paywall/status/{challenge['payment_hash']}",
        headers={"X-Api-Key": stranger, "Authorization": f"L402 {challenge['macaroon']}"},
        params={"expected_resource": "api/premium"},
    )
    assert rejected.status_code == 401
    assert rejected.json()["error"] == "client mismatch"

    wallet_lnaddr.confirm_lud21 = lambda **_kwargs: None
    try:
        unlocked = client.get(
            f"/v1/paywall/status/{challenge['payment_hash']}",
            headers={"X-Api-Key": api_key, "Authorization": f"L402 {challenge['macaroon']}"},
            params={"expected_resource": "api/premium"},
        )
    finally:
        wallet_lnaddr.confirm_lud21 = original
    assert unlocked.status_code == 200, unlocked.text
    assert unlocked.json()["charged_credits"] == 1
    assert client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"] == before - 1

    # Replay does not ask LUD-21 again and does not charge.
    wallet_lnaddr.confirm_lud21 = _not_settled
    try:
        replay = client.get(
            f"/v1/paywall/status/{challenge['payment_hash']}",
            headers={"X-Api-Key": api_key, "Authorization": f"L402 {challenge['macaroon']}"},
            params={"expected_resource": "api/premium"},
        )
    finally:
        wallet_lnaddr.confirm_lud21 = original
    assert replay.status_code == 200, replay.text
    assert replay.json()["charged_credits"] == 0

    ticket = client.get("/v1/tickets")
    assert ticket.status_code == 402, ticket.text
    ticket_body = ticket.json()
    with db._connect(config.DB_PATH) as conn:
        conn.execute(
            "UPDATE ticket_challenges SET verify_url = ? WHERE payment_hash = ?",
            ("https://ln.example/verify/" + ticket_body["payment_hash"], ticket_body["payment_hash"]),
        )
    wallet_lnaddr.confirm_lud21 = lambda **_kwargs: None
    try:
        granted = client.get("/v1/tickets", headers={"Authorization": f"L402 {ticket_body['macaroon']}"})
    finally:
        wallet_lnaddr.confirm_lud21 = original
    assert granted.status_code == 200, granted.text
    assert granted.json()["ticket"]["payment_hash"] == ticket_body["payment_hash"]


def test_public_openapi_hides_dev_and_admin_routes(tmp_path):
    import warnings

    from fastapi.testclient import TestClient

    dev = _load_app(tmp_path / "dev")
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        schema = dev.app.openapi()
    assert not any("Duplicate Operation ID" in str(item.message) for item in caught)
    operation_ids = [
        op.get("operationId")
        for ops in schema["paths"].values()
        for op in ops.values()
        if isinstance(op, dict)
    ]
    assert len(operation_ids) == len(set(operation_ids))

    production = _load_app(
        tmp_path / "prod",
        SATSGATE_ENV="production",
        SATSGATE_DEV_MODE="0",
        SATSGATE_WALLET_MODE="lnaddr",
        SATSGATE_LIGHTNING_ADDRESS="ops@example.com",
        SATSGATE_MACAROON_SECRET="ab" * 32,
        SATSGATE_ADMIN_TOKEN="prod-admin-token",
    )
    with TestClient(production.app) as http:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            public = http.get("/openapi.json")
        assert public.status_code == 200
        assert not any("Duplicate Operation ID" in str(item.message) for item in caught)
        paths = set(public.json()["paths"])
        assert "/v1/plans" in paths
        assert "/v1/topup/status/{payment_hash}" in paths
        assert "/v1/paywall/status/{payment_hash}" in paths
        assert "/v1/admin/overview" not in paths
        assert "/v1/tickets" not in paths
        assert "/v1/spend" not in paths
        assert "/dev/mock/pay/{payment_hash}" not in paths
        assert "/internal/gate/sites/{slug}" not in paths
        assert "/internal/gate/challenge" not in paths
        # The admin route still answers; it is only absent from the public document.
        hidden = http.get("/v1/admin/overview", headers={"X-Admin-Token": "prod-admin-token"})
        assert hidden.status_code == 200
        assert http.get("/v1/tickets").status_code == 404


def test_sdk_polls_topup_and_decodes_macaroon(client):
    import sys

    import httpx

    sdk_src = REPO_ROOT / "sdk" / "python" / "src"
    if str(sdk_src) not in sys.path:
        sys.path.insert(0, str(sdk_src))
    from satsgate_sdk import SatsgateClient, SatsgateError
    from satsgate_sdk.client import decode_macaroon_payload

    started = client.get("/v1/topup/trial")
    body = started.json()
    decoded = decode_macaroon_payload(body["macaroon"])
    assert decoded["v"] == 2
    assert decoded["ph"] == body["payment_hash"]
    assert decoded["res"] == "v1/topup/trial"
    assert decoded["purpose"] == "topup"

    calls = {"n": 0}

    def _handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == f"L402 {body['macaroon']}"
        assert ":" not in request.headers["authorization"].split(" ", 1)[1]
        assert request.url.path.endswith("/" + body["payment_hash"])
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(
                200,
                json={"ok": True, "status": "pending", "settled": False, "payment_hash": body["payment_hash"]},
            )
        return httpx.Response(
            200,
            json={
                "ok": True,
                "settled": True,
                "api_key": "sg_from_poll",
                "credits_added": 200,
                "new_balance": 200,
                "client_id": 1,
                "payment_hash": body["payment_hash"],
            },
        )

    sdk = SatsgateClient(base_url="http://testserver", api_key="unused")
    sdk._http.close()
    sdk._http = httpx.Client(transport=httpx.MockTransport(_handler), base_url="http://testserver")
    result = sdk.poll_topup(
        macaroon=body["macaroon"],
        payment_hash=body["payment_hash"],
        interval_seconds=0,
        timeout_seconds=5,
    )
    assert result["settled"] is True
    assert result["api_key"] == "sg_from_poll"
    assert calls["n"] == 2

    def _stuck(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True, "status": "pending", "settled": False})

    sdk._http.close()
    sdk._http = httpx.Client(transport=httpx.MockTransport(_stuck), base_url="http://testserver")
    with pytest.raises(SatsgateError) as caught:
        sdk.poll_topup(macaroon=body["macaroon"], payment_hash=body["payment_hash"], interval_seconds=0, timeout_seconds=0)
    assert "pending" in str(caught.value)
