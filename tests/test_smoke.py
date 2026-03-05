from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest


def _fresh_import_app(tmp_path: Path):
    """Import the FastAPI app with a clean module cache.

    Important: satsgate loads config at import-time, so we set env vars before importing.
    """

    # Ensure repository root is importable as a module root.
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

    # Configure env for a fully-local test run
    os.environ["SATSGATE_WALLET_MODE"] = "mock"
    os.environ["SATSGATE_DEV_MODE"] = "1"
    os.environ["SATSGATE_RL_ENABLED"] = "0"
    os.environ["SATSGATE_MACAROON_SECRET"] = "test-secret"
    os.environ["SATSGATE_DB_PATH"] = str(tmp_path / "satsgate_test.sqlite3")

    # Ensure a clean import (config is loaded at import time)
    for name in list(sys.modules.keys()):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)

    m = importlib.import_module("app.main")
    return m.app


@pytest.fixture()
def client(tmp_path):
    from fastapi.testclient import TestClient

    app = _fresh_import_app(tmp_path)
    with TestClient(app) as c:
        yield c


def _auth(macaroon: str, preimage_hex: str) -> str:
    return f"L402 {macaroon}:{preimage_hex}"


def test_manifest_and_plans(client):
    # Uptime monitors may use HEAD
    assert client.head("/health").status_code == 200
    assert client.head("/.well-known/satsgate.json").status_code == 200

    r = client.get("/.well-known/satsgate.json")
    assert r.status_code == 200
    data = r.json()
    assert data["schema"] == "satsgate.manifest.v1"
    assert data["api"]["endpoints"]["plans"]["path"] == "/v1/plans"

    r2 = client.get("/v1/plans")
    assert r2.status_code == 200
    assert r2.json()["ok"] is True


def test_topup_flow_creates_api_key_and_credits(client):
    # Start topup
    r1 = client.get("/v1/topup/trial")
    assert r1.status_code == 402
    d1 = r1.json()
    assert d1["error"] == "payment_required"
    assert d1["plan"]["id"] == "trial"

    payment_hash = d1["payment_hash"]
    macaroon = d1["macaroon"]

    # Mock pay to get preimage
    r2 = client.get(f"/dev/mock/pay/{payment_hash}")
    assert r2.status_code == 200
    preimage = r2.json()["preimage"]

    # Finalize topup
    r3 = client.get(
        "/v1/topup/trial",
        headers={"Authorization": _auth(macaroon, preimage)},
    )
    assert r3.status_code == 200
    d3 = r3.json()
    assert d3["ok"] is True
    api_key = d3["api_key"]
    assert api_key.startswith("sg_")

    # Balance must equal plan credits (trial)
    r4 = client.get("/v1/balance", headers={"X-Api-Key": api_key})
    assert r4.status_code == 200
    d4 = r4.json()
    assert d4["credits"] == d3["new_balance"]
    assert d4["credits"] == d1["plan"]["credits"]


def test_paywall_verify_is_idempotent_per_payment_hash(client):
    # Buy credits
    r1 = client.get("/v1/topup/trial")
    d1 = r1.json()
    ph1 = d1["payment_hash"]
    mac1 = d1["macaroon"]
    pre1 = client.get(f"/dev/mock/pay/{ph1}").json()["preimage"]
    topup = client.get("/v1/topup/trial", headers={"Authorization": _auth(mac1, pre1)}).json()
    api_key = topup["api_key"]

    bal_before = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]

    # Challenge paywall
    r2 = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": api_key},
        json={"resource": "demo/test", "amount_sats": 1},
    )
    assert r2.status_code == 200
    ch = r2.json()
    ph = ch["payment_hash"]
    mac = ch["macaroon"]

    pre = client.get(f"/dev/mock/pay/{ph}").json()["preimage"]
    auth = _auth(mac, pre)

    # Verify once => charged
    r3 = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": auth},
        json={"expected_resource": "demo/test", "cost_credits": 1},
    )
    assert r3.status_code == 200
    v1 = r3.json()
    assert v1["charged_credits"] == 1

    # Verify again with same payment_hash => not charged
    r4 = client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": auth},
        json={"expected_resource": "demo/test", "cost_credits": 1},
    )
    assert r4.status_code == 200
    v2 = r4.json()
    assert v2["charged_credits"] == 0

    bal_after = client.get("/v1/balance", headers={"X-Api-Key": api_key}).json()["credits"]
    assert bal_after == bal_before - 1


def test_forecast_has_recommendation_keys(client):
    # Buy credits
    r1 = client.get("/v1/topup/trial")
    d1 = r1.json()
    ph1 = d1["payment_hash"]
    mac1 = d1["macaroon"]
    pre1 = client.get(f"/dev/mock/pay/{ph1}").json()["preimage"]
    topup = client.get("/v1/topup/trial", headers={"Authorization": _auth(mac1, pre1)}).json()
    api_key = topup["api_key"]

    # Create and verify one payment so forecast has some data
    ch = client.post(
        "/v1/paywall/challenge",
        headers={"X-Api-Key": api_key},
        json={"resource": "demo/test", "amount_sats": 1},
    ).json()
    pre = client.get(f"/dev/mock/pay/{ch['payment_hash']}").json()["preimage"]
    auth = _auth(ch["macaroon"], pre)
    client.post(
        "/v1/paywall/verify",
        headers={"X-Api-Key": api_key, "Authorization": auth},
        json={"expected_resource": "demo/test", "cost_credits": 1},
    )

    r2 = client.get(
        "/v1/usage/forecast",
        headers={"X-Api-Key": api_key},
        params={"lookback_hours": 24, "buffer_days": 7, "max_topups": 3, "trigger_hours": 24},
    )
    assert r2.status_code == 200
    data = r2.json()
    assert data["ok"] is True

    rec = data["recommendation"]
    assert "recommended_purchase" in rec
    assert "should_topup_now" in rec
    assert "trigger_at_iso" in rec
