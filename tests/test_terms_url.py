"""SATSGATE_TERMS_URL on the API, and the paywall top-up hint (T-B.2)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from test_sites import _create, _patch_dns
from test_x402 import _load_app

ROOT = Path(__file__).resolve().parents[1]
TERMS = "https://satsgate.org/terms"
TOPUP_HINT = "Top up with POST /v1/topup/lightning or POST /v1/topup/usdc."
OLD_HINT = "GET /v1/plans then /v1/topup/{plan_id}"


def _auth(macaroon: str, preimage_hex: str) -> str:
    return f"L402 {macaroon}:{preimage_hex}"


def test_t_b_2_1_well_known_returns_the_terms_url(tmp_path: Path) -> None:
    module = _load_app(tmp_path, SATSGATE_TERMS_URL=TERMS)
    with TestClient(module.app) as http:
        body = http.get("/.well-known/satsgate.json").json()
    assert body["terms_url"] == TERMS


def test_t_b_2_2_well_known_terms_url_is_null_when_unset(tmp_path: Path) -> None:
    module = _load_app(tmp_path)
    assert module.config.TERMS_URL == ""
    with TestClient(module.app) as http:
        body = http.get("/.well-known/satsgate.json").json()
    assert "terms_url" in body
    assert body["terms_url"] is None


def test_t_b_2_4_plans_include_terms_url(tmp_path: Path) -> None:
    set_module = _load_app(tmp_path, SATSGATE_TERMS_URL=TERMS)
    with TestClient(set_module.app) as http:
        body = http.get("/v1/plans").json()
    assert body["terms_url"] == TERMS
    assert body["model"] == "B"

    os.environ.pop("SATSGATE_TERMS_URL", None)
    unset = _load_app(tmp_path)
    with TestClient(unset.app) as http:
        body = http.get("/v1/plans").json()
    assert "terms_url" in body
    assert body["terms_url"] is None


def test_t_b_2_5_signup_201_includes_terms_url_and_still_takes_an_empty_body(tmp_path: Path) -> None:
    module = _load_app(tmp_path, SATSGATE_TERMS_URL=TERMS)
    with TestClient(module.app) as http:
        opened = http.post("/v1/accounts", json={})
        assert opened.status_code == 201
        body = opened.json()
        assert body["terms_url"] == TERMS
        assert body["ok"] is True
        assert isinstance(body["client_id"], int)
        assert isinstance(body["api_key"], str) and body["api_key"].startswith("sg_")
        assert body["balance_msat"] == 0
        assert "balance_sats" in body
        assert "estimated_unlocks_remaining" in body
        refused = http.post("/v1/accounts", json={"email": "person@example.com"})
        assert refused.status_code == 422

    os.environ.pop("SATSGATE_TERMS_URL", None)
    unset = _load_app(tmp_path)
    with TestClient(unset.app) as http:
        opened = http.post("/v1/accounts", json={})
        assert opened.status_code == 201
        assert opened.json()["terms_url"] is None
        assert opened.json()["api_key"].startswith("sg_")


def test_t_b_2_6_client_includes_terms_url(tmp_path: Path) -> None:
    module = _load_app(tmp_path, SATSGATE_TERMS_URL=TERMS)
    with TestClient(module.app) as http:
        opened = http.post("/v1/accounts", json={})
        assert opened.status_code == 201
        key = opened.json()["api_key"]
        client = http.get("/v1/client", headers={"X-Api-Key": key})
        assert client.status_code == 200
        body = client.json()
        assert body["terms_url"] == TERMS
        assert body["balance_msat"] == 0
        assert "estimated_unlocks_remaining" in body

    os.environ.pop("SATSGATE_TERMS_URL", None)
    unset = _load_app(tmp_path)
    with TestClient(unset.app) as http:
        opened = http.post("/v1/accounts", json={})
        assert opened.status_code == 201
        client = http.get("/v1/client", headers={"X-Api-Key": opened.json()["api_key"]})
        assert client.status_code == 200
        assert client.json()["terms_url"] is None


def test_public_directory_includes_terms_url_when_set(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module = _load_app(tmp_path, SATSGATE_TERMS_URL=TERMS)
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        opened = http.post("/v1/accounts", json={})
        assert opened.status_code == 201
        key = opened.json()["api_key"]
        _create(http, key)
        route = http.post(
            "/v1/sites/my-shop/routes",
            headers={"X-Api-Key": key},
            json={"path": "/post", "price_sats": 21, "max_uses": 1},
        )
        assert route.status_code == 200
        approved = http.post("/v1/admin/sites/my-shop/approve", headers={"X-Admin-Token": "test-admin-token"})
        assert approved.status_code == 200
        public = http.get("/v1/sites")
        assert public.status_code == 200
        assert public.json()["terms_url"] == TERMS


def test_t_b_2_7_http_or_userinfo_terms_url_refuses_to_start(tmp_path: Path) -> None:
    for bad in ("http://satsgate.org/terms", "https://alice@satsgate.org/terms"):
        with pytest.raises(RuntimeError, match="SATSGATE_TERMS_URL"):
            _load_app(tmp_path, SATSGATE_TERMS_URL=bad)


def test_t_b_2_8_paywall_hint_names_amount_topup(tmp_path: Path) -> None:
    for path in (ROOT / "app").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert OLD_HINT not in text, path
    module = _load_app(tmp_path)
    with TestClient(module.app) as http:
        started = http.post("/v1/topup/lightning", json={"sats": 1000})
        assert started.status_code == 402
        issued = started.json()
        paid = http.get(f"/dev/mock/pay/{issued['payment_hash']}")
        assert paid.status_code == 200
        preimage = paid.json()["preimage"]
        settled = http.post(
            "/v1/topup/lightning",
            json={"sats": 1000},
            headers={"Authorization": _auth(issued["macaroon"], preimage)},
        )
        assert settled.status_code == 200
        api_key = settled.json()["api_key"]
        challenge = http.post(
            "/v1/paywall/challenge",
            headers={"X-Api-Key": api_key},
            json={"resource": "api/broke", "amount_sats": 1},
        )
        assert challenge.status_code == 200
        issued_challenge = challenge.json()
        paid_challenge = http.get(f"/dev/mock/pay/{issued_challenge['payment_hash']}")
        assert paid_challenge.status_code == 200
        authorization = _auth(issued_challenge["macaroon"], paid_challenge.json()["preimage"])
        from app import config, db

        with db._connect(config.DB_PATH) as conn:
            conn.execute("UPDATE clients SET credits = 0, balance_msat = 0")
        denied = http.post(
            "/v1/paywall/verify",
            headers={"X-Api-Key": api_key, "Authorization": authorization},
            json={"expected_resource": "api/broke"},
        )
        assert denied.status_code == 402
        assert denied.json()["error"] == "insufficient balance"
        assert denied.json()["hint"] == TOPUP_HINT
        assert "plan_id" not in denied.json()["hint"]
