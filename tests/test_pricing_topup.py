"""T-5.4 and T-5.5. Amount top-ups, retired packs, and the accounting rate."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

os.environ.setdefault("SATSGATE_ENV", "test")
os.environ.setdefault("SATSGATE_MACAROON_SECRET", "test-secret")


def _app(tmp_path: Path):
    os.environ["SATSGATE_ENV"] = "development"
    os.environ["SATSGATE_WALLET_MODE"] = "mock"
    os.environ["SATSGATE_DEV_MODE"] = "1"
    os.environ["SATSGATE_RL_ENABLED"] = "0"
    os.environ["SATSGATE_MACAROON_SECRET"] = "test-secret"
    os.environ["SATSGATE_DB_PATH"] = str(tmp_path / "topup.sqlite3")
    os.environ["SATSGATE_LN_NETWORK"] = "mainnet"
    import importlib
    import sys

    for name in list(sys.modules):
        if name == "app" or name.startswith("app."):
            sys.modules.pop(name, None)
    return importlib.import_module("app.main")


def _auth(macaroon: str, preimage: str) -> str:
    return f"L402 {macaroon}:{preimage}"


def test_t_5_4_1_plans_describe_model_b(tmp_path: Path) -> None:
    module = _app(tmp_path)
    with TestClient(module.app) as client:
        body = client.get("/v1/plans").json()
    assert "trial" not in str(body).lower() or body.get("model") == "B"
    assert body["model"] == "B"
    assert body["quota"] == module.config.FREE_QUOTA
    assert body["fee_msat"] == 2000
    assert body["fee_cap_bps"] == 1000
    assert body["usdc_floor_usd"] == "0.001"
    assert body["topup_min_sats"] == 1000
    assert body["prepaid_expires"] is False
    assert body["quota_resets"] == "day 1 00:00:00 UTC"
    assert body["bonus_tiers"][1]["bonus_bps"] == 1000
    assert body["bonus_tiers"][2]["bonus_bps"] == 2000


def test_t_5_4_2_and_8_lightning_amount_and_retired_packs(tmp_path: Path) -> None:
    module = _app(tmp_path)
    with TestClient(module.app) as client:
        small = client.post("/v1/topup/lightning", json={"sats": 999})
        assert small.status_code == 400
        assert small.json()["error"] == "amount_too_small"
        started = client.post("/v1/topup/lightning", json={"sats": 1000})
        assert started.status_code == 402, started.text
        body = started.json()
        assert body["msat_credit"] == 1_000_000
        preimage = client.get(f"/dev/mock/pay/{body['payment_hash']}").json()["preimage"]
        settled = client.post(
            "/v1/topup/lightning",
            json={"sats": 1000},
            headers={"Authorization": _auth(body["macaroon"], preimage)},
        )
        assert settled.status_code == 200, settled.text
        key = settled.json()["api_key"]
        assert client.get("/v1/balance", headers={"X-Api-Key": key}).status_code == 200
        # Legacy credits column is msat/2000. The balance_msat column is the credit.
        with module.db._connect(module.config.DB_PATH) as conn:
            row = conn.execute("SELECT balance_msat FROM clients").fetchone()
        assert int(row[0]) == 1_000_000
        for plan in ("trial", "starter", "growth", "scale", "hyper", "mega"):
            for path in (f"/v1/topup/{plan}", f"/v1/topup/{plan}/x402"):
                gone = client.get(path)
                assert gone.status_code == 410, path
                assert gone.json()["error"] == "packs_retired"
                assert gone.json()["topup_lightning"] == "/v1/topup/lightning"


def test_t_5_4_3_bonus_boundaries() -> None:
    from app.pricing import bonus_bps, credit_msat_for_principal

    assert bonus_bps(99_999) == 0
    assert credit_msat_for_principal(99_999) == 99_999_000
    assert bonus_bps(100_000) == 1000
    assert credit_msat_for_principal(100_000) == 110_000_000
    assert bonus_bps(999_999) == 1000
    assert credit_msat_for_principal(999_999) == 1_099_998_900
    assert bonus_bps(1_000_000) == 2000
    assert credit_msat_for_principal(1_000_000) == 1_200_000_000
    assert credit_msat_for_principal(50_000) == 50_000_000
    assert credit_msat_for_principal(50_000) == 50_000_000


def test_t_5_11_and_12_terms_and_headline() -> None:
    root = Path(__file__).resolve().parents[1]
    terms = (root / "docs" / "hosted-gate-terms.md").read_text(encoding="utf-8")
    lowered = terms.lower()
    assert "draft" not in lowered
    for phrase in (
        "not money",
        "not redeemable",
        "credit to the prepaid balance",
        "500 free",
        "does not expire",
        "00:00:00 utc",
        "does not take custody",
        "cuba",
        "iran",
        "north korea",
        "24 hours",
        "origin failed after a receipt",
    ):
        assert phrase in lowered, phrase
    readme = (root / "README.md").read_text(encoding="utf-8")
    assert "Cobrale a agentes de IA en Lightning y USDC, en el mismo 402. La plata va directo a tu billetera. 500 cobros gratis por mes." in readme
    assert "anónimo" not in readme.lower()
    quick = (root / "CUSTOMER_QUICKSTART.md").read_text(encoding="utf-8")
    import re

    banned = re.compile(r"\b(trial|starter|growth|scale|hyper|mega)\b", re.I)
    for label, text in (("README", readme), ("CUSTOMER_QUICKSTART", quick)):
        assert banned.search(text) is None, label
        lowered_doc = text.lower()
        assert "1 credit = 1 unlock" not in lowered_doc
        assert "spends **1 credit**" not in lowered_doc
        assert "spends 1 credit" not in lowered_doc


def test_t_5_2_5_cache_does_not_reread_within_the_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replaces the old CoinGecko cache test. The window is the effective-rate cache."""
    from app import accounting_rate, chainlink
    from test_chainlink import oracle_poster

    accounting_rate.reset_for_tests()
    calls = {"n": 0}
    inner = oracle_poster(80_070, updated_at=1_000)

    def poster(url, payload, headers, timeout):
        if payload.get("method") == "eth_chainId":
            calls["n"] += 1
        return inner(url, payload, headers, timeout)

    monkeypatch.setattr(chainlink, "poster", poster)
    monkeypatch.setattr(accounting_rate.rates, "quote_rate", lambda now=None: None)
    monkeypatch.setattr(accounting_rate.config, "ACCOUNTING_RATE_CACHE_S", 60)
    first = accounting_rate.effective_rate(now=1_000)
    second = accounting_rate.effective_rate(now=1_050)
    assert first is not None and first.source == "oracle"
    assert second.rate_num == first.rate_num
    assert calls["n"] == 1
    third = accounting_rate.effective_rate(now=1_000 + 60)
    assert calls["n"] == 2
    assert third is not None and third.source == "oracle"
