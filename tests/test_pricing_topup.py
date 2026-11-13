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


def test_t_5_5_buyer_quote_ignores_coingecko(monkeypatch: pytest.MonkeyPatch) -> None:
    from app import rates
    from app.rates import Rate

    buyer = Rate(rate_num=80_070 * rates.RATE_DEN, rate_den=rates.RATE_DEN, fetched_at=1, sources=("bitstamp",), value="80070")
    monkeypatch.setattr(rates, "quote_rate", lambda now=None: buyer)
    atomic = rates.usd_atomic_from_sats(1000, buyer)
    # A different accounting rate must not be an input to this function.
    assert atomic == rates.usd_atomic_from_sats(1000, buyer)


def test_t_5_5_cache_and_backup(monkeypatch: pytest.MonkeyPatch) -> None:
    from app import accounting_rate, rates
    from app.rates import Rate

    accounting_rate.reset_for_tests()
    calls = {"n": 0}

    def _fetch(_url: str):
        calls["n"] += 1
        return {"bitcoin": {"usd": 80070}}

    monkeypatch.setattr(accounting_rate, "fetcher", _fetch)
    monkeypatch.setattr(accounting_rate.config, "ACCOUNTING_RATE_CACHE_S", 300)
    monkeypatch.setattr(accounting_rate.config, "ACCOUNTING_RATE_STALE_S", 3600)
    first = accounting_rate.accounting_rate(now=1_000)
    second = accounting_rate.accounting_rate(now=1_100)
    assert first is not None and first.source == "coingecko"
    assert second.source == "coingecko"
    assert calls["n"] == 1
    third = accounting_rate.accounting_rate(now=1_000 + 301)
    assert calls["n"] == 2
    assert third.source == "coingecko"

    accounting_rate.reset_for_tests()

    def _down(_url: str):
        return None

    monkeypatch.setattr(accounting_rate, "fetcher", _down)
    backup = Rate(
        rate_num=90_000 * rates.RATE_DEN,
        rate_den=rates.RATE_DEN,
        fetched_at=5_000,
        sources=("kraken",),
        value="90000",
    )
    monkeypatch.setattr(rates, "snapshot", lambda now=None: {
        "status": "stale",
        "value": "90000",
        "sources": ["kraken"],
        "fetched_at": 5_000,
        "rate_num": backup.rate_num,
        "rate_den": backup.rate_den,
    })
    used = accounting_rate.accounting_rate(now=5_100)
    assert used is not None and used.source == "d23_median"
    missing = accounting_rate.accounting_rate(now=5_000 + 3601)
    assert missing is None
