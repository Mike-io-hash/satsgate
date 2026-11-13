"""Public quote silence, and the removal of the old price vendor."""

from __future__ import annotations

from pathlib import Path

from eth_account import Account
from fastapi.testclient import TestClient

from test_chainlink import oracle_poster
from test_x402 import _buy, _gate, _load_app, _patch_dns, _site, _verify_payee
from test_x402_topup import _app, _quote

_FORBIDDEN = ("bitstamp", "coinbase", "kraken", "chainlink", "coingecko", "d23_median")
_ROOT = Path(__file__).resolve().parents[1]


def _body_is_quiet(body: str) -> None:
    lowered = body.lower()
    for word in _FORBIDDEN:
        assert word not in lowered, word


def test_t_5_3_1_public_rate_has_no_source_names(tmp_path, monkeypatch) -> None:
    module = _load_app(tmp_path)
    module.chainlink.poster = oracle_poster(80_070)
    module.accounting_rate.reset_for_tests()
    with TestClient(module.app) as http:
        public = http.get("/v1/rates")
        assert public.status_code == 200
        body = public.json()
        assert body["ok"] is True
        assert body["pair"] == "BTC-USD"
        assert body["status"] == "ok"
        assert body["value"] == "80070"
        assert isinstance(body["fetched_at"], int)
        assert "sources" not in body
        assert body["source"] == "oracle"
        _body_is_quiet(public.text)
        known = http.get("/.well-known/satsgate.json")
        assert known.status_code == 200
        _body_is_quiet(known.text)


def test_t_5_3_2_fallback_is_generic(tmp_path, monkeypatch) -> None:
    module = _load_app(tmp_path)
    module.chainlink.poster = lambda *_args, **_kwargs: (
        200,
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "down"}},
    )
    module.accounting_rate.reset_for_tests()
    _quote(module, "65000")
    with TestClient(module.app) as http:
        public = http.get("/v1/rates")
        assert public.status_code == 200
        body = public.json()
        assert body["status"] == "ok"
        assert body["value"] == "65000"
        assert body["source"] == "fallback"
        assert "sources" not in body
        _body_is_quiet(public.text)


def test_t_5_3_3_both_down_is_unavailable(tmp_path, monkeypatch) -> None:
    module = _load_app(tmp_path)
    module.chainlink.poster = lambda *_args, **_kwargs: (
        200,
        {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "down"}},
    )
    module.accounting_rate.reset_for_tests()
    module.rates._state = None
    with TestClient(module.app) as http:
        public = http.get("/v1/rates")
        assert public.status_code == 200
        body = public.json()
        assert body["status"] == "unavailable"
        assert body["value"] is None
        assert "sources" not in body
        assert body.get("source") in (None,)
        _body_is_quiet(public.text)


def test_t_5_3_4_topup_rate_object_is_generic(tmp_path, monkeypatch) -> None:
    treasury = Account.create()
    module = _app(tmp_path, monkeypatch, treasury.address)
    _patch_dns(monkeypatch, module)
    module.chainlink.poster = oracle_poster(80_070)
    module.accounting_rate.reset_for_tests()
    with TestClient(module.app) as http:
        key = _buy(http)
        offered = http.post("/v1/topup/usdc", headers={"X-Api-Key": key}, json={"usd": "1.00"})
        assert offered.status_code == 402, offered.text
        rate = offered.json()["rate"]
        assert set(rate) == {"source", "rate_num", "rate_den", "fetched_at"}
        assert rate["source"] == "oracle"
        _body_is_quiet(offered.text)


def test_t_5_3_5_buyer_402_rate_view_is_numbers_only(tmp_path, monkeypatch) -> None:
    module = _load_app(tmp_path)
    _patch_dns(monkeypatch, module)
    owner = Account.create()
    module.chainlink.poster = oracle_poster(65_000)
    module.accounting_rate.reset_for_tests()
    _quote(module, "65000")
    with TestClient(module.app) as http:
        key = _buy(http)
        _verify_payee(http, key, owner)
        _site(http, key, path="/blog/post", body={"price_sats": 21})
        http.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"rail_x402": True, "x402_mode": "test"})
        issued = _gate(http, "POST", "/internal/gate/challenge", json={"slug": "my-shop", "path": "/blog/post"})
        assert issued.status_code == 200, issued.text
        rate = issued.json()["rate"]
        assert set(rate) == {"rate_num", "rate_den", "fetched_at"}
        _body_is_quiet(issued.text)


def test_t_5_4_1_vendor_name_is_gone_from_the_tree() -> None:
    needles = ("api.coingecko.com", "SATSGATE_COINGECKO_API_KEY", "x_cg_demo_api_key")
    roots = [_ROOT / "app", _ROOT / "gate", _ROOT / "proxy", _ROOT / "sdk", _ROOT / "mcp", _ROOT / "docs"]
    files = [path for root in roots for path in root.rglob("*") if path.is_file()]
    files.extend([_ROOT / "docker-compose.yml", _ROOT / ".env.example"])
    for path in files:
        if path.name == "CHANGELOG.md" or "test_public_rate.py" in path.name:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for needle in needles:
            assert needle not in text, f"{needle} in {path}"
    for path in (_ROOT / "app").rglob("*.py"):
        assert "coingecko" not in path.read_text(encoding="utf-8").lower(), path


def test_t_5_4_2_and_t_5_4_3_boot_without_the_old_key(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("SATSGATE_COINGECKO_API_KEY", raising=False)
    module = _load_app(tmp_path)
    assert not hasattr(module.config, "COINGECKO_API_KEY")
    with TestClient(module.app) as http:
        health = http.get("/health")
        assert health.status_code == 200
        assert health.json()["ok"] is True
