"""Open hosted gate: honest onboarding text, activation reasons, and a clear answer for inactive sites.

T-GO.1 create note. T-GO.2 activation reasons. T-GO.3 terms error and manifest.
T-GO.4 internal status. T-GO.5 public gate answer.
"""

from __future__ import annotations

import importlib

from fastapi.testclient import TestClient

from test_receipt_acceptance import _proof_body
from test_satsgate_gate import _buy, _close, _load_app, _open_gate, _patch_dns, _settings

_ADMIN = {"X-Admin-Token": "test-admin-token"}
_GATE_TOKEN = "test-gate-token"


def _mod(name: str):
    return importlib.import_module(name)


def _create(http: TestClient, key: str, *, slug: str = "my-shop", accept: str | None = "v1"):
    body = {"slug": slug, "display_name": "My Shop", "origin_url": "https://origin.example", "listed": False}
    if accept is not None:
        body["accept_terms"] = accept
    return http.post("/v1/sites", headers={"X-Api-Key": key}, json=body)


def _codes(site: dict) -> list[str]:
    return [reason["code"] for reason in site["activation"]["reasons"]]


def _verify(http: TestClient, monkeypatch, module, key: str, secret: str, slug: str = "my-shop"):
    monkeypatch.setattr(_mod("app.origin_check"), "safe_get_response", _proof_body(module, secret))
    checked = http.post(f"/v1/sites/{slug}/verify-origin", headers={"X-Api-Key": key})
    assert checked.status_code == 200, checked.text
    return checked.json()


# T-GO.1 -------------------------------------------------------------------


def test_t_go_1_1_note_with_auto_approve_on(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_SITES_AUTO_APPROVE="1", SATSGATE_TERMS_VERSION="v1")
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        created = _create(http, _buy(http))
        assert created.status_code == 200, created.text
        note = created.json()["note"]
        assert "goes live by itself after a successful origin check" in note
        assert "operator" not in note
        assert "X-Satsgate-Signature" not in note
        assert "Satsgate-Receipt" in note
        assert created.json()["site"]["status"] == "pending"
        assert _codes(created.json()["site"]) == ["origin_not_verified"]


def test_t_go_1_2_note_with_auto_approve_off(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_SITES_AUTO_APPROVE="0", SATSGATE_TERMS_VERSION="v1")
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        created = _create(http, _buy(http))
        assert created.status_code == 200, created.text
        note = created.json()["note"]
        assert "an operator approves new sites" in note
        assert "goes live by itself" not in note
        assert _codes(created.json()["site"]) == ["operator_review"]
        assert "origin_secret" not in created.json()["site"]


# T-GO.2 -------------------------------------------------------------------


def test_t_go_2_1_origin_check_makes_the_site_live(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_SITES_AUTO_APPROVE="1", SATSGATE_TERMS_VERSION="v1")
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        created = _create(http, key)
        detail = created.json()["site"]["activation"]["reasons"][0]["detail"]
        assert "/.well-known/satsgate-check" in detail
        assert "POST /v1/sites/my-shop/verify-origin" in detail
        checked = _verify(http, monkeypatch, module, key, created.json()["origin_secret"])
        assert checked["status"] == "approved"
        assert checked["site"]["activation"] == {"live": True, "reasons": []}
        one = http.get("/v1/sites/my-shop", headers={"X-Api-Key": key}).json()["site"]
        assert one["activation"] == {"live": True, "reasons": []}
        mine = http.get("/v1/sites/mine", headers={"X-Api-Key": key}).json()["sites"]
        assert mine[0]["activation"] == {"live": True, "reasons": []}
        assert "origin_secret" not in one


def test_t_go_2_2_stale_terms_then_accept(tmp_path, monkeypatch):
    module = _load_app(
        tmp_path,
        SATSGATE_SITES_AUTO_APPROVE="1",
        SATSGATE_TERMS_VERSION="v1",
        SATSGATE_TERMS_URL="https://terms.example/terms",
    )
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        created = _create(http, key)
        monkeypatch.setattr(module.config, "TERMS_VERSION", "v2")
        checked = _verify(http, monkeypatch, module, key, created.json()["origin_secret"])
        assert checked["status"] == "pending"
        reasons = checked["site"]["activation"]["reasons"]
        assert [reason["code"] for reason in reasons] == ["terms_not_accepted"]
        assert reasons[0]["terms_version"] == "v2"
        assert reasons[0]["terms_url"] == "https://terms.example/terms"
        assert '{"accept_terms": "v2"}' in reasons[0]["detail"]
        patched = http.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"accept_terms": "v2"})
        assert patched.status_code == 200, patched.text
        assert patched.json()["site"]["status"] == "approved"
        assert patched.json()["site"]["activation"] == {"live": True, "reasons": []}


def test_t_go_2_3_recheck_after_the_switch_turns_on(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_SITES_AUTO_APPROVE="0", SATSGATE_TERMS_VERSION="v1")
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        created = _create(http, key)
        checked = _verify(http, monkeypatch, module, key, created.json()["origin_secret"])
        assert checked["status"] == "pending"
        assert _codes(checked["site"]) == ["operator_review"]
        monkeypatch.setattr(module.config, "SITES_AUTO_APPROVE", True)
        one = http.get("/v1/sites/my-shop", headers={"X-Api-Key": key}).json()["site"]
        assert _codes(one) == ["recheck_needed"]
        again = _verify(http, monkeypatch, module, key, created.json()["origin_secret"])
        assert again["status"] == "approved"
        assert again["site"]["activation"]["live"] is True


def test_t_go_2_4_disabled_names_the_contact(tmp_path, monkeypatch):
    module = _load_app(
        tmp_path,
        SATSGATE_SITES_AUTO_APPROVE="1",
        SATSGATE_TERMS_VERSION="v1",
        SATSGATE_ABUSE_CONTACT="abuse@example.com",
    )
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        _create(http, key)
        assert http.post("/v1/admin/sites/my-shop/disable", headers=_ADMIN).status_code == 200
        site = http.get("/v1/sites/my-shop", headers={"X-Api-Key": key}).json()["site"]
        assert site["activation"]["live"] is False
        assert _codes(site) == ["site_disabled"]
        assert "abuse@example.com" in site["activation"]["reasons"][0]["detail"]
        monkeypatch.setattr(module.config, "ABUSE_CONTACT", "")
        bare = http.get("/v1/sites/my-shop", headers={"X-Api-Key": key}).json()["site"]
        assert bare["activation"]["reasons"][0]["detail"] == "The operator turned this site off."


def test_t_go_2_5_suspended_account_is_not_live(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_SITES_AUTO_APPROVE="1", SATSGATE_TERMS_VERSION="v1")
    _patch_dns(monkeypatch, module)
    with TestClient(module.app) as http:
        key = _buy(http)
        created = _create(http, key)
        _verify(http, monkeypatch, module, key, created.json()["origin_secret"])
        client_id = http.get("/v1/client", headers={"X-Api-Key": key}).json()["client_id"]
        module.db.suspend_client(module.config.DB_PATH, client_id=int(client_id), reason="test")
        site = http.get("/v1/sites/my-shop", headers={"X-Api-Key": key}).json()["site"]
        assert site["status"] == "disabled"
        assert site["activation"]["live"] is False
        assert _codes(site) == ["account_suspended", "site_disabled"]


# T-GO.3 -------------------------------------------------------------------


def test_t_go_3_1_terms_error_names_the_version(tmp_path, monkeypatch):
    module = _load_app(
        tmp_path,
        SATSGATE_SITES_AUTO_APPROVE="1",
        SATSGATE_TERMS_VERSION="v1",
        SATSGATE_TERMS_URL="https://terms.example/terms",
    )
    _patch_dns(monkeypatch, module)
    expected = {
        "ok": False,
        "error": "terms_not_accepted",
        "terms_version": "v1",
        "terms_url": "https://terms.example/terms",
    }
    with TestClient(module.app) as http:
        key = _buy(http)
        missing = _create(http, key, accept=None)
        assert missing.status_code == 400
        assert missing.json() == expected
        old = _create(http, key, accept="v0")
        assert old.status_code == 400
        assert old.json() == expected
        assert _create(http, key).status_code == 200
        patched = http.patch("/v1/sites/my-shop", headers={"X-Api-Key": key}, json={"accept_terms": "v0"})
        assert patched.status_code == 400
        assert patched.json() == expected


def test_t_go_3_2_manifest_description_and_terms_version(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_TERMS_VERSION="v1")
    with TestClient(module.app) as http:
        manifest = http.get("/.well-known/satsgate.json").json()
        assert manifest["terms_version"] == "v1"
        text = manifest["description"]
        assert "credits" not in text.lower()
        assert "verification" not in text.lower()
        assert "seller's wallet" in text
        assert "prepaid balance" in text
    (tmp_path / "empty").mkdir()
    bare = _load_app(tmp_path / "empty", SATSGATE_TERMS_VERSION="")
    with TestClient(bare.app) as http:
        assert http.get("/.well-known/satsgate.json").json()["terms_version"] is None


# T-GO.4 -------------------------------------------------------------------


def test_t_go_4_1_internal_status_three_answers(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_SITES_AUTO_APPROVE="1", SATSGATE_TERMS_VERSION="v1")
    _patch_dns(monkeypatch, module)
    token = {"X-Satsgate-Gate-Token": _GATE_TOKEN}
    with TestClient(module.app) as http:
        key = _buy(http)
        created = _create(http, key)
        pending = http.get("/internal/gate/sites/my-shop/status", headers=token)
        assert pending.status_code == 404
        assert pending.json() == {"ok": False, "error": "site_not_active"}
        missing = http.get("/internal/gate/sites/no-such/status", headers=token)
        assert missing.json() == {"ok": False, "error": "not_found"}
        bad = http.get("/internal/gate/sites/NO_SUCH!/status", headers=token)
        assert bad.json() == {"ok": False, "error": "not_found"}
        hidden = http.get("/internal/gate/sites/my-shop/status")
        assert hidden.json() == {"ok": False, "error": "not_found"}
        wrong = http.get("/internal/gate/sites/my-shop/status", headers={"X-Satsgate-Gate-Token": "nope"})
        assert wrong.json() == {"ok": False, "error": "not_found"}
        _verify(http, monkeypatch, module, key, created.json()["origin_secret"])
        approved = http.get("/internal/gate/sites/my-shop/status", headers=token)
        assert approved.json() == {"ok": True, "status": "approved"}
        assert http.get("/internal/gate/sites/my-shop", headers=token).status_code == 200
        http.post("/v1/admin/sites/my-shop/disable", headers=_ADMIN)
        disabled = http.get("/internal/gate/sites/my-shop/status", headers=token)
        assert disabled.status_code == 404
        assert disabled.json() == pending.json()
        assert http.get("/internal/gate/sites/my-shop", headers=token).json() == {"ok": False, "error": "not_found"}


# T-GO.5 -------------------------------------------------------------------


def test_t_go_5_1_gate_explains_an_inactive_site(tmp_path, monkeypatch):
    module = _load_app(tmp_path, SATSGATE_SITES_AUTO_APPROVE="1", SATSGATE_TERMS_VERSION="v1")
    _patch_dns(monkeypatch, module)
    gate, core_client, _origin = _open_gate(module.app, _settings())
    try:
        with TestClient(module.app) as core, gate as http:
            key = _buy(core)
            _create(core, key)
            route = core.post("/v1/sites/my-shop/routes", headers={"X-Api-Key": key}, json={"path": "/blog/post", "price_sats": 21})
            assert route.status_code == 200, route.text
            before = core.get("/v1/balance", headers={"X-Api-Key": key}).json()
            inactive = http.get("/my-shop/blog/post")
            assert inactive.status_code == 404
            body = inactive.json()
            assert body["ok"] is False
            assert body["error"] == "site_not_active"
            assert "Nothing was charged" in body["hint"]
            assert "GET /v1/sites/{slug}" in body["hint"]
            assert set(body) == {"ok", "error", "hint"}
            assert inactive.headers["cache-control"] == "no-store"
            assert "origin.example" not in inactive.text
            assert "invoice" not in body
            missing = http.get("/no-such/blog/post")
            assert missing.status_code == 404
            assert missing.json() == {"ok": False, "error": "not_found"}
            core.post("/v1/admin/sites/my-shop/approve", headers=_ADMIN)
            live = http.get("/my-shop/blog/post")
            assert live.status_code == 402, live.text
            hint = live.json()["hint"]
            assert "LUD-21 verify" in hint
            assert "do not pay the new invoice" in hint
            assert "will poll until the invoice settles" not in hint
            core.post("/v1/admin/sites/my-shop/disable", headers=_ADMIN)
            off = http.get("/my-shop/blog/post")
            assert off.status_code == 404
            assert off.json() == body
            after = core.get("/v1/balance", headers={"X-Api-Key": key}).json()
            assert after["balance_msat"] == before["balance_msat"]
    finally:
        _close(core_client)


def test_t_go_5_2_old_core_answer_still_reads_as_missing():
    import asyncio

    import httpx

    from satsgate_gate.core_client import fetch_status

    def handler(request: httpx.Request) -> httpx.Response:
        slug = request.url.path.split("/")[4]
        if slug == "old":
            return httpx.Response(404, json={"ok": False, "error": "not_found"})
        if slug == "inactive":
            return httpx.Response(404, json={"ok": False, "error": "site_not_active"})
        if slug == "blank":
            return httpx.Response(404, content=b"")
        return httpx.Response(200, json={"ok": True, "status": "approved"})

    async def run() -> list[str]:
        settings = _settings()
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url=settings.core_base_url) as client:
            return [await fetch_status(client, settings, slug) for slug in ("old", "inactive", "blank", "live")]

    assert asyncio.run(run()) == ["missing", "inactive", "missing", "approved"]
