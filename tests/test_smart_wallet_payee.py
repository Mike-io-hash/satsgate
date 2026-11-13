"""EIP-1271 and ERC-6492 payee checks. The poster never leaves the process."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import sqlite3
import threading

import httpx
from eth_account import Account
from eth_account.messages import _hash_eip191_message, encode_defunct
from fastapi.testclient import TestClient

from test_payee_connect import _buy, _headers, _load_app, _mint_link, _sign


def _rpc():
    return importlib.import_module("app.evm_rpc")


def _ssrf():
    return importlib.import_module("app.ssrf")


def _install(poster) -> None:
    _rpc().poster = poster


def _chain_and(handler):
    def poster(url, payload, headers=None, timeout=None):
        method = payload.get("method")
        if method == "eth_chainId":
            return 200, {"jsonrpc": "2.0", "id": 1, "result": "0x2105"}
        return handler(payload, timeout)

    return poster


def _ok_contract(payload, timeout=None):
    if payload.get("method") == "eth_getCode":
        return 200, {"jsonrpc": "2.0", "id": 1, "result": "0x60016000"}
    return 200, {
        "jsonrpc": "2.0",
        "id": 1,
        "result": "0x1626ba7e" + ("0" * 56),
    }


def _challenge(http: TestClient, key: str, address: str, *, connect: bool = False):
    if connect:
        token, _body = _mint_link(http, key)
        response = http.post(
            "/v1/connect/evm/challenge",
            headers=_headers(token),
            json={"address": address},
        )
        assert response.status_code == 200, response.text
        return token, response.json()["message"]
    response = http.post(
        "/v1/client/payee/evm/challenge",
        headers={"X-Api-Key": key},
        json={"address": address},
    )
    assert response.status_code == 200, response.text
    return None, response.json()["message"]


def _verify(http: TestClient, key: str, address: str, signature: str, *, token: str | None = None):
    if token:
        return http.post(
            "/v1/connect/evm/verify",
            headers=_headers(token),
            json={"address": address, "signature": signature},
        )
    return http.post(
        "/v1/client/payee/evm",
        headers={"X-Api-Key": key},
        json={"address": address, "signature": signature},
    )


def _row():
    import os

    with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
        return conn.execute(
            "SELECT payee_evm_address, payee_evm_kind, payee_evm_connect_hash FROM clients"
        ).fetchone()


def test_bytecode_sha256_matches_the_pinned_viem_constant(tmp_path):
    module = _load_app(tmp_path)
    del module
    evm = _rpc()
    raw = bytes.fromhex(evm.ERC6492_BYTECODE[2:])
    assert hashlib.sha256(raw).hexdigest() == evm.ERC6492_BYTECODE_SHA256
    assert evm.ERC6492_BYTECODE_SHA256 == "d46b6085a6558eb925573e4e395ccbc669a1db1b7aa49196cbb1a7540db6a470"


def test_eoa_happy_path_makes_no_rpc_call(tmp_path):
    module = _load_app(tmp_path)
    calls = []

    def poster(url, payload, headers=None, timeout=None):
        calls.append(payload)
        raise AssertionError("eoa path must not call Base")

    _install(poster)
    owner = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        for connect in (False, True):
            calls.clear()
            token, message = _challenge(http, key, owner.address, connect=connect)
            saved = _verify(http, key, owner.address, _sign(owner, message), token=token)
            assert saved.status_code == 200, saved.text
            body = saved.json()
            assert body["payee_evm_kind"] == "eoa"
            assert body["payee_evm_verified"] is True
            assert body["payee_evm_address"] == owner.address
            assert "rails_cleared" in body
            assert calls == []
        client = http.get("/v1/client", headers={"X-Api-Key": key}).json()
        assert client["payee_evm_kind"] == "eoa"


def test_contract_accepts_only_the_rstrip_candidate_digest(tmp_path):
    module = _load_app(tmp_path)
    owner = Account.create()
    seen = []

    with TestClient(module.app) as http:
        key = _buy(http)
        token, message = _challenge(http, key, owner.address, connect=True)
        wanted = _hash_eip191_message(encode_defunct(text=message.rstrip()))
        exact = _hash_eip191_message(encode_defunct(text=message))
        assert wanted != exact

        def handler_with_magic(payload, timeout=None):
            if payload.get("method") == "eth_getCode":
                return 200, {"jsonrpc": "2.0", "id": 1, "result": "0x6001"}
            data = payload["params"][0]["data"]
            assert data.startswith("0x1626ba7e")
            digest = bytes.fromhex(data[10:74])
            seen.append(digest)
            word = "0x1626ba7e" + ("0" * 56) if digest == wanted else "0x" + ("00" * 32)
            return 200, {"jsonrpc": "2.0", "id": 1, "result": word}

        _install(_chain_and(handler_with_magic))
        saved = _verify(http, key, owner.address, "0x" + "11" * 80, token=token)
        assert saved.status_code == 200, saved.text
        assert saved.json()["payee_evm_kind"] == "contract"
        assert seen[0] == exact
        assert wanted in seen
        assert _row()[1] == "contract"


def test_contract_rejection_keeps_the_token(tmp_path):
    module = _load_app(tmp_path)
    owner = Account.create()

    def reject(kind: str):
        def handler(payload, timeout=None):
            if payload.get("method") == "eth_getCode":
                return 200, {"jsonrpc": "2.0", "id": 1, "result": "0x6001"}
            if kind == "revert":
                return 200, {"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "execution reverted"}}
            if kind == "empty":
                return 200, {"jsonrpc": "2.0", "id": 1, "result": "0x"}
            return 200, {"jsonrpc": "2.0", "id": 1, "result": "0x" + ("11" * 32)}

        return handler

    with TestClient(module.app) as http:
        key = _buy(http)
        for kind in ("other", "revert", "empty"):
            _install(_chain_and(reject(kind)))
            token, message = _challenge(http, key, owner.address, connect=True)
            before = _row()
            saved = _verify(http, key, owner.address, "0x" + "22" * 80, token=token)
            assert saved.status_code == 400, saved.text
            assert saved.json()["error"] == "bad_signature"
            assert _row() == before
            assert http.get("/v1/connect/evm", headers=_headers(token)).status_code == 200


def test_sixty_five_byte_owner_signature_is_checked_as_1271(tmp_path):
    module = _load_app(tmp_path)
    owner = Account.create()
    safe = Account.create().address
    _install(_chain_and(_ok_contract))
    with TestClient(module.app) as http:
        key = _buy(http)
        token, message = _challenge(http, key, safe, connect=True)
        signature = _sign(owner, message)
        assert len(signature) == 132
        saved = _verify(http, key, safe, signature, token=token)
        assert saved.status_code == 200, saved.text
        assert saved.json()["payee_evm_kind"] == "contract"
        assert saved.json()["payee_evm_address"] == safe


def test_no_code_on_base(tmp_path):
    module = _load_app(tmp_path)

    def handler(payload, timeout=None):
        if payload.get("method") == "eth_getCode":
            return 200, {"jsonrpc": "2.0", "id": 1, "result": "0x"}
        raise AssertionError("no code means no isValidSignature call")

    _install(_chain_and(handler))
    owner = Account.create()
    stranger = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        _token, message = _challenge(http, key, owner.address, connect=False)
        mismatch = _verify(http, key, owner.address, _sign(stranger, message))
        assert mismatch.status_code == 400
        assert mismatch.json()["error"] == "bad_signature"
        token, message = _challenge(http, key, owner.address, connect=True)
        long = _verify(http, key, owner.address, "0x" + "ab" * 80, token=token)
        assert long.status_code == 400
        assert long.json()["error"] == "smart_wallet_not_on_base"
        assert http.get("/v1/connect/evm", headers=_headers(token)).status_code == 200


def test_erc6492_deployless_call(tmp_path):
    module = _load_app(tmp_path)
    evm = _rpc()
    owner = Account.create()
    magic = "6492" * 16

    def scenario(result):
        seen = {}

        def handler(payload, timeout=None):
            tx = payload["params"][0]
            assert "to" not in tx
            assert tx["data"].startswith(evm.ERC6492_BYTECODE)
            seen["data"] = tx["data"]
            if result == "revert":
                return 200, {"jsonrpc": "2.0", "id": 1, "error": {"code": 3, "message": "execution reverted"}}
            return 200, {"jsonrpc": "2.0", "id": 1, "result": result}

        return handler, seen

    with TestClient(module.app) as http:
        key = _buy(http)
        signature = "0x" + ("ab" * 40) + magic
        for result, status, code in (
            ("0x01", 200, None),
            ("0x00", 400, "bad_signature"),
            ("revert", 400, "bad_signature"),
        ):
            handler, _seen = scenario(result)
            _install(_chain_and(handler))
            token, _message = _challenge(http, key, owner.address, connect=True)
            saved = _verify(http, key, owner.address, signature, token=token)
            assert saved.status_code == status, saved.text
            if code:
                assert saved.json()["error"] == code
                assert http.get("/v1/connect/evm", headers=_headers(token)).status_code == 200
            else:
                assert saved.json()["payee_evm_kind"] == "contract"


def test_rpc_failures_are_fail_closed(tmp_path, caplog):
    secret_url = "https://rpc.example/v1/secretkeyvalue"
    module = _load_app(tmp_path, SATSGATE_BASE_RPC_URL=secret_url)
    owner = Account.create()
    cases = []

    def boom_timeout(payload, timeout=None):
        raise _ssrf().SSRFError("fetch_failed")

    def boom_redirect(payload, timeout=None):
        raise _ssrf().SSRFError("redirects_not_allowed")

    def boom_size(payload, timeout=None):
        raise _ssrf().SSRFError("response_too_large")

    def http_500(payload, timeout=None):
        return 500, None

    def rpc_error(payload, timeout=None):
        return 200, {"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "missing trie node"}}

    def wrong_chain(payload, timeout=None):
        raise AssertionError("chain id is handled before this")

    named = {
        "timeout": boom_timeout,
        "redirect": boom_redirect,
        "oversized": boom_size,
        "http": http_500,
        "rpc": rpc_error,
    }
    with TestClient(module.app) as http:
        key = _buy(http)
        for name, handler in named.items():
            _install(_chain_and(handler))
            token, message = _challenge(http, key, owner.address, connect=True)
            before = _row()
            caplog.clear()
            saved = _verify(http, key, owner.address, "0x" + "cd" * 70, token=token)
            assert saved.status_code == 503, (name, saved.text)
            assert saved.json()["error"] == "smart_wallet_check_unavailable"
            assert _row() == before
            assert http.get("/v1/connect/evm", headers=_headers(token)).status_code == 200
            assert secret_url not in caplog.text
            assert "secretkeyvalue" not in caplog.text
            cases.append(name)

        _rpc().reset_chain_cache()

        def chain_poster(url, payload, headers=None, timeout=None):
            assert payload.get("method") == "eth_chainId"
            return 200, {"jsonrpc": "2.0", "id": 1, "result": "0x1"}

        _install(chain_poster)
        token, _message = _challenge(http, key, owner.address, connect=True)
        before = _row()
        caplog.clear()
        saved = _verify(http, key, owner.address, "0x" + "cd" * 70, token=token)
        assert saved.status_code == 503, saved.text
        assert saved.json()["error"] == "smart_wallet_check_unavailable"
        assert _row() == before
        assert secret_url not in caplog.text

        evm = _rpc()
        evm.reset_chain_cache()
        calls = {"n": 0}

        def clock():
            calls["n"] += 1
            return 0.0 if calls["n"] < 3 else 100.0

        evm.monotonic = clock
        _install(_chain_and(_ok_contract))
        token, _message = _challenge(http, key, owner.address, connect=True)
        before = _row()
        saved = _verify(http, key, owner.address, "0x" + "cd" * 70, token=token)
        assert saved.status_code == 503, saved.text
        assert saved.json()["error"] == "smart_wallet_check_unavailable"
        assert _row() == before
        assert http.get("/v1/connect/evm", headers=_headers(token)).status_code == 200
    assert "timeout" in cases


def test_rpc_runs_outside_the_write_lock_and_a_replaced_challenge_is_stale(tmp_path):
    module = _load_app(tmp_path)
    owner = Account.create()
    entered = threading.Event()
    release = threading.Event()
    state = {"blocked": False}

    def handler(payload, timeout=None):
        if not state["blocked"]:
            state["blocked"] = True
            entered.set()
            assert release.wait(5)
        return _ok_contract(payload, timeout)

    _install(_chain_and(handler))
    with TestClient(module.app) as http:
        key = _buy(http)
        token, message = _challenge(http, key, owner.address, connect=True)
        outcome = {}

        def run():
            outcome["response"] = _verify(http, key, owner.address, "0x" + "ab" * 70, token=token)

        worker = threading.Thread(target=run)
        worker.start()
        assert entered.wait(3)
        db_path = __import__("os").environ["SATSGATE_DB_PATH"]
        with sqlite3.connect(db_path, timeout=1) as conn:
            conn.execute("UPDATE clients SET credits = credits + 3")
            conn.commit()
            conn.execute("UPDATE clients SET payee_evm_pending_message = ?", ("replaced\n",))
            conn.commit()
        release.set()
        worker.join(5)
        assert not worker.is_alive()
        saved = outcome["response"]
        assert saved.status_code == 400, saved.text
        assert saved.json()["error"] == "stale_challenge"
        assert _row()[0] is None
        assert http.get("/v1/connect/evm", headers=_headers(token)).status_code == 200


def test_connect_verify_does_not_block_the_event_loop(tmp_path):
    module = _load_app(tmp_path)
    owner = Account.create()
    entered = threading.Event()
    release = threading.Event()

    def handler(payload, timeout=None):
        entered.set()
        assert release.wait(5)
        return _ok_contract(payload, timeout)

    _install(_chain_and(handler))
    with TestClient(module.app) as http:
        key = _buy(http)
        token, _message = _challenge(http, key, owner.address, connect=True)

    async def race():
        transport = httpx.ASGITransport(app=module.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            task = asyncio.create_task(
                client.post(
                    "/v1/connect/evm/verify",
                    headers={"X-Connect-Token": token},
                    json={"address": owner.address, "signature": "0x" + "ab" * 70},
                )
            )
            assert await asyncio.to_thread(entered.wait, 3)
            health = await asyncio.wait_for(client.get("/health"), timeout=1)
            assert health.status_code == 200
            assert health.json()["version"] == "0.20.1"
            release.set()
            saved = await task
            assert saved.status_code == 200, saved.text
            assert saved.json()["payee_evm_kind"] == "contract"

    asyncio.run(race())


def test_smart_wallet_rate_limits_skip_the_rpc(tmp_path):
    module = _load_app(tmp_path)
    calls = []

    def handler(payload, timeout=None):
        calls.append(payload.get("method"))
        if payload.get("method") == "eth_getCode":
            return 200, {"jsonrpc": "2.0", "id": 1, "result": "0x6001"}
        return 200, {"jsonrpc": "2.0", "id": 1, "result": "0x" + ("00" * 32)}

    _install(_chain_and(handler))
    owner = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        token, _message = _challenge(http, key, owner.address, connect=True)
        signature = "0x" + "ab" * 70
        for _index in range(10):
            saved = _verify(http, key, owner.address, signature, token=token)
            assert saved.status_code == 400, saved.text
            assert saved.json()["error"] == "bad_signature"
        before = len(calls)
        limited = _verify(http, key, owner.address, signature, token=token)
        assert limited.status_code == 429, limited.text
        assert limited.json()["error"] == "rate_limited"
        assert limited.headers["retry-after"]
        assert len(calls) == before

    module = _load_app(tmp_path)
    calls.clear()
    _install(_chain_and(handler))
    evm = _rpc()
    for _index in range(60):
        assert evm.global_limiter.allow("global")[0] is True
    with TestClient(module.app) as http:
        key = _buy(http)
        token, _message = _challenge(http, key, owner.address, connect=True)
        limited = _verify(http, key, owner.address, "0x" + "ab" * 70, token=token)
        assert limited.status_code == 429, limited.text
        assert calls == []


def test_smart_wallets_kill_switch_restores_pr9(tmp_path):
    module = _load_app(tmp_path, SATSGATE_SMART_WALLETS="0")

    def poster(url, payload, headers=None, timeout=None):
        raise AssertionError("kill switch must not call Base")

    _install(poster)
    owner = Account.create()
    stranger = Account.create()
    with TestClient(module.app) as http:
        key = _buy(http)
        token, message = _challenge(http, key, owner.address, connect=True)
        long = _verify(http, key, owner.address, "0x" + "ab" * 70, token=token)
        assert long.status_code == 400
        assert long.json()["error"] == "smart_wallet_not_supported"
        mismatch = _verify(http, key, owner.address, _sign(stranger, message), token=token)
        assert mismatch.status_code == 400
        assert mismatch.json()["error"] == "bad_signature"
        assert http.get("/v1/connect/evm", headers=_headers(token)).status_code == 200
