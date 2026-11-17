"""Proxy config, unpaid 402, snippets, and the connect link (T-C.3, T-C.4, T-C.5.9)."""

from __future__ import annotations

import base64
import importlib.util
import json
import logging
import os
import sqlite3
import stat
from pathlib import Path

import httpx
import pytest
from eth_account import Account
from fastapi.testclient import TestClient
from starlette.testclient import TestClient as ProxyClient

from satsgate.init import START_COMMAND, x402_offer_problem
from satsgate_proxy.app import build_app
from satsgate_proxy.config import load_settings
from satsgate_sdk import SatsgateClient
from test_x402 import _load_app, _verify_payee

from init_harness import RecordingSync, Scripted, invoke, posts

ROOT = Path(__file__).resolve().parents[1]
_SNIPPETS = ("fastapi_verify.py", "express_verify.js", "nginx_verify.js", "nginx.conf", "Caddyfile")


@pytest.fixture(autouse=True)
def _restore_free_quota(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SATSGATE_FREE_QUOTA", "500")


def _core(tmp_path: Path, **env: str):
    env.setdefault("SATSGATE_FREE_QUOTA", "500")
    module = _load_app(tmp_path, **env)
    http = TestClient(module.app)
    http.__enter__()
    return module, http, RecordingSync(http)


def _close(http: TestClient) -> None:
    http.__exit__(None, None, None)


def _debits() -> tuple:
    with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
        row = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(delta_credits), 0) FROM ledger WHERE reason = 'paywall_verify'"
        ).fetchone()
    return (int(row[0]), int(row[1]))


def _env_value(work: Path, name: str) -> str:
    for line in (work / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith(name + "="):
            return line.split("=", 1)[1]
    raise AssertionError(name)


def _account_key(work: Path) -> str:
    return (work / ".satsgate" / "account.env").read_text(encoding="utf-8").split("=", 1)[1].strip()


def test_t_c_3_1_yaml_loads_and_has_no_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 0, body
    text = (work / "satsgate-proxy.yaml").read_text(encoding="utf-8")
    secret = _env_value(work, "SATSGATE_ORIGIN_SECRET")
    api_key = _env_value(work, "SATSGATE_API_KEY")
    assert secret not in text
    assert api_key not in text
    assert _account_key(work) not in text
    monkeypatch.setenv("SATSGATE_API_KEY", api_key)
    monkeypatch.setenv("SATSGATE_ORIGIN_SECRET", secret)
    settings = load_settings(work / "satsgate-proxy.yaml")
    assert len(settings.routes) == 1
    route = settings.routes[0]
    assert route.price_sats == 10
    assert route.access.kind == "per_request"
    assert route.resource == "route:first"
    assert route.x402 is False


def test_t_c_3_2_test_402_does_not_debit(tmp_path: Path) -> None:
    """A verify or a mock payment during init would add a paywall_verify row or a pay request."""
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    before = _debits()
    try:
        code, body, _out, _err = invoke(work, transport)
        key = _account_key(work)
        balance = http.get("/v1/balance", headers={"X-Api-Key": key}).json()
    finally:
        _close(http)
    assert code == 0, body
    assert body["test_402"] == {"ok": True, "rail_lightning": True, "rail_x402": False, "debited": False}
    assert balance["balance_msat"] == 0
    assert balance["free_unlocks_remaining"] == 500
    assert _debits() == before == (0, 0)
    paths = [item.url.path for item in transport.requests]
    paths += [item.url.path for item in transport.async_transport.core_requests]
    assert not any(path.startswith("/dev/mock/pay") for path in paths)
    assert not any(path.endswith("/verify") or path.endswith("/settle") for path in paths)


def test_t_c_3_3_paid_retry_reaches_the_origin_and_the_signature_checks(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
        assert code == 0, body
        secret = _env_value(work, "SATSGATE_ORIGIN_SECRET")
        os.environ["SATSGATE_API_KEY"] = _env_value(work, "SATSGATE_API_KEY")
        os.environ["SATSGATE_ORIGIN_SECRET"] = secret
        seen: list[httpx.Request] = []

        def origin(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, content=b"unlocked")

        transport.async_transport.origin = origin
        settings = load_settings(work / "satsgate-proxy.yaml")
        with ProxyClient(build_app(settings, transport=transport.async_transport)) as proxy:
            challenge = proxy.get("/paid/check")
            assert challenge.status_code == 402, challenge.text
            payload = challenge.json()
            preimage = http.get(f"/dev/mock/pay/{payload['payment_hash']}").json()["preimage"]
            served = proxy.get(
                "/paid/check",
                headers={"Authorization": f"L402 {payload['macaroon']}:{preimage}"},
            )
        assert served.status_code == 200, served.text
        assert served.content == b"unlocked"
        assert len(seen) == 1
        header = seen[0].headers["x-satsgate-signature"]
        payment_hash = seen[0].headers["x-satsgate-payment-hash"]
        spec = importlib.util.spec_from_file_location(
            "fastapi_verify_under_test",
            ROOT / "proxy" / "snippets" / "fastapi_verify.py",
        )
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        assert module.verify_origin_signature(
            secret=secret,
            header=header,
            method=seen[0].method,
            target=seen[0].url.path,
            payment_hash=payment_hash,
            now=int(__import__("time").time()),
        )
    finally:
        os.environ.pop("SATSGATE_API_KEY", None)
        os.environ.pop("SATSGATE_ORIGIN_SECRET", None)
        _close(http)


def test_t_c_3_4_unreachable_origin_still_returns_402(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    called: list[str] = []

    def origin(request: httpx.Request) -> httpx.Response:
        called.append(str(request.url))
        raise httpx.ConnectError("origin down")

    transport.async_transport.origin = origin
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 0, body
    assert body["test_402"]["ok"] is True
    assert called == []
    assert transport.async_transport.origin_requests == []


def test_t_c_3_5_core_failure_is_explained_by_one_diagnostic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, http, transport = _core(tmp_path)
    module.config.WALLET_MODE = "lnaddr"
    work = tmp_path / "work"
    work.mkdir()

    def _skip_payee(self: SatsgateClient, address: str) -> dict:
        return {"ok": True, "payee_lightning_address": address}

    monkeypatch.setattr(SatsgateClient, "set_payee", _skip_payee)
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 1
    assert body["error"]["step"] == "test_402"
    assert body["error"]["code"] == "client_payee_not_set"
    diagnostic = [
        item
        for item in transport.requests
        if item.method == "POST" and item.url.path == "/v1/paywall/challenge"
    ]
    assert len(diagnostic) == 1


def test_t_c_3_6_x402_turns_on_only_after_the_evm_payee_is_verified(tmp_path: Path) -> None:
    """Enabling x402 just because the payee is verified fails the second run."""
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
        text = (work / "satsgate-proxy.yaml").read_text(encoding="utf-8")
        assert code == 0, body
        assert "x402" not in text
        assert "public_base" not in text
        _verify_payee(http, _account_key(work), Account.create())
        again, again_body, _out2, _err2 = invoke(work, transport)
        still = (work / "satsgate-proxy.yaml").read_text(encoding="utf-8")
        chosen, chosen_body, _out3, _err3 = invoke(work, transport, want_usdc=True)
        updated = (work / "satsgate-proxy.yaml").read_text(encoding="utf-8")
    finally:
        _close(http)
    assert again == 0, again_body
    assert still == text
    assert again_body["usdc"]["enabled"] is False
    assert again_body["test_402"]["rail_x402"] is False
    assert chosen == 0, chosen_body
    assert "x402: true" in updated
    assert "x402_mode: test" in updated
    assert "public_base" in updated
    assert chosen_body["test_402"]["rail_x402"] is True
    assert chosen_body["test_402"]["debited"] is False
    assert chosen_body["usdc"]["enabled"] is True


def test_t_c_3_7_start_command_and_docker_compose_keep_secrets_out(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, out, _err = invoke(work, transport, docker=True)
    finally:
        _close(http)
    assert code == 0, body
    assert body["start_command"] == START_COMMAND
    assert START_COMMAND in out
    compose = (work / "docker-compose.satsgate.yml").read_text(encoding="utf-8")
    assert "env_file: .env" in compose
    assert "satsgate-proxy:0.14.1" in compose
    assert "ghcr.io/mike-io-hash/satsgate-proxy:0.14.1" in compose
    assert "dockerfile: Dockerfile.satsgate-proxy" in compose
    assert "proxy/Dockerfile" not in compose
    assert "host: 0.0.0.0" in compose
    assert '"./satsgate-proxy.yaml":/etc/satsgate/proxy.yaml:ro' in compose
    assert 'user: "65532:65532"' in compose
    assert "read_only: true" in compose
    assert _env_value(work, "SATSGATE_API_KEY") not in compose
    assert _env_value(work, "SATSGATE_ORIGIN_SECRET") not in compose
    assert "docker compose -f docker-compose.satsgate.yml up" in body["next_steps"]
    dockerfile = (work / "Dockerfile.satsgate-proxy").read_text(encoding="utf-8")
    assert "FROM python:3.12-slim" in dockerfile
    assert 'satsgate-proxy>=0.14.1,<0.15' in dockerfile
    assert "--uid 65532" in dockerfile
    written = (work / "satsgate-proxy.yaml").read_text(encoding="utf-8")
    assert "host: 127.0.0.1" in written
    assert "host: 0.0.0.0" not in written


def test_m4_missing_usdc_offer_is_not_the_wrong_network() -> None:
    """Calling a missing offer 'not on Base Sepolia' fails this test."""
    code, message = x402_offer_problem("")
    assert code == "x402_offer_missing"
    assert "no USDC offer" in message
    assert "Base Sepolia" not in message
    wrong = base64.b64encode(json.dumps({"accepts": [{"network": "eip155:1"}]}).encode()).decode()
    code, message = x402_offer_problem(wrong)
    assert code == "x402_network"
    assert "Base Sepolia" in message
    good = base64.b64encode(json.dumps({"accepts": [{"network": "eip155:84532"}]}).encode()).decode()
    assert x402_offer_problem(good) is None


def test_m3_start_command_uses_yaml_out(tmp_path: Path) -> None:
    """A start command that still names satsgate-proxy.yaml fails this test."""
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport, yaml_out="alt.yaml")
    finally:
        _close(http)
    assert code == 0, body
    assert "alt.yaml" in body["start_command"]
    assert "satsgate-proxy.yaml" not in body["start_command"]
    text = (work / "alt.yaml").read_text(encoding="utf-8")
    assert "# Start: " in text
    assert "alt.yaml" in text
    assert "satsgate-proxy.yaml" not in text
    source = [step for step in body["next_steps"] if "python -m satsgate_proxy" in step]
    assert source and "alt.yaml" in source[0]
    assert "satsgate-proxy.yaml" not in source[0]


def test_i3_docker_mounts_the_yaml_out_path(tmp_path: Path) -> None:
    """A compose file that builds proxy/Dockerfile, listens only on loopback, or mounts the default name fails."""
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport, docker=True, yaml_out="alt.yaml")
    finally:
        _close(http)
    assert code == 0, body
    compose = (work / "docker-compose.satsgate.yml").read_text(encoding="utf-8")
    assert '"./alt.yaml":/etc/satsgate/proxy.yaml:ro' in compose
    assert "satsgate-proxy.yaml" not in compose
    assert "proxy/Dockerfile" not in compose
    assert "host: 0.0.0.0" in compose
    assert "host.docker.internal" in compose
    written = (work / "alt.yaml").read_text(encoding="utf-8")
    assert "host: 127.0.0.1" in written
    assert "host: 0.0.0.0" not in written


def test_t_c_3_8_packaged_snippets_match_the_proxy_sources() -> None:
    """Editing one packaged copy makes this comparison fail."""
    packaged = ROOT / "cli" / "src" / "satsgate" / "snippets"
    for name in _SNIPPETS:
        assert (packaged / name).read_bytes() == (ROOT / "proxy" / "snippets" / name).read_bytes()


def test_t_c_3_9_init_tests_do_not_call_the_public_hosts(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 0, body
    hosts = {item.url.host for item in transport.requests}
    hosts.update(item.url.host for item in transport.async_transport.core_requests)
    hosts.update(item.url.host for item in transport.async_transport.origin_requests)
    assert "api.satsgate.org" not in hosts
    assert "gate.satsgate.org" not in hosts
    forbidden = httpx.Request("GET", "https://api." + "satsgate.org/v1/client")
    with pytest.raises(AssertionError):
        transport.handle_request(forbidden)


def test_t_c_3_10_framework_snippets_are_copied_and_not_overwritten(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    try:
        for framework, filename, source in (
            ("fastapi", "satsgate_fastapi_verify.py", "fastapi_verify.py"),
            ("express", "satsgate_express_verify.js", "express_verify.js"),
            ("nginx", "satsgate_nginx_verify.js", "nginx_verify.js"),
        ):
            work = tmp_path / framework
            work.mkdir()
            code, body, _out, _err = invoke(work, transport, framework=framework)
            assert code == 0, body
            written = (work / filename).read_bytes()
            assert written == (ROOT / "proxy" / "snippets" / source).read_bytes()
        blocked = tmp_path / "blocked"
        blocked.mkdir()
        target = blocked / "satsgate_fastapi_verify.py"
        target.write_text("keep this snippet\n", encoding="utf-8")
        opened = len(posts(transport, "/v1/accounts"))
        code, body, _out, _err = invoke(blocked, transport, framework="fastapi")
    finally:
        _close(http)
    assert code == 3
    assert body["status"] == "file_exists"
    assert target.read_text(encoding="utf-8") == "keep this snippet\n"
    assert len(posts(transport, "/v1/accounts")) == opened
    assert not (blocked / ".satsgate" / "account.env").exists()


def test_t_c_4_1_agent_connect_link_stays_out_of_json_and_logs(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Putting the URL in the JSON object fails the search below."""
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    caplog.set_level(logging.DEBUG)
    try:
        code, body, out, err = invoke(work, transport, want_usdc=True)
    finally:
        _close(http)
    assert code == 0, body
    link = work / ".satsgate" / "connect-link.txt"
    url = link.read_text(encoding="utf-8").strip()
    assert url.startswith("https://")
    assert "#t=" in url
    assert stat.S_IMODE(link.stat().st_mode) == 0o600
    assert body["usdc"]["connect_link_file"].endswith("connect-link.txt")
    assert isinstance(body["usdc"]["expires_at"], int)
    blob = out + err + caplog.text + json.dumps(body)
    assert url not in blob


def test_t_c_4_2_human_tty_prints_the_link_once_and_a_pipe_writes_the_file(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    tty_dir = tmp_path / "tty"
    pipe_dir = tmp_path / "pipe"
    tty_dir.mkdir()
    pipe_dir.mkdir()
    tty_in = Scripted(["merchant@pay.example\n", "y\n", "none\n", "n\n"], tty=True)
    pipe_in = Scripted(["merchant@pay.example\n", "y\n", "none\n"], tty=True)
    try:
        tty_code, _tty_body, tty_out, tty_err = invoke(
            tty_dir,
            transport,
            stdin=tty_in,
            json_mode=False,
            lightning_address=None,
            want_usdc=None,
            framework=None,
            stdout_tty=True,
        )
        pipe_code, pipe_body, pipe_out, pipe_err = invoke(
            pipe_dir,
            transport,
            stdin=pipe_in,
            json_mode=False,
            lightning_address=None,
            want_usdc=None,
            framework=None,
            stdout_tty=False,
        )
    finally:
        _close(http)
    assert tty_code == 0, tty_out
    url = [line for line in tty_out.splitlines() if line.startswith("https://") and "#t=" in line]
    assert url == [url[0]]
    assert url[0] not in tty_err
    assert not (tty_dir / ".satsgate" / "connect-link.txt").exists()
    assert pipe_code == 0, pipe_body
    stored = (pipe_dir / ".satsgate" / "connect-link.txt").read_text(encoding="utf-8").strip()
    assert stored.startswith("https://")
    assert stored not in pipe_out
    assert stored not in pipe_err


def test_t_c_5_9_next_steps_name_the_buyer_path_only_when_usdc_is_on(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
        assert code == 0, body
        _verify_payee(http, _account_key(work), Account.create())
        again, again_body, _out2, _err2 = invoke(work, transport)
        chosen, chosen_body, _out3, _err3 = invoke(work, transport, want_usdc=True)
    finally:
        _close(http)
    assert any("--want-usdc" in step for step in body["next_steps"])
    assert not any("Base Sepolia" in step for step in body["next_steps"])
    assert again == 0, again_body
    assert any("--want-usdc" in step for step in again_body["next_steps"])
    assert not any("Base Sepolia" in step for step in again_body["next_steps"])
    assert chosen == 0, chosen_body
    assert any("Base Sepolia" in step and "satsgate-mcp-pay" in step for step in chosen_body["next_steps"])
    assert not any("--want-usdc" in step for step in chosen_body["next_steps"])
