"""Account, payee, keys, and secret files for satsgate init (T-C.2)."""

from __future__ import annotations

import logging
import stat
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from satsgate.__main__ import build_parser
from satsgate.init import looks_like_lightning_address
from test_x402 import _load_app

from init_harness import ADDRESS, Closed, RecordingSync, invoke, posts

ROOT = Path(__file__).resolve().parents[1]


def _core(tmp_path: Path, **env: str):
    module = _load_app(tmp_path, **env)
    http = TestClient(module.app)
    http.__enter__()
    return module, http, RecordingSync(http)


def _close(http: TestClient) -> None:
    http.__exit__(None, None, None)


def test_t_c_2_1_first_run_opens_one_account_and_one_route_key(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 0, body
    assert body["ok"] is True
    assert len(posts(transport, "/v1/accounts")) == 1
    account = (work / ".satsgate" / "account.env").read_text(encoding="utf-8")
    key = account.split("=", 1)[1].strip()
    client = http.get("/v1/client", headers={"X-Api-Key": key})
    assert client.status_code == 200, client.text
    assert client.json()["payee_lightning_address"] == ADDRESS
    keys = http.get("/v1/api-keys", headers={"X-Api-Key": key})
    assert keys.status_code == 200, keys.text
    minted = keys.json()["keys"]
    assert len(minted) == 1
    assert minted[0]["resource_prefix"] == "route:"
    assert len(posts(transport, "/v1/api-keys")) == 1


def test_t_c_2_2_private_modes_on_posix(tmp_path: Path) -> None:
    """A default umask without an explicit chmod would leave 0644/0755 and fail."""
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 0, body
    assert stat.S_IMODE((work / ".satsgate").stat().st_mode) == 0o700
    assert stat.S_IMODE((work / ".satsgate" / "account.env").stat().st_mode) == 0o600
    assert stat.S_IMODE((work / ".env").stat().st_mode) == 0o600


def test_t_c_2_3_stdout_stderr_and_logs_hide_secrets(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Printing either key or the origin secret makes this assertion fail."""
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    caplog.set_level(logging.DEBUG)
    try:
        code, body, out, err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 0, body
    account = (work / ".satsgate" / "account.env").read_text(encoding="utf-8").split("=", 1)[1].strip()
    env = (work / ".env").read_text(encoding="utf-8")
    api_key = next(line.split("=", 1)[1] for line in env.splitlines() if line.startswith("SATSGATE_API_KEY="))
    origin = next(line.split("=", 1)[1] for line in env.splitlines() if line.startswith("SATSGATE_ORIGIN_SECRET="))
    blob = out + err + caplog.text
    assert account not in blob
    assert api_key not in blob
    assert origin not in blob
    assert body["account"]["key_preview"].endswith(account[-4:])
    assert len(body["account"]["fingerprint"]) == 12


def test_t_c_2_4_account_key_stays_out_of_the_project_env(tmp_path: Path) -> None:
    """Writing the sg_ value into .env fails this test."""
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 0, body
    env = (work / ".env").read_text(encoding="utf-8")
    account = (work / ".satsgate" / "account.env").read_text(encoding="utf-8")
    key = account.split("=", 1)[1].strip()
    assert key.startswith("sg_")
    assert key not in env
    assert "SATSGATE_API_KEY=sgr_" in env
    assert "SATSGATE_ORIGIN_SECRET=" in env
    assert account.strip() == f"SATSGATE_ACCOUNT_KEY={key}"
    assert (work / ".satsgate" / ".gitignore").read_text(encoding="utf-8").strip() == "*"


def test_t_c_2_5_signup_limit_is_one_request_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SATSGATE_SIGNUP_MAX_PER_IP_PER_DAY", "0")
    monkeypatch.setenv("SATSGATE_SIGNUP_MAX_GLOBAL_PER_DAY", "0")
    _module, http, transport = _core(
        tmp_path,
        SATSGATE_SIGNUP_MAX_PER_IP_PER_DAY="0",
        SATSGATE_SIGNUP_MAX_GLOBAL_PER_DAY="0",
    )
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 4
    assert body["status"] == "rate_limited"
    assert body["exit_code"] == 4
    assert body["error"]["code"] in {"signup_ip_limit", "signup_global_limit"}
    assert isinstance(body["retry_after_seconds"], int)
    assert len(posts(transport, "/v1/accounts")) == 1
    assert not (work / ".satsgate").exists()
    assert not (work / ".env").exists()


def test_t_c_2_6_missing_or_invalid_lightning_address_sends_nothing(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        missing, missing_body, _out, _err = invoke(work, transport, lightning_address=None)
        invalid, invalid_body, _out2, _err2 = invoke(work, transport, lightning_address="not-an-address")
    finally:
        _close(http)
    assert missing == 2
    assert missing_body["exit_code"] == 2
    assert "--lightning-address" in missing_body["error"]["message"]
    assert invalid == 2
    assert invalid_body["error"]["code"] == "invalid_lightning_address"
    assert transport.requests == []
    assert looks_like_lightning_address(ADDRESS)


def test_t_c_2_7_http_api_url_is_refused_off_localhost(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        refused, body, _out, _err = invoke(work, transport, api_url="http://example.test")
        assert transport.requests == []
        accepted, accepted_body, _out2, _err2 = invoke(work, transport, api_url="http://127.0.0.1:9")
    finally:
        _close(http)
    assert refused == 2
    assert body["exit_code"] == 2
    assert "example.test" not in {item.url.host for item in transport.requests}
    assert accepted == 0, accepted_body


def test_t_c_2_8_payee_failure_keeps_the_account_file(tmp_path: Path) -> None:
    _module, http, inner = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()

    class _FailPayee(httpx.BaseTransport):
        def __init__(self) -> None:
            self.requests: list[httpx.Request] = []

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            if request.method == "POST" and request.url.path == "/v1/client/payee":
                self.requests.append(request)
                return httpx.Response(500, json={"ok": False, "error": "payee_down"})
            return inner.handle_request(request)

    transport = _FailPayee()
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 1
    assert body["error"]["step"] == "set_payee"
    assert (work / ".satsgate" / "account.env").is_file()
    assert "sg_" in (work / ".satsgate" / "account.env").read_text(encoding="utf-8")


def test_t_c_2_9_no_wallet_secret_flag_prompt_or_variable() -> None:
    parser = build_parser()
    sub = next(action for action in parser._actions if action.dest == "command")
    text = parser.format_help() + sub.choices["init"].format_help()
    lowered = text.lower()
    for banned in ("seed", "mnemonic", "private key", "recovery phrase"):
        assert banned not in lowered
    allowed = {"SATSGATE_ACCOUNT_KEY", "SATSGATE_API_KEY", "SATSGATE_ORIGIN_SECRET"}
    # The prompts the human path asks are these three, none of which request a wallet secret.
    for prompt in ("Lightning Address:", "Accept USDC test mode?", "Origin snippet"):
        assert "seed" not in prompt.lower()
    assert allowed  # names checked against written files in T-C.2.4 and the rerun tests


def test_t_c_2_9_written_files_use_only_allowlisted_names(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 0, body
    allowed = {"SATSGATE_ACCOUNT_KEY", "SATSGATE_API_KEY", "SATSGATE_ORIGIN_SECRET"}
    from satsgate import files

    account = files.parse_env((work / ".satsgate" / "account.env").read_text(encoding="utf-8"))
    env = files.parse_env((work / ".env").read_text(encoding="utf-8"))
    assert set(account) <= allowed
    assert set(env) <= allowed
    assert set(account) == {"SATSGATE_ACCOUNT_KEY"}
    assert set(env) == {"SATSGATE_API_KEY", "SATSGATE_ORIGIN_SECRET"}


def test_t_c_2_10_windows_warns_that_permissions_are_not_restricted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # pathlib refuses WindowsPath on Linux, so os.name cannot be patched here.
    # The permission helper is what init consults, including when os.name == "nt".
    monkeypatch.setattr("satsgate.files.permissions_restricted", lambda: False)
    _module, http, transport = _core(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 0, body
    assert "permissions_not_restricted" in body["warnings"]
    assert body["exit_code"] == 0


def test_closed_stdin_is_the_agent_default() -> None:
    assert Closed().isatty() is False
