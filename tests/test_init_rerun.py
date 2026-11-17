"""Re-runs, conflicts, and agent output for satsgate init (T-C.5)."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from satsgate.init import render_yaml
from test_x402 import _load_app

from init_harness import ADDRESS, API, Closed, Scripted, invoke, posts

OTHER = "other@pay.example"


@pytest.fixture(autouse=True)
def _restore_free_quota(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SATSGATE_FREE_QUOTA", "500")


def _core(tmp_path: Path, **env: str):
    env.setdefault("SATSGATE_FREE_QUOTA", "500")
    module = _load_app(tmp_path, **env)
    http = TestClient(module.app)
    http.__enter__()
    return http, module


def _close(http: TestClient) -> None:
    http.__exit__(None, None, None)


def test_t_c_5_1_second_run_reuses_everything(tmp_path: Path) -> None:
    http, _module = _core(tmp_path)
    from init_harness import RecordingSync

    transport = RecordingSync(http)
    work = tmp_path / "work"
    work.mkdir()
    try:
        first, first_body, _out, _err = invoke(work, transport)
        before = len(posts(transport, "/v1/accounts"))
        keys_before = len(posts(transport, "/v1/api-keys"))
        code, body, _out2, _err2 = invoke(work, transport)
    finally:
        _close(http)
    assert first == 0, first_body
    assert code == 0, body
    assert len(posts(transport, "/v1/accounts")) == before
    assert len(posts(transport, "/v1/api-keys")) == keys_before
    assert body["account"]["reused"] is True
    assert set(body["files"].values()) == {"unchanged"}


def test_t_c_5_2_rerun_after_payee_failure_does_not_sign_up_again(tmp_path: Path) -> None:
    http, _module = _core(tmp_path)
    from init_harness import RecordingSync

    inner = RecordingSync(http)
    work = tmp_path / "work"
    work.mkdir()

    class _Once(httpx.BaseTransport):
        def __init__(self) -> None:
            self.requests = inner.requests
            self.async_transport = inner.async_transport
            self._failed = False

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            if request.method == "POST" and request.url.path == "/v1/client/payee" and not self._failed:
                self._failed = True
                self.requests.append(request)
                return httpx.Response(500, json={"ok": False, "error": "payee_down"})
            return inner.handle_request(request)

    transport = _Once()
    try:
        failed, failed_body, _out, _err = invoke(work, transport)
        code, body, _out2, _err2 = invoke(work, transport)
    finally:
        _close(http)
    assert failed == 1
    assert failed_body["error"]["step"] == "set_payee"
    assert code == 0, body
    assert len(posts(transport, "/v1/accounts")) == 1
    assert body["account"]["reused"] is True


def test_t_c_5_3_existing_yaml_is_not_overwritten(tmp_path: Path) -> None:
    http, _module = _core(tmp_path)
    from init_harness import RecordingSync

    transport = RecordingSync(http)
    work = tmp_path / "work"
    work.mkdir()
    target = work / "satsgate-proxy.yaml"
    target.write_text("keep: this\n", encoding="utf-8")
    before = target.read_bytes()
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 3
    assert body["status"] == "file_exists"
    assert body["error"]["code"] == "file_exists"
    assert target.read_bytes() == before


def test_t_c_5_4_env_appends_missing_keys_and_conflicts_stop(tmp_path: Path) -> None:
    http, _module = _core(tmp_path)
    from init_harness import RecordingSync

    transport = RecordingSync(http)
    work = tmp_path / "work"
    work.mkdir()
    env = work / ".env"
    env.write_text("HELLO=world\nKEEP=1\n", encoding="utf-8")
    os.chmod(env, 0o640)
    try:
        code, body, _out, _err = invoke(work, transport)
        text = env.read_text(encoding="utf-8")
        assert code == 0, body
        assert text.startswith("HELLO=world\nKEEP=1\n")
        assert "SATSGATE_API_KEY=sgr_" in text
        assert "SATSGATE_ORIGIN_SECRET=" in text
        assert stat.S_IMODE(env.stat().st_mode) == 0o640
        conflict = "HELLO=world\nSATSGATE_API_KEY=sgr_not-the-saved-key\n"
        env.write_text(conflict, encoding="utf-8")
        os.chmod(env, 0o640)
        again, again_body, _out2, _err2 = invoke(work, transport)
    finally:
        _close(http)
    assert again == 3
    assert again_body["status"] == "env_conflict"
    assert again_body["error"]["code"] == "env_conflict"
    assert env.read_text(encoding="utf-8") == conflict
    assert stat.S_IMODE(env.stat().st_mode) == 0o640


def test_t_c_5_5_payee_difference_stops_unless_replaced(tmp_path: Path) -> None:
    http, _module = _core(tmp_path)
    from init_harness import RecordingSync

    transport = RecordingSync(http)
    work = tmp_path / "work"
    work.mkdir()
    try:
        first, first_body, _out, _err = invoke(work, transport)
        blocked, blocked_body, _out2, _err2 = invoke(work, transport, lightning_address=OTHER)
        account = (work / ".satsgate" / "account.env").read_text(encoding="utf-8").split("=", 1)[1].strip()
        unchanged = http.get("/v1/client", headers={"X-Api-Key": account})
        replaced, replaced_body, _out3, _err3 = invoke(
            work, transport, lightning_address=OTHER, replace_lightning_address=True
        )
        changed = http.get("/v1/client", headers={"X-Api-Key": account})
    finally:
        _close(http)
    assert first == 0, first_body
    assert blocked == 3
    assert blocked_body["status"] == "payee_differs"
    assert unchanged.json()["payee_lightning_address"] == ADDRESS
    assert replaced == 0, replaced_body
    assert changed.json()["payee_lightning_address"] == OTHER


def test_t_c_5_6_agent_stdout_is_one_json_object_and_stdin_is_unread(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cases = []
    http, _module = _core(tmp_path)
    from init_harness import RecordingSync

    transport = RecordingSync(http)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, out, _err = invoke(work, transport, stdin=Closed())
        cases.append((0, code, body, out))
        code, body, out, _err = invoke(work / "usage", transport, stdin=Closed(), lightning_address=None)
        (work / "usage").mkdir()
        code, body, out, _err = invoke(work / "usage", transport, stdin=Closed(), lightning_address=None)
        cases.append((2, code, body, out))
        yaml = work / "exists"
        yaml.mkdir()
        (yaml / "satsgate-proxy.yaml").write_text("other: true\n", encoding="utf-8")
        code, body, out, _err = invoke(yaml, transport, stdin=Closed())
        cases.append((3, code, body, out))
        monkeypatch.setenv("SATSGATE_SIGNUP_MAX_PER_IP_PER_DAY", "0")
        monkeypatch.setenv("SATSGATE_SIGNUP_MAX_GLOBAL_PER_DAY", "0")
        limited_http, _limited = _core(
            tmp_path / "limited",
            SATSGATE_SIGNUP_MAX_PER_IP_PER_DAY="0",
            SATSGATE_SIGNUP_MAX_GLOBAL_PER_DAY="0",
        )
        limited = RecordingSync(limited_http)
        try:
            slot = tmp_path / "limited-work"
            slot.mkdir()
            code, body, out, _err = invoke(slot, limited, stdin=Closed())
        finally:
            _close(limited_http)
        cases.append((4, code, body, out))
    finally:
        _close(http)
    seen = set()
    for expected, code, body, out in cases:
        parsed = json.loads(out)
        assert parsed == body
        assert list(out.strip().splitlines()) == [out.strip()]
        assert code == expected
        assert body["exit_code"] == expected
        assert body["ok"] is (expected == 0)
        seen.add(expected)
        if expected == 0:
            assert body["status"] == "ready"
        elif expected == 2:
            assert body["status"] == "usage"
        elif expected == 4:
            assert body["status"] == "rate_limited"
        else:
            assert body["status"] == body["error"]["code"]
    assert seen == {0, 2, 3, 4}


def test_t_c_5_7_rejected_account_key_does_not_sign_up(tmp_path: Path) -> None:
    http, _module = _core(tmp_path)
    from init_harness import RecordingSync

    transport = RecordingSync(http)
    work = tmp_path / "work"
    account = work / ".satsgate"
    account.mkdir(parents=True)
    (account / "account.env").write_text("SATSGATE_ACCOUNT_KEY=sg_not-a-real-account-key\n", encoding="utf-8")
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        _close(http)
    assert code == 3
    assert body["status"] == "account_key_rejected"
    assert posts(transport, "/v1/accounts") == []


def test_t_c_5_8_human_answers_reach_the_same_end_state(tmp_path: Path) -> None:
    http, _module = _core(tmp_path)
    from init_harness import RecordingSync

    transport = RecordingSync(http)
    agent = tmp_path / "agent"
    human = tmp_path / "human"
    agent.mkdir()
    human.mkdir()
    stdin = Scripted(["merchant@pay.example\n", "n\n", "none\n"], tty=True)
    try:
        agent_code, agent_body, _out, _err = invoke(agent, transport)
        human_code, _human_body, human_out, _human_err = invoke(
            human,
            transport,
            stdin=stdin,
            json_mode=False,
            lightning_address=None,
            want_usdc=None,
            framework=None,
        )
    finally:
        _close(http)
    assert agent_code == 0, agent_body
    assert human_code == 0, human_out
    assert not human_out.strip().startswith("{")

    def shape(root: Path) -> dict[str, object]:
        key = (root / ".satsgate" / "account.env").read_text(encoding="utf-8").split("=", 1)[1].strip()
        info = http.get("/v1/client", headers={"X-Api-Key": key}).json()
        env = (root / ".env").read_text(encoding="utf-8")
        return {
            "payee": info["payee_lightning_address"],
            "keys": len(http.get("/v1/api-keys", headers={"X-Api-Key": key}).json()["keys"]),
            "has_api": "SATSGATE_API_KEY=sgr_" in env,
            "has_origin": "SATSGATE_ORIGIN_SECRET=" in env,
            "yaml": (root / "satsgate-proxy.yaml").is_file(),
            "mode": stat.S_IMODE((root / ".env").stat().st_mode) == 0o600,
        }

    assert shape(agent) == shape(human)
    assert shape(agent)["payee"] == ADDRESS


def test_t_c_5_10_symlink_targets_are_not_written(tmp_path: Path) -> None:
    http, _module = _core(tmp_path)
    from init_harness import RecordingSync

    transport = RecordingSync(http)
    work = tmp_path / "work"
    work.mkdir()
    real_env = tmp_path / "real.env"
    real_env.write_text("KEEP=1\n", encoding="utf-8")
    (work / ".env").symlink_to(real_env)
    real_yaml = tmp_path / "real.yaml"
    real_yaml.write_text("keep: true\n", encoding="utf-8")
    other = tmp_path / "yaml-work"
    other.mkdir()
    (other / "satsgate-proxy.yaml").symlink_to(real_yaml)
    try:
        env_code, env_body, _out, _err = invoke(work, transport)
        yaml_code, yaml_body, _out2, _err2 = invoke(other, transport)
    finally:
        _close(http)
    assert env_code == 3
    assert env_body["status"] == "symlink_refused"
    assert real_env.read_text(encoding="utf-8") == "KEEP=1\n"
    assert yaml_code == 3
    assert yaml_body["status"] == "symlink_refused"
    assert real_yaml.read_text(encoding="utf-8") == "keep: true\n"


def test_render_yaml_has_no_secret_slot() -> None:
    text = render_yaml(api_url=API, upstream="http://127.0.0.1:3000", route_path="/paid/**")
    assert "sgr_" not in text
    assert "sg_" not in text
