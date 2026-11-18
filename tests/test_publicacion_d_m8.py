"""T-D.7.2a–d. The init file and probe checks that were missing."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from init_harness import RecordingSync, invoke
from satsgate import files
from test_x402 import _load_app


@pytest.fixture(autouse=True)
def _free_quota(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SATSGATE_FREE_QUOTA", "500")


def _core(tmp_path: Path) -> TestClient:
    module = _load_app(tmp_path, SATSGATE_FREE_QUOTA="500")
    http = TestClient(module.app)
    http.__enter__()
    return http


def test_t_d_7_2a_atomic_write_is_owner_only_under_umask_0(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def wide_temp(*args, **kwargs):
        fd, name = tempfile.mkstemp(*args, **kwargs)
        os.fchmod(fd, 0o666)
        return fd, name

    monkeypatch.setattr(files.tempfile, "mkstemp", wide_temp)
    previous = os.umask(0)
    try:
        path = tmp_path / "account.env"
        assert files.atomic_write(path, "SATSGATE_ACCOUNT_KEY=sg_example\n", mode=0o600)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    finally:
        os.umask(previous)


def test_t_d_7_2b_agent_mode_env_conflict_does_not_prompt(tmp_path: Path) -> None:
    http = _core(tmp_path)
    transport = RecordingSync(http)
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
        assert code == 0, body
        env = work / ".env"
        lines = env.read_text(encoding="utf-8").splitlines(keepends=True)
        replaced = False
        rewritten: list[str] = []
        for line in lines:
            if line.startswith("SATSGATE_ORIGIN_SECRET="):
                rewritten.append("SATSGATE_ORIGIN_SECRET=\n")
                replaced = True
            else:
                rewritten.append(line)
        assert replaced
        env.write_text("".join(rewritten), encoding="utf-8")
        os.chmod(env, 0o600)
        again, again_body, _out2, _err2 = invoke(work, transport)
    finally:
        http.__exit__(None, None, None)
    assert again == 3
    assert again_body["status"] == "env_conflict"
    assert again_body["error"]["message"] == "A SATSGATE_* value in .env differs. It was not changed."
    assert "SATSGATE_ORIGIN_SECRET=\n" in env.read_text(encoding="utf-8")


def test_t_d_7_2c_a_challenge_amount_other_than_10_fails_the_probe(tmp_path: Path) -> None:
    http = _core(tmp_path)
    transport = RecordingSync(http)
    original = transport.async_transport.handle_async_request

    async def crafted(request: httpx.Request) -> httpx.Response:
        response = await original(request)
        await response.aread()
        if str(request.url.path).endswith("/v1/paywall/challenge") and response.status_code == 200:
            body = json.loads(response.content)
            body["amount_sats"] = 99
            return httpx.Response(200, json=body)
        return response

    transport.async_transport.handle_async_request = crafted
    work = tmp_path / "work"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        http.__exit__(None, None, None)
    assert code == 1
    assert body["error"]["step"] == "test_402"
    assert body["error"]["code"] == "paywall_unavailable"
    assert body["error"]["message"] == "The test 402 failed. No payment was sent."
    assert body["test_402"]["debited"] is False


def test_t_d_7_2c_a_402_for_a_different_amount_is_not_accepted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    http = _core(tmp_path)
    transport = RecordingSync(http)

    class _Response:
        status_code = 402
        headers = {"www-authenticate": "L402 macaroon"}

        def json(self) -> dict[str, int]:
            return {"amount_sats": 11}

    monkeypatch.setattr("satsgate.init._probe_get", lambda _app, _route: _Response())
    work = tmp_path / "amount"
    work.mkdir()
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        http.__exit__(None, None, None)
    assert code == 1
    assert body["error"]["message"] == "The test challenge was not 10 sats."


def test_t_d_7_2d_refuse_symlink_does_not_open_the_target(tmp_path: Path) -> None:
    target = tmp_path / "real.env"
    target.write_text("KEEP=1\n", encoding="utf-8")
    link = tmp_path / "account.env"
    link.symlink_to(target)
    with pytest.raises(files.FileRefusal) as caught:
        files.atomic_write(link, "SATSGATE_ACCOUNT_KEY=sg_new\n")
    assert caught.value.code == "symlink_refused"
    assert target.read_text(encoding="utf-8") == "KEEP=1\n"


def test_t_d_7_2d_init_refuses_a_symlink_before_it_writes(tmp_path: Path) -> None:
    http = _core(tmp_path)
    transport = RecordingSync(http)
    work = tmp_path / "work"
    work.mkdir()
    target = tmp_path / "real.env"
    target.write_text("KEEP=1\n", encoding="utf-8")
    (work / ".env").symlink_to(target)
    try:
        code, body, _out, _err = invoke(work, transport)
    finally:
        http.__exit__(None, None, None)
    assert code == 3
    assert body["status"] == "symlink_refused"
    assert "was not written" in body["error"]["message"]
    assert target.read_text(encoding="utf-8") == "KEEP=1\n"
    assert not (work / ".satsgate" / "account.env").exists()
