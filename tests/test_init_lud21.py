"""T-LA: satsgate init reports whether the Lightning Address advertises LUD-21 verify."""

from __future__ import annotations

import dataclasses
import os
import sqlite3
from pathlib import Path

import httpx
import pytest
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from test_x402 import _load_app

from init_harness import RecordingSync, Scripted, invoke

_STATUS = "/v1/paywall/status/"
_YES = "The Lightning Address advertises LUD-21 verify. A person can pay the QR from any Lightning wallet."
_NO = (
    "The Lightning Address does not advertise LUD-21 verify. Agents can still pay: they send the preimage. "
    "A person who pays the QR from a wallet that does not show the preimage cannot finish. "
    "To accept those payments, use a Lightning Address that advertises LUD-21 verify."
)
_UNKNOWN = "LUD-21 verify could not be checked. Nothing was paid. Run satsgate init again to check."


@pytest.fixture(autouse=True)
def _free_quota(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SATSGATE_FREE_QUOTA", "500")


def _core(tmp_path: Path):
    module = _load_app(tmp_path, SATSGATE_FREE_QUOTA="500")
    http = TestClient(module.app)
    http.__enter__()
    return module, http, RecordingSync(http)


def _advertise_verify(monkeypatch: pytest.MonkeyPatch, module, state) -> None:
    original = module.WALLET.create_invoice

    def create_invoice(**kwargs):
        invoice = original(**kwargs)
        return dataclasses.replace(invoice, verify_url=f"https://verify.invalid/v/{invoice.payment_hash}")

    monkeypatch.setattr(module.WALLET, "create_invoice", create_invoice)
    monkeypatch.setattr(module, "_paywall_lud21", lambda **_kw: state)


def _status_calls(transport: RecordingSync) -> list[httpx.Request]:
    return [item for item in transport.requests if item.url.path.startswith(_STATUS)]


def _ledger_rows() -> int:
    with sqlite3.connect(os.environ["SATSGATE_DB_PATH"]) as conn:
        return int(conn.execute("SELECT COUNT(*) FROM ledger WHERE reason = 'paywall_verify'").fetchone()[0])


def _run(tmp_path: Path, transport: RecordingSync, **overrides):
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    return invoke(work, transport, **overrides)


def test_la_1_1_address_without_verify_warns_and_finishes(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    try:
        code, body, out, err = _run(tmp_path, transport)
    finally:
        http.__exit__(None, None, None)
    assert code == 0, body
    assert body["ok"] is True
    assert body["lud21"] == {"supported": False, "detail": _NO}
    assert "lud21_not_supported" in body["warnings"]
    assert "lud21_not_checked" not in body["warnings"]
    calls = _status_calls(transport)
    assert len(calls) == 1
    assert calls[0].method == "GET"
    assert dict(calls[0].url.params) == {"expected_resource": "route:first", "consume": "false", "charge": "false"}
    assert calls[0].headers["x-api-key"].startswith("sgr_")
    macaroon = calls[0].headers["authorization"].removeprefix("L402 ")
    assert ":" not in macaroon
    assert macaroon not in out + err
    assert _ledger_rows() == 0
    assert (tmp_path / "work" / "satsgate-proxy.yaml").is_file()


def test_la_1_2_address_with_verify_reports_supported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, http, transport = _core(tmp_path)
    _advertise_verify(monkeypatch, module, "pending")
    try:
        code, body, _out, _err = _run(tmp_path, transport)
    finally:
        http.__exit__(None, None, None)
    assert code == 0, body
    assert body["lud21"] == {"supported": True, "detail": _YES}
    assert "lud21_not_supported" not in body["warnings"]
    assert "lud21_not_checked" not in body["warnings"]
    assert len(_status_calls(transport)) == 1
    assert _ledger_rows() == 0


def test_la_1_3_provider_failure_is_not_checked_and_does_not_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    module, http, transport = _core(tmp_path)
    _advertise_verify(
        monkeypatch,
        module,
        JSONResponse(status_code=502, content={"ok": False, "error": "lud21_unavailable"}),
    )
    try:
        code, body, _out, _err = _run(tmp_path, transport)
    finally:
        http.__exit__(None, None, None)
    assert code == 0, body
    assert body["ok"] is True
    assert body["lud21"] == {"supported": None, "detail": _UNKNOWN}
    assert "lud21_not_checked" in body["warnings"]
    assert "lud21_not_supported" not in body["warnings"]


def test_la_1_4_network_failure_on_the_check_does_not_block(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _module, http, transport = _core(tmp_path)
    original = transport.handle_request

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path.startswith(_STATUS):
            raise httpx.ReadTimeout("slow", request=request)
        return original(request)

    monkeypatch.setattr(transport, "handle_request", handle)
    try:
        code, body, _out, _err = _run(tmp_path, transport)
    finally:
        http.__exit__(None, None, None)
    assert code == 0, body
    assert body["status"] == "ready"
    assert body["lud21"] == {"supported": None, "detail": _UNKNOWN}
    assert "lud21_not_checked" in body["warnings"]


def test_la_1_5_human_mode_prints_the_result(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    try:
        code, body, out, _err = _run(
            tmp_path,
            transport,
            json_mode=False,
            stdin=Scripted([], tty=True),
        )
    finally:
        http.__exit__(None, None, None)
    assert code == 0
    assert body is None
    assert _NO in out.splitlines()


def test_la_1_6_a_failed_init_has_no_check(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    try:
        code, body, _out, _err = _run(tmp_path, transport, framework="bogus")
    finally:
        http.__exit__(None, None, None)
    assert code == 2
    assert body["lud21"] is None
    assert _status_calls(transport) == []


def test_la_1_7_a_second_run_checks_again(tmp_path: Path) -> None:
    _module, http, transport = _core(tmp_path)
    try:
        first, _body, _out, _err = _run(tmp_path, transport)
        code, body, _out, _err = _run(tmp_path, transport)
    finally:
        http.__exit__(None, None, None)
    assert first == 0
    assert code == 0, body
    assert body["account"]["reused"] is True
    assert body["lud21"] == {"supported": False, "detail": _NO}
    assert len(_status_calls(transport)) == 2
