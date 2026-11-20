"""Non-MCP paywall responses recorded before MCP routes.

The fixture is the byte-level contract for routes that have no mcp block.
Regenerating it without the same proxy behavior fails the hash check.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import httpx
import pytest

from test_satsgate_proxy import PAYMENT, PREIMAGE, YAML, World, _client, _load, _macaroon

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "proxy-paywall-golden.json"
FROZEN_UNIX = 1_700_000_000
FIXTURE_SHA256 = "583265a39ec276ac361e35957228e34c154f5964978409000649ebd69054c4b5"

GOLDEN_YAML = YAML.replace(
    "  pending_retry_after_seconds: 2\n",
    "  pending_retry_after_seconds: 2\n  public_base: https://pay.example\n",
) + (
    "  - name: usdc\n"
    "    methods: [GET, POST]\n"
    "    path: /usdc/**\n"
    "    price_sats: 100\n"
    "    access: per_request\n"
    "    scope: route\n"
    "    description: USDC route\n"
    "    x402: true\n"
)

_X402_NONCE = "ab" * 32
_PAYMENT_RESPONSE = "c2V0dGxlZA"


class PaywallWorld(World):
    """Same core and origin stub, plus the x402 verify and settle paths."""

    def __init__(self) -> None:
        super().__init__()
        self.clock = int(time.time())

    def _core(self, request: httpx.Request) -> httpx.Response:
        self.clock = int(time.time())
        path = request.url.path
        if path.endswith("/x402/verify") or path.endswith("/x402/settle"):
            snap = self._snap(request)
            self.core_calls.append(snap)
            if path.endswith("/x402/verify"):
                return httpx.Response(
                    200,
                    json={
                        "ok": True,
                        "serve": True,
                        "amount_usd_atomic": 10000,
                        "nonce": _X402_NONCE,
                    },
                )
            return httpx.Response(
                200,
                json={"ok": True, "payment_response": _PAYMENT_RESPONSE},
                headers={"payment-response": _PAYMENT_RESPONSE},
            )
        return super()._core(request)

    def _upstream(self, request: httpx.Request) -> httpx.Response:
        if self.upstream == "client_error":
            self.up_calls.append(self._snap(request))
            return httpx.Response(
                404,
                content=b"missing",
                headers={"content-type": "text/plain", "server": "secret-upstream"},
            )
        return super()._upstream(request)


def _body_field(content: bytes) -> dict[str, str]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return {"encoding": "hex", "value": content.hex()}
    return {"encoding": "utf-8", "value": text}


def _pairs(items: list[tuple[str, str]]) -> list[list[str]]:
    return [[key, value] for key, value in items]


def _capture(name: str, response: httpx.Response, world: PaywallWorld) -> dict:
    headers = _pairs(sorted((key.lower(), value) for key, value in response.headers.items()))
    core_calls = [
        {"method": call["method"], "path": call["path"], "body": call["body"]}
        for call in world.core_calls
    ]
    origin_calls = [
        {
            "method": call["method"],
            "raw_path": call["raw_path"],
            "headers": _pairs(sorted(call["headers"].items())),
            "body": call["body"],
        }
        for call in world.up_calls
    ]
    return {
        "name": name,
        "status": response.status_code,
        "headers": headers,
        "body": _body_field(response.content),
        "core_calls": core_calls,
        "origin_calls": origin_calls,
    }


def _run_case(settings, name: str, prepare, call) -> dict:
    world = PaywallWorld()
    prepare(world)
    with _client(settings, world) as client:
        response = call(client)
    return _capture(name, response, world)


def record_cases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    monkeypatch.setattr("satsgate_proxy.forward.time.time", lambda: FROZEN_UNIX)
    monkeypatch.setattr("app.l402.secrets.token_bytes", lambda size: b"\x11" * size)
    settings = _load(tmp_path, monkeypatch, GOLDEN_YAML)
    article = _macaroon("route:article")
    other = _macaroon("route:other")
    paid = {"Authorization": f"L402 {article}:{PREIMAGE}"}
    signature = {"PAYMENT-SIGNATURE": "sig-test"}

    def ready(world: PaywallWorld) -> None:
        return None

    cases = [
        _run_case(
            settings,
            "free_path",
            ready,
            lambda client: client.get("/health", headers={"Authorization": "Bearer keep-me"}),
        ),
        _run_case(settings, "not_found", ready, lambda client: client.get("/nope")),
        _run_case(settings, "method_not_allowed", ready, lambda client: client.put("/blog/post")),
        _run_case(
            settings,
            "unpaid",
            ready,
            lambda client: client.get("/blog/post?file=a%20b"),
        ),
        _run_case(
            settings,
            "pending",
            lambda world: setattr(world, "unlock", "pending"),
            lambda client: client.get("/blog/a", headers={"Authorization": f"L402 not-a-real-macaroon:{PREIMAGE}"}),
        ),
        _run_case(
            settings,
            "preimage_success",
            ready,
            lambda client: client.post(
                "/blog/post?file=a%20b",
                content=b'{"q":1}',
                headers={**paid, "Content-Type": "application/json"},
            ),
        ),
        _run_case(
            settings,
            "used_up",
            lambda world: setattr(world, "unlock", "used_up"),
            lambda client: client.get("/blog/a", headers=paid),
        ),
        _run_case(
            settings,
            "wrong_route",
            ready,
            lambda client: client.get("/blog/a", headers={"Authorization": f"L402 {other}:{PREIMAGE}"}),
        ),
        _run_case(
            settings,
            "origin_500",
            lambda world: setattr(world, "upstream", "error"),
            lambda client: client.get("/blog/a", headers=paid),
        ),
        _run_case(
            settings,
            "origin_timeout",
            lambda world: setattr(world, "upstream", "timeout"),
            lambda client: client.get("/blog/a", headers=paid),
        ),
        _run_case(
            settings,
            "oversize",
            ready,
            lambda client: client.post("/blog/a", content=b"x" * 2000),
        ),
        _run_case(
            settings,
            "one_rail_only",
            ready,
            lambda client: client.get("/blog/a", headers={**paid, **signature}),
        ),
        _run_case(
            settings,
            "x402_success",
            ready,
            lambda client: client.get("/usdc/a", headers=signature),
        ),
        _run_case(
            settings,
            "x402_origin_4xx",
            lambda world: setattr(world, "upstream", "client_error"),
            lambda client: client.get("/usdc/a", headers=signature),
        ),
    ]
    assert [item["name"] for item in cases] == [
        "free_path",
        "not_found",
        "method_not_allowed",
        "unpaid",
        "pending",
        "preimage_success",
        "used_up",
        "wrong_route",
        "origin_500",
        "origin_timeout",
        "oversize",
        "one_rail_only",
        "x402_success",
        "x402_origin_4xx",
    ]
    return {"frozen_unix": FROZEN_UNIX, "payment_hash": PAYMENT, "cases": cases}


def test_pm_6_1_non_mcp_paywall_matches_golden_fixture(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    raw = FIXTURE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == FIXTURE_SHA256
    expected = json.loads(raw.decode("utf-8"))
    actual = record_cases(tmp_path, monkeypatch)
    assert actual == expected
