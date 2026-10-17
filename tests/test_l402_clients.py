"""The proxy 402 header is the one lnget and Alby fetch402 parse."""

from __future__ import annotations

import importlib.util
from pathlib import Path

from satsgate_mcp.clients import fetch402_global_strip_keeps_macaroon, parse_fetch402, parse_lnget


def _proxy_tests():
    path = Path(__file__).with_name("test_satsgate_proxy.py")
    spec = importlib.util.spec_from_file_location("satsgate_proxy_test_support", path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_proxy_402_matches_lnget_and_fetch402(tmp_path, monkeypatch) -> None:
    support = _proxy_tests()
    world = support.World()
    settings = support._load(tmp_path, monkeypatch)
    with support._client(settings, world) as client:
        response = client.get("/blog/post")
    assert response.status_code == 402
    header = response.headers["www-authenticate"]
    lnget = parse_lnget(header)
    fetch402 = parse_fetch402(header)
    assert lnget is not None and fetch402 is not None
    assert lnget == fetch402
    macaroon, invoice = lnget
    assert header.index("macaroon=") < header.index("invoice=")
    assert fetch402_global_strip_keeps_macaroon(header, macaroon)
    body = response.json()
    assert body["invoice"] == invoice
    assert body["macaroon"] == macaroon
    assert body["max_uses"] == 1
    assert body["access_seconds"] is None
    assert body["amount_sats"] == 100
