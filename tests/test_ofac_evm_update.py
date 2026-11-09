"""Offline checks for the OFAC EVM updater. No network and no full SDN file."""

from __future__ import annotations

import email.message
import importlib.util
from pathlib import Path
from urllib.error import HTTPError

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "ofac_sdn_advanced_min.xml"
BUCKET = "wc2h-sls-prod-public-published.s3.us-gov-west-1.amazonaws.com"
BUCKET_URL = f"https://{BUCKET}/SDN_ADVANCED.XML?X-Amz-Signature=test"
EVIL = "https://evil.example/sdn.xml"
EXPECTED = {
    "0xabcdef0123456789abcdef0123456789abcdef01",
    "0x2222222222222222222222222222222222222222",
}


def _load():
    spec = importlib.util.spec_from_file_location("ofac_evm_update", ROOT / "scripts" / "ofac_evm_update.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _headers(*, location: str | None = None, content_type: str = "text/xml") -> email.message.EmailMessage:
    headers = email.message.EmailMessage()
    headers["Content-Type"] = content_type
    if location is not None:
        headers["Location"] = location
    return headers


def _redirect(url: str, location: str) -> HTTPError:
    return HTTPError(url, 302, "Found", _headers(location=location), None)


class _Body:
    def __init__(self, body: bytes, url: str, content_type: str = "text/xml") -> None:
        self._body = body
        self.status = 200
        self.headers = _headers(content_type=content_type)
        self._url = url

    def read(self) -> bytes:
        return self._body

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> "_Body":
        return self

    def __exit__(self, *args: object) -> bool:
        return False


class _Opener:
    def __init__(self, routes) -> None:
        self.routes = routes
        self.urls: list[str] = []

    def open(self, request, timeout=60):
        del timeout
        url = request.full_url
        self.urls.append(url)
        result = self.routes(url)
        if isinstance(result, Exception):
            raise result
        return result


def _patch_fetch(monkeypatch, module, routes) -> _Opener:
    opener = _Opener(routes)

    def build_opener(*args, **kwargs):
        del args, kwargs
        return opener

    monkeypatch.setattr(module, "build_opener", build_opener)
    return opener


def _xml() -> bytes:
    return FIXTURE.read_bytes()


def test_extract_evm_uses_the_feature_type_attribute_and_ignores_btc() -> None:
    module = _load()
    assert set(module.extract_evm(_xml())) == EXPECTED


def test_primary_redirect_to_the_official_bucket_is_accepted(tmp_path, monkeypatch) -> None:
    module = _load()
    monkeypatch.setattr(module, "MIN_XML_BYTES", 1)
    monkeypatch.setattr(module, "MIN_ADDRESSES", 1)
    xml = _xml()

    def routes(url: str):
        if url == module.PRIMARY:
            return _redirect(url, BUCKET_URL)
        if url == BUCKET_URL:
            return _Body(xml, BUCKET_URL)
        raise AssertionError(url)

    opener = _patch_fetch(monkeypatch, module, routes)
    dest = tmp_path / "ofac_evm.txt"
    assert _run(module, dest) == 0
    assert opener.urls == [module.PRIMARY, BUCKET_URL]
    text = dest.read_text(encoding="utf-8")
    for address in EXPECTED:
        assert address in text
    assert "bc1qexamplebtcaddressnotevm" not in text
    assert "0x3333333333333333333333333333333333333333" not in text


def test_redirect_to_another_host_keeps_the_previous_file(tmp_path, monkeypatch) -> None:
    module = _load()
    dest = tmp_path / "ofac_evm.txt"
    dest.write_text("previous\n", encoding="utf-8")

    def routes(url: str):
        if url in {module.PRIMARY, module.LEGACY}:
            return _redirect(url, EVIL)
        raise AssertionError(url)

    opener = _patch_fetch(monkeypatch, module, routes)
    assert _run(module, dest) == 1
    assert dest.read_text(encoding="utf-8") == "previous\n"
    assert EVIL not in opener.urls
    assert all(module._is_treas(url) for url in opener.urls)


def test_bucket_start_url_is_refused(monkeypatch) -> None:
    module = _load()
    opened: list[str] = []

    def routes(url: str):
        opened.append(url)
        raise AssertionError(url)

    _patch_fetch(monkeypatch, module, routes)
    with pytest.raises(RuntimeError, match="host refused"):
        module._fetch(BUCKET_URL)
    assert opened == []


def test_below_address_floor_keeps_the_previous_file(tmp_path, monkeypatch) -> None:
    module = _load()
    monkeypatch.setattr(module, "MIN_XML_BYTES", 1)
    dest = tmp_path / "ofac_evm.txt"
    dest.write_text("previous\n", encoding="utf-8")
    xml = _xml()

    def routes(url: str):
        if url == module.PRIMARY:
            return _redirect(url, BUCKET_URL)
        if url == BUCKET_URL:
            return _Body(xml, BUCKET_URL)
        raise AssertionError(url)

    _patch_fetch(monkeypatch, module, routes)
    assert module.MIN_ADDRESSES == 100
    assert _run(module, dest) == 1
    assert dest.read_text(encoding="utf-8") == "previous\n"


def _run(module, dest: Path) -> int:
    return module.main_for(dest) if hasattr(module, "main_for") else _argv_main(module, dest)


def _argv_main(module, dest: Path) -> int:
    import sys

    old = sys.argv
    sys.argv = ["ofac_evm_update.py", str(dest)]
    try:
        return module.main()
    finally:
        sys.argv = old
