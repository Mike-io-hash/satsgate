"""Offline checks for the OFAC EVM updater. No network and no full SDN file."""

from __future__ import annotations

import email.message
import importlib.util
from pathlib import Path
from urllib.error import HTTPError, URLError

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

    def read(self, amt: int = -1) -> bytes:
        if amt is None or int(amt) < 0:
            raise AssertionError("unlimited read")
        if not hasattr(self, "_offset"):
            self._offset = 0
        part = self._body[self._offset : self._offset + int(amt)]
        self._offset += len(part)
        self.max_read = max(getattr(self, "max_read", 0), int(amt))
        return part

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
    assert set(module.extract_evm(FIXTURE)) == EXPECTED


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
    assert module.PRIMARY in text
    assert "X-Amz-Signature" not in text


def test_redirect_to_another_host_keeps_the_previous_file(tmp_path, monkeypatch) -> None:
    module = _load()
    dest = tmp_path / "ofac_evm.txt"
    dest.write_text("previous\n", encoding="utf-8")

    def routes(url: str):
        if url == module.PRIMARY:
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


_MARKER = "presign-marker-do-not-leak"
_ADDRESS = "0xabcdef0123456789abcdef0123456789abcdef01"


def _order_xml() -> bytes:
    return f"""<?xml version="1.0"?>
<Sanctions xmlns="urn:ofac-test">
  <Noise><Pad>ignore</Pad><Note>0x3333333333333333333333333333333333333333</Note></Noise>
  <DistinctParties><DistinctParty><Profile>
    <Feature FeatureTypeID="9">
      <FeatureVersion><VersionDetail>0xAbCdEf0123456789AbCdEf0123456789AbCdEf01</VersionDetail></FeatureVersion>
    </Feature>
    <Feature FeatureTypeID="9">
      <FeatureVersion><VersionDetail>{_ADDRESS}</VersionDetail></FeatureVersion>
    </Feature>
    <Feature>
      <FeatureType>Digital Currency Address - ETH</FeatureType>
      <FeatureVersion><VersionDetail>0x2222222222222222222222222222222222222222</VersionDetail></FeatureVersion>
    </Feature>
    <Feature FeatureTypeID="8">
      <FeatureVersion><VersionDetail>bc1qexamplebtcaddressnotevm</VersionDetail></FeatureVersion>
    </Feature>
    <Feature FeatureTypeID="9">
      <FeatureVersion><VersionDetail>not-an-address</VersionDetail></FeatureVersion>
    </Feature>
  </Profile></DistinctParty></DistinctParties>
  <ReferenceValueSets><FeatureTypeValues>
    <FeatureType ID="9">Digital Currency Address - ETH</FeatureType>
    <FeatureType ID="8">Digital Currency Address - XBT</FeatureType>
  </FeatureTypeValues></ReferenceValueSets>
  <Noise><Pad>after</Pad></Noise>
</Sanctions>
""".encode()


def test_types_after_features_and_truncated_xml_keep_the_previous_file(tmp_path, monkeypatch) -> None:
    module = _load()
    ordered = tmp_path / "ordered.xml"
    ordered.write_bytes(_order_xml())
    assert set(module.extract_evm(ordered)) == EXPECTED
    cut = tmp_path / "cut.xml"
    cut.write_bytes(_order_xml()[:-40])
    with pytest.raises(RuntimeError, match="did not parse"):
        module.extract_evm(cut)

    monkeypatch.setattr(module, "MIN_XML_BYTES", 1)
    monkeypatch.setattr(module, "MIN_ADDRESSES", 1)
    dest = tmp_path / "ofac_evm.txt"
    dest.write_text("previous\n", encoding="utf-8")
    body = _order_xml()[:-40]

    def routes(url: str):
        if url == module.PRIMARY:
            return _Body(body, module.PRIMARY)
        raise AssertionError("second download")

    _patch_fetch(monkeypatch, module, routes)
    assert _run(module, dest) == 1
    assert dest.read_text(encoding="utf-8") == "previous\n"
    assert list(tmp_path.glob(".ofac-*")) == []


def test_download_is_chunked_without_content_length(tmp_path, monkeypatch) -> None:
    module = _load()
    monkeypatch.setattr(module, "MIN_XML_BYTES", 1)
    monkeypatch.setattr(module, "MIN_ADDRESSES", 1)
    seen: list[_Body] = []
    xml = _xml()

    def routes(url: str):
        if url == module.PRIMARY:
            return _redirect(url, f"https://{BUCKET}/SDN_ADVANCED.XML")
        if url.startswith(f"https://{BUCKET}/"):
            body = _Body(xml, url)
            seen.append(body)
            return body
        raise AssertionError("unexpected host")

    _patch_fetch(monkeypatch, module, routes)
    dest = tmp_path / "nested" / "ofac_evm.txt"
    assert _run(module, dest) == 0
    assert seen and 0 < seen[0].max_read <= module._CHUNK_BYTES
    text = dest.read_text(encoding="utf-8")
    for address in EXPECTED:
        assert address in text
    assert list(tmp_path.glob(".ofac-*")) == []


def test_primary_failure_has_no_legacy_fallback(tmp_path, monkeypatch) -> None:
    module = _load()
    dest = tmp_path / "ofac_evm.txt"
    dest.write_text("previous\n", encoding="utf-8")
    hosts: list[str] = []

    def routes(url: str):
        hosts.append(module._hostname(url))
        raise URLError("primary down")

    _patch_fetch(monkeypatch, module, routes)
    _out, err = io_capture(module, monkeypatch)
    assert _run(module, dest) == 1
    assert dest.read_text(encoding="utf-8") == "previous\n"
    assert hosts == ["sanctionslistservice.ofac.treas.gov"]
    assert "treasury.gov" not in err.getvalue()
    assert not hasattr(module, "LEGACY")


def test_oversized_content_length_does_not_count(tmp_path, monkeypatch) -> None:
    module = _load()
    dest = tmp_path / "ofac_evm.txt"
    dest.write_text("previous\n", encoding="utf-8")
    xml = _xml()

    def routes(url: str):
        if url == module.PRIMARY:
            body = _Body(xml, module.PRIMARY)
            body.headers["Content-Length"] = "999999999"
            return body
        raise AssertionError(url)

    _patch_fetch(monkeypatch, module, routes)
    _out, err = io_capture(module, monkeypatch)
    assert _run(module, dest) == 1
    assert dest.read_text(encoding="utf-8") == "previous\n"
    assert "999999999" not in err.getvalue()
    assert str(len(xml)) in err.getvalue()


def test_refused_downloads_leave_no_temp_and_no_new_file(tmp_path, monkeypatch) -> None:
    module = _load()
    cases = []

    def http_error(url: str, code: int, location: str | None = None) -> HTTPError:
        return HTTPError(url, code, "nope", _headers(location=location), None)

    def routes_factory(kind: str):
        def routes(url: str):
            if kind == "loop" and url == module.PRIMARY:
                return _redirect(url, module.PRIMARY)
            if kind == "many" and module._is_treas(url):
                return _redirect(url, "https://ofac.treas.gov/again")
            if kind == "noloc" and url == module.PRIMARY:
                return http_error(url, 302, None)
            if kind == "status" and url == module.PRIMARY:
                return http_error(url, 500)
            if kind == "type" and url == module.PRIMARY:
                return _Body(b"<html></html>", module.PRIMARY, content_type="text/html")
            if kind == "final" and url == module.PRIMARY:
                return _redirect(url, f"https://{BUCKET}/file.xml")
            if kind == "final" and module._is_publish_bucket(url):
                return _Body(b"<xml/>", "https://evil.example/file.xml")
            if kind == "mid" and url == module.PRIMARY:
                return _Exploding(b"abc", module.PRIMARY)
            if kind == "foreign" and url == module.PRIMARY:
                return _redirect(url, "https://evil.example/sdn.xml")
            raise AssertionError(kind)
        return routes

    for kind in ("loop", "many", "noloc", "status", "type", "final", "mid", "foreign"):
        dest = tmp_path / kind / "ofac_evm.txt"
        dest.parent.mkdir()
        dest.write_text("previous\n", encoding="utf-8")
        before = _download_temps()
        _patch_fetch(monkeypatch, module, routes_factory(kind))
        assert _run(module, dest) == 1
        assert dest.read_text(encoding="utf-8") == "previous\n"
        assert _download_temps() == before
        cases.append(kind)
    missing = tmp_path / "absent" / "ofac_evm.txt"
    _patch_fetch(monkeypatch, module, routes_factory("status"))
    assert _run(module, missing) == 1
    assert not missing.exists()
    assert not missing.parent.exists()
    assert cases


def test_replace_failure_keeps_the_previous_file(tmp_path, monkeypatch) -> None:
    module = _load()
    monkeypatch.setattr(module, "MIN_XML_BYTES", 1)
    monkeypatch.setattr(module, "MIN_ADDRESSES", 1)
    dest = tmp_path / "ofac_evm.txt"
    dest.write_text("previous\n", encoding="utf-8")

    def routes(url: str):
        if url == module.PRIMARY:
            return _Body(_xml(), module.PRIMARY)
        raise AssertionError(url)

    def boom(src, dst):
        raise OSError("replace failed")

    _patch_fetch(monkeypatch, module, routes)
    monkeypatch.setattr(module.os, "replace", boom)
    before = _download_temps()
    assert _run(module, dest) == 1
    assert dest.read_text(encoding="utf-8") == "previous\n"
    assert list(tmp_path.glob(".ofac-*")) == []
    assert _download_temps() == before


def test_presigned_query_is_not_stored_or_printed(tmp_path, monkeypatch) -> None:
    module = _load()
    monkeypatch.setattr(module, "MIN_XML_BYTES", 1)
    monkeypatch.setattr(module, "MIN_ADDRESSES", 1)
    signed = f"https://{BUCKET}/SDN_ADVANCED.XML?X-Amz-Signature={_MARKER}"
    dest = tmp_path / "ofac_evm.txt"

    def routes(url: str):
        if url == module.PRIMARY:
            return _redirect(url, signed)
        if url == signed:
            return _Body(_xml(), signed)
        raise AssertionError("unexpected request")

    out, err = io_capture(module, monkeypatch)
    _patch_fetch(monkeypatch, module, routes)
    assert _run(module, dest) == 0
    blob = dest.read_text(encoding="utf-8") + out.getvalue() + err.getvalue()
    assert _MARKER not in blob
    assert "X-Amz-Signature" not in blob
    assert module.PRIMARY in dest.read_text(encoding="utf-8")


def test_large_xml_rss_stays_within_budget(tmp_path) -> None:
    module_path = ROOT / "scripts" / "ofac_evm_update.py"
    address = _ADDRESS
    small = tmp_path / "pad16.xml"
    large = tmp_path / "pad128.xml"
    _write_padded(small, 16 * 1024 * 1024, address)
    _write_padded(large, 128 * 1024 * 1024, address)
    assert small.stat().st_size >= 16 * 1024 * 1024
    assert large.stat().st_size >= 128 * 1024 * 1024
    first = _measure_child(module_path, small)
    second = _measure_child(module_path, large)
    assert first["count"] == second["count"] == 1
    assert first["digest"] == second["digest"]
    assert second["rss_kib"] <= 192 * 1024
    assert second["rss_kib"] - first["rss_kib"] <= 32 * 1024
    print(
        f"OFAC_RSS bytes16={small.stat().st_size} rss16_kib={first['rss_kib']} "
        f"seconds16={first['seconds']} bytes128={large.stat().st_size} "
        f"rss128_kib={second['rss_kib']} seconds128={second['seconds']} py={second['python']}"
    )


class _Exploding(_Body):
    def read(self, amt: int = -1) -> bytes:
        if amt is None or int(amt) < 0:
            raise AssertionError("unlimited read")
        raise OSError("mid read")


def io_capture(module, monkeypatch):
    import io

    out = io.StringIO()
    err = io.StringIO()
    monkeypatch.setattr(module.sys, "stdout", out)
    monkeypatch.setattr(module.sys, "stderr", err)
    return out, err


def _download_temps() -> list[str]:
    import tempfile

    root = Path(tempfile.gettempdir())
    return sorted(path.name for path in root.glob(".ofac-download-*"))


def _write_padded(path: Path, target: int, address: str) -> None:
    pad = b"<Pad>" + (b"n" * 180) + b"</Pad>"
    feature = (
        "<DistinctParties><DistinctParty><Profile>"
        f"<Feature FeatureTypeID=\"9\"><FeatureVersion><VersionDetail>{address}</VersionDetail></FeatureVersion></Feature>"
        "</Profile></DistinctParty></DistinctParties>"
        "<ReferenceValueSets><FeatureTypeValues>"
        "<FeatureType ID=\"9\">Digital Currency Address - ETH</FeatureType>"
        "</FeatureTypeValues></ReferenceValueSets>"
    ).encode()
    header = b'<?xml version="1.0"?><Sanctions xmlns="urn:ofac-test"><Noise>'
    footer = b"</Noise></Sanctions>"
    with path.open("wb") as handle:
        handle.write(header)
        half = max(0, (target // 2) - len(header))
        written = len(header)
        while written < half:
            handle.write(pad)
            written += len(pad)
        handle.write(b"</Noise>")
        handle.write(feature)
        handle.write(b"<Noise>")
        written = handle.tell()
        while written + len(footer) < target:
            handle.write(pad)
            written += len(pad)
        handle.write(footer)


def _measure_child(script: Path, xml_path: Path) -> dict[str, object]:
    import subprocess
    import sys

    code = (
        "import hashlib,sys,time,importlib.util\n"
        "spec=importlib.util.spec_from_file_location('ofac_evm_update', sys.argv[1])\n"
        "mod=importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(mod)\n"
        "started=time.perf_counter()\n"
        "found=mod.extract_evm(sys.argv[2])\n"
        "elapsed=time.perf_counter()-started\n"
        "rss=0\n"
        "for line in open('/proc/self/status', encoding='ascii'):\n"
        "    if line.startswith('VmHWM:'):\n"
        "        rss=int(line.split()[1])\n"
        "        break\n"
        "digest=hashlib.sha256(('\\n'.join(found)).encode()).hexdigest()\n"
        "sys.stdout.write(f'{len(found)} {rss} {elapsed:.3f} {sys.version.split()[0]} {digest}\\n')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code, str(script), str(xml_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr[-400:]
    count, rss, seconds, python, digest = proc.stdout.strip().split()
    return {
        "count": int(count),
        "rss_kib": int(rss),
        "seconds": seconds,
        "python": python,
        "digest": digest,
    }
