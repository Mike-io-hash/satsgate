"""B-1. Published files are taken from the JSON API, with no network in pytest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "publish.yml"


def _load():
    import importlib.util

    path = ROOT / "scripts" / "release" / "fetch_published.py"
    spec = importlib.util.spec_from_file_location("fetch_published", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sums(tmp_path: Path, files: dict[str, bytes]) -> Path:
    lines = []
    for name, payload in files.items():
        digest = hashlib.sha256(payload).hexdigest()
        lines.append(f"{digest}  {name}")
    path = tmp_path / "SHA256SUMS"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _body(index: str, files: dict[str, bytes], *, host: str | None = None) -> bytes:
    fetch = _load()
    file_host = host or fetch.FILE_HOSTS[index]
    urls = []
    for name, payload in files.items():
        urls.append(
            {
                "filename": name,
                "url": f"https://{file_host}/packages/ab/{name}",
                "digests": {"sha256": hashlib.sha256(payload).hexdigest()},
            }
        )
    return json.dumps({"urls": urls}).encode()


def _fetch(tmp_path: Path, files: dict[str, bytes], body: bytes, *, index: str = "testpypi"):
    fetch = _load()
    downloaded: list[str] = []

    def opener(_url: str) -> tuple[int, bytes]:
        return 200, body

    def downloader(url: str) -> bytes:
        downloaded.append(url)
        name = url.rsplit("/", 1)[-1]
        return files[name]

    dest = tmp_path / "got"
    fetch.fetch(
        index=index,
        name="satsgate-sdk",
        version="0.10.0",
        sums=_sums(tmp_path, files),
        dest=dest,
        opener=opener,
        downloader=downloader,
    )
    return dest, downloaded


def test_index_urls_stay_on_their_own_hosts() -> None:
    fetch = _load()
    assert fetch.INDEX_HOSTS == {"pypi": "pypi.org", "testpypi": "test.pypi.org"}
    assert fetch.FILE_HOSTS == {
        "pypi": "files.pythonhosted.org",
        "testpypi": "test-files.pythonhosted.org",
    }
    assert fetch.release_url("testpypi", "satsgate-sdk", "0.10.0") == (
        "https://test.pypi.org/pypi/satsgate-sdk/0.10.0/json"
    )
    assert fetch.release_url("pypi", "satsgate-sdk", "0.10.0") == "https://pypi.org/pypi/satsgate-sdk/0.10.0/json"


def test_default_downloader_retries_a_server_error(monkeypatch: pytest.MonkeyPatch) -> None:
    fetch = _load()
    monkeypatch.setattr(fetch, "_https_get", lambda *_args, **_kwargs: (503, b""))
    with pytest.raises(fetch.NotReady, match="503"):
        fetch._default_downloader("https://files.pythonhosted.org/packages/ab/pkg.whl")


def test_b1_exact_published_set_matches_the_build(tmp_path: Path) -> None:
    files = {"pkg-0.1.0-py3-none-any.whl": b"wheel-bytes", "pkg-0.1.0.tar.gz": b"sdist-bytes"}
    dest, urls = _fetch(tmp_path, files, _body("testpypi", files))
    assert (dest / "pkg-0.1.0-py3-none-any.whl").read_bytes() == b"wheel-bytes"
    assert (dest / "pkg-0.1.0.tar.gz").read_bytes() == b"sdist-bytes"
    assert all(url.startswith("https://test-files.pythonhosted.org/") for url in urls)


def test_b1_rejects_a_different_sha_an_extra_file_a_missing_file_and_a_foreign_host(tmp_path: Path) -> None:
    fetch = _load()
    files = {"pkg-0.1.0-py3-none-any.whl": b"wheel-bytes", "pkg-0.1.0.tar.gz": b"sdist-bytes"}
    sums = _sums(tmp_path, files)

    def run(body: bytes) -> None:
        fetch.fetch(
            index="testpypi",
            name="satsgate-sdk",
            version="0.10.0",
            sums=sums,
            dest=tmp_path / "out",
            opener=lambda _url: (200, body),
            downloader=lambda _url: b"unused",
        )

    changed = _body("testpypi", files)
    parsed = json.loads(changed)
    parsed["urls"][0]["digests"]["sha256"] = "0" * 64
    with pytest.raises(fetch.FetchError, match="sha mismatch"):
        run(json.dumps(parsed).encode())

    extra = dict(files)
    extra["extra-0.1.0.whl"] = b"extra"
    with pytest.raises(fetch.FetchError, match="extra file"):
        run(_body("testpypi", extra))

    missing = {"pkg-0.1.0-py3-none-any.whl": files["pkg-0.1.0-py3-none-any.whl"]}
    with pytest.raises(fetch.NotReady, match="incomplete"):
        run(_body("testpypi", missing))

    with pytest.raises(fetch.FetchError, match="refusing host"):
        run(_body("testpypi", files, host="example.invalid"))


def test_b1_workflows_download_with_the_script_and_not_with_pip(tmp_path: Path) -> None:
    import re

    import yaml

    text = re.sub(r'(?m)^on:', '"on":', WORKFLOW.read_text(encoding="utf-8"), count=1)
    workflow = yaml.safe_load(text)
    jobs = {
        "smoke-testpypi": "testpypi",
        "verify-pypi": "pypi",
    }
    for name, index in jobs.items():
        script = next(step["run"] for step in workflow["jobs"][name]["steps"] if "fetch_published.py" in step.get("run", ""))
        assert "pip download" not in script
        assert "--no-binary" not in script
        assert f"--index {index}" in script
        assert '[[ "${code}" != "2" ]]' in script
        assert script.index('exit "${code}"') < script.index("sleep 10")
    fetch = _load()
    help_proc = __import__("subprocess").run(
        [__import__("sys").executable, str(ROOT / "scripts" / "release" / "fetch_published.py"), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert help_proc.returncode == 0
    with pytest.raises(fetch.NotReady):
        fetch.fetch(
            index="pypi",
            name="satsgate-sdk",
            version="0.10.0",
            sums=_sums(tmp_path, {"a.whl": b"a", "a.tar.gz": b"b"}),
            dest=tmp_path / "missing",
            opener=lambda _url: (404, b"{}"),
            downloader=lambda _url: b"",
        )


def test_n1_transient_errors_retry_and_bad_sets_do_not(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import http.client

    fetch = _load()
    files = {"pkg-0.1.0-py3-none-any.whl": b"wheel-bytes", "pkg-0.1.0.tar.gz": b"sdist-bytes"}
    sums = _sums(tmp_path, files)

    def attempt(opener, downloader) -> None:
        fetch.fetch(
            index="testpypi",
            name="satsgate-sdk",
            version="0.10.0",
            sums=sums,
            dest=tmp_path / "out",
            opener=opener,
            downloader=downloader,
        )

    with pytest.raises(fetch.NotReady):
        attempt(lambda _url: (500, b""), lambda _url: b"")
    with pytest.raises(fetch.NotReady):
        attempt(lambda _url: (_ for _ in ()).throw(http.client.IncompleteRead(b"x")), lambda _url: b"")
    with pytest.raises(fetch.FetchError, match="downloaded bytes"):
        attempt(lambda _url: (200, _body("testpypi", files)), lambda _url: b"not-the-published-bytes")

    duplicated = json.loads(_body("testpypi", files))
    duplicated["urls"].append(dict(duplicated["urls"][0]))
    with pytest.raises(fetch.FetchError, match="duplicate"):
        attempt(lambda _url: (200, json.dumps(duplicated).encode()), lambda _url: b"")

    monkeypatch.setattr(fetch, "_default_opener", lambda _url: (404, b"{}"))
    monkeypatch.setattr(fetch, "_default_downloader", lambda _url: b"")
    code = fetch.main(
        ["--index", "pypi", "--name", "satsgate-sdk", "--version", "0.10.0", "--sums", str(sums), "--dest", str(tmp_path / "gone")]
    )
    assert code == 2
