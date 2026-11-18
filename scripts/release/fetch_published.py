"""Download a published release from the PyPI JSON API.

The published set ``{filename: sha256}`` must equal the build's SHA256SUMS.
Files are fetched only from ``files.pythonhosted.org`` or
``test-files.pythonhosted.org``. pip is not used, so the index is never asked
to supply a build backend.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import sys
import urllib.parse
from collections.abc import Callable
from pathlib import Path

INDEX_HOSTS = {"pypi": "pypi.org", "testpypi": "test.pypi.org"}
FILE_HOSTS = {
    "pypi": "files.pythonhosted.org",
    "testpypi": "test-files.pythonhosted.org",
}

Opener = Callable[[str], tuple[int, bytes]]
Downloader = Callable[[str], bytes]


class FetchError(Exception):
    """The published files are not the files that were built."""


class NotReady(Exception):
    """The project version is not on the index yet. The caller may retry."""


def parse_sums(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        found[Path(name.strip()).name] = digest
    if not found:
        raise FetchError("SHA256SUMS is empty")
    return found


def release_url(index: str, name: str, version: str) -> str:
    host = INDEX_HOSTS.get(index)
    if host is None:
        raise FetchError(f"unknown index {index}")
    if "/" in name or "/" in version:
        raise FetchError("refusing a name or version with a slash")
    return f"https://{host}/pypi/{name}/{version}/json"


def published_files(body: bytes, *, index: str) -> dict[str, tuple[str, str]]:
    """Return ``filename → (url, sha256)`` from a project version JSON body."""
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise FetchError("malformed JSON") from exc
    urls = data.get("urls") if isinstance(data, dict) else None
    if not isinstance(urls, list) or not urls:
        raise FetchError("release JSON has no files")
    found: dict[str, tuple[str, str]] = {}
    for item in urls:
        if not isinstance(item, dict):
            raise FetchError("release JSON has a file that is not an object")
        filename = item.get("filename")
        url = item.get("url")
        digests = item.get("digests")
        sha = digests.get("sha256") if isinstance(digests, dict) else None
        if not isinstance(filename, str) or not isinstance(url, str) or not isinstance(sha, str):
            raise FetchError("release JSON is missing a filename, url, or sha256")
        if filename in found:
            raise FetchError(f"duplicate published file {filename}")
        _require_file_host(url, index=index)
        found[filename] = (url, sha)
    return found


def _require_file_host(url: str, *, index: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    expected = FILE_HOSTS[index]
    if parsed.scheme != "https" or parsed.hostname != expected or parsed.username or parsed.password:
        host = parsed.hostname or url
        raise FetchError(f"refusing host {host}")


def assert_exact(expected: dict[str, str], published: dict[str, str]) -> None:
    extra = sorted(set(published) - set(expected))
    missing = sorted(set(expected) - set(published))
    mismatched = sorted(name for name in expected.keys() & published.keys() if expected[name] != published[name])
    if mismatched:
        raise FetchError("sha mismatch: " + ", ".join(mismatched))
    if extra:
        raise FetchError("extra file: " + ", ".join(extra))
    if missing:
        # The files that are present match. The index may still be catching up.
        raise NotReady("published set is incomplete: " + ", ".join(missing))


def fetch(
    *,
    index: str,
    name: str,
    version: str,
    sums: Path,
    dest: Path,
    opener: Opener,
    downloader: Downloader,
) -> None:
    expected = parse_sums(sums.read_text(encoding="utf-8"))
    try:
        status, body = opener(release_url(index, name, version))
    except (http.client.IncompleteRead, TimeoutError, OSError) as exc:
        raise NotReady(exc.__class__.__name__) from exc
    if status == 404 or status >= 500:
        raise NotReady(f"{name} {version} is not on {index} ({status})")
    if status != 200:
        raise FetchError(f"index returned {status}")
    files = published_files(body, index=index)
    assert_exact(expected, {filename: sha for filename, (_url, sha) in files.items()})
    dest.mkdir(parents=True, exist_ok=True)
    for filename, (url, sha) in files.items():
        try:
            payload = downloader(url)
        except (http.client.IncompleteRead, TimeoutError, OSError) as exc:
            raise NotReady(exc.__class__.__name__) from exc
        got = hashlib.sha256(payload).hexdigest()
        if got != sha:
            raise FetchError(f"downloaded bytes do not match {filename}")
        (dest / filename).write_bytes(payload)


def _https_get(url: str, *, allowed: set[str], timeout: int, accept: str | None = None) -> tuple[int, bytes]:
    """GET one https URL. Redirects are not followed."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in allowed or parsed.username or parsed.password:
        raise FetchError(f"refusing host {parsed.hostname or url}")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    headers = {"User-Agent": "satsgate-release"}
    if accept:
        headers["Accept"] = accept
    try:
        connection = http.client.HTTPSConnection(parsed.hostname, timeout=timeout)
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()
    except (http.client.IncompleteRead, TimeoutError, OSError) as exc:
        raise NotReady(exc.__class__.__name__) from exc


def _default_opener(url: str) -> tuple[int, bytes]:
    return _https_get(url, allowed=set(INDEX_HOSTS.values()), timeout=20, accept="application/json")


def _default_downloader(url: str) -> bytes:
    status, body = _https_get(url, allowed=set(FILE_HOSTS.values()), timeout=60)
    if status >= 500:
        raise NotReady(f"download returned {status}")
    if status != 200:
        raise FetchError(f"download returned {status}")
    return body


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download published files and match SHA256SUMS.")
    parser.add_argument("--index", required=True, choices=tuple(INDEX_HOSTS))
    parser.add_argument("--name", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--sums", type=Path, required=True)
    parser.add_argument("--dest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        fetch(
            index=args.index,
            name=args.name,
            version=args.version,
            sums=args.sums,
            dest=args.dest,
            opener=_default_opener,
            downloader=_default_downloader,
        )
    except NotReady as exc:
        sys.stderr.write(f"{exc}\n")
        return 2
    except (FetchError, OSError) as exc:
        sys.stderr.write(f"{exc.__class__.__name__}: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
