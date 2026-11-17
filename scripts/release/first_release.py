"""Decide whether a PyPI project is being released for the first time.

The plan job calls this. 404 on the project means a TestPyPI rehearsal is
required. 200 means the project already exists. Any other status, a network
error, malformed JSON, or a version that is already on PyPI is a failure.
No flag can force or skip the rehearsal.
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import sys
import urllib.parse
from collections.abc import Callable

NAMES = frozenset({"satsgate-sdk", "satsgate-proxy", "satsgate-mcp", "satsgate"})
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
HOST = "pypi.org"

Opener = Callable[[str], tuple[int, bytes]]


class ReleaseError(Exception):
    """The plan could not be decided. The run must stop."""


def project_url(name: str) -> str:
    _check_name(name)
    return f"https://{HOST}/pypi/{name}/json"


def version_url(name: str, version: str) -> str:
    _check_name(name)
    _check_version(version)
    return f"https://{HOST}/pypi/{name}/{version}/json"


def _check_name(name: str) -> None:
    if name not in NAMES:
        raise ReleaseError(f"unknown project {name}")


def _check_version(version: str) -> None:
    if _VERSION_RE.fullmatch(version) is None:
        raise ReleaseError(f"unsupported version {version}")


def default_opener(url: str) -> tuple[int, bytes]:
    """GET one https://pypi.org URL. The host is fixed; other URLs are refused."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != HOST or not parsed.path.startswith("/pypi/"):
        raise ReleaseError("refusing a non-pypi URL")
    try:
        connection = http.client.HTTPSConnection(HOST, timeout=30)
        try:
            connection.request(
                "GET",
                parsed.path,
                headers={"Accept": "application/json", "User-Agent": "satsgate-release"},
            )
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()
    except (TimeoutError, OSError) as exc:
        raise ReleaseError(exc.__class__.__name__) from exc


def _json_ok(status: int, body: bytes) -> None:
    if status != 200:
        return
    try:
        json.loads(body)
    except json.JSONDecodeError as exc:
        raise ReleaseError("malformed JSON") from exc


def decide(name: str, version: str, opener: Opener) -> str:
    """Return ``true`` or ``false`` for the ``rehearse`` output."""
    _check_name(name)
    _check_version(version)
    try:
        status, body = opener(project_url(name))
    except ReleaseError:
        raise
    except (TimeoutError, OSError) as exc:
        raise ReleaseError(exc.__class__.__name__) from exc
    _json_ok(status, body)
    if status == 404:
        rehearse = "true"
    elif status == 200:
        rehearse = "false"
    else:
        raise ReleaseError(f"project lookup failed with status {status}")
    try:
        version_status, version_body = opener(version_url(name, version))
    except ReleaseError:
        raise
    except (TimeoutError, OSError) as exc:
        raise ReleaseError(exc.__class__.__name__) from exc
    _json_ok(version_status, version_body)
    if version_status == 200:
        raise ReleaseError("version is already on PyPI")
    if version_status != 404:
        raise ReleaseError(f"version lookup failed with status {version_status}")
    return rehearse


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decide if this is the project's first PyPI release.")
    parser.add_argument("name")
    parser.add_argument("version")
    args = parser.parse_args(argv)
    try:
        rehearse = decide(args.name, args.version, default_opener)
    except ReleaseError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    sys.stdout.write(f"rehearse={rehearse}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
