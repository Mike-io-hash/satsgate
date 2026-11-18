"""T-D.3.4. The plan decision never touches the network in pytest."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release" / "first_release.py"


def _load():
    spec = importlib.util.spec_from_file_location("first_release", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _opener(routes: dict[str, tuple[int, bytes] | BaseException]):
    def opener(url: str) -> tuple[int, bytes]:
        value = routes[url]
        if isinstance(value, BaseException):
            raise value
        return value

    return opener


def test_t_d_3_4_first_release_plan() -> None:
    first = _load()
    name = "satsgate-sdk"
    version = "0.10.0"
    project = first.project_url(name)
    version_url = first.version_url(name, version)
    body = json.dumps({"info": {"version": version}}).encode()

    assert first.decide(name, version, _opener({project: (404, b"missing"), version_url: (404, b"missing")})) == "true"
    assert first.decide(name, version, _opener({project: (200, body), version_url: (404, b"missing")})) == "false"

    with pytest.raises(first.ReleaseError):
        first.decide(name, version, _opener({project: (500, b"nope"), version_url: (404, b"missing")}))
    with pytest.raises(first.ReleaseError):
        first.decide(name, version, _opener({project: TimeoutError("timed out")}))
    with pytest.raises(first.ReleaseError):
        first.decide(name, version, _opener({project: (200, b"{"), version_url: (404, b"missing")}))
    with pytest.raises(first.ReleaseError):
        first.decide(name, version, _opener({project: (200, body), version_url: (200, body)}))
    with pytest.raises(first.ReleaseError):
        first.decide(name, version, _opener({project: (404, b"missing"), version_url: (200, body)}))
    with pytest.raises(first.ReleaseError):
        first.decide("not-ours", version, _opener({}))

    with pytest.raises(first.ReleaseError):
        first.default_opener("https://example.com/pypi/satsgate-sdk/json")
    with pytest.raises(first.ReleaseError):
        first.default_opener("http://pypi.org/pypi/satsgate-sdk/json")
