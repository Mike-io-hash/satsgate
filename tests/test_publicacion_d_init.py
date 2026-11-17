"""T-D.6. The init leftovers stay enforced."""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from init_harness import RecordingSync, invoke
from test_x402 import _load_app

ROOT = Path(__file__).resolve().parents[1]
@pytest.fixture(autouse=True)
def _free_quota(monkeypatch: pytest.MonkeyPatch) -> None:
    """Restored after the test so later modules are not left on the free quota."""
    monkeypatch.setenv("SATSGATE_FREE_QUOTA", "500")


def _app(tmp_path: Path):
    return _load_app(tmp_path, SATSGATE_FREE_QUOTA="500")


def _nosec_count() -> int:
    total = 0
    for path in (ROOT / "cli" / "src").rglob("*"):
        if path.is_file() and path.suffix in {".py", ".md", ".js", ".conf", ".txt", ".yaml", ".yml"}:
            total += path.read_text(encoding="utf-8").count("nosec")
    return total


def test_t_d_6_1_init_inside_a_running_loop_matches_a_plain_call(tmp_path: Path) -> None:
    module = _app(tmp_path)
    http = TestClient(module.app)
    http.__enter__()
    try:
        outside = invoke(tmp_path / "outside", RecordingSync(http))

        async def inside():
            return invoke(tmp_path / "inside", RecordingSync(http))

        inner = asyncio.run(inside())
    finally:
        http.__exit__(None, None, None)
    assert outside[0] == 0, outside[1]
    assert inner[0] == 0, inner[1]
    assert outside[1]["ok"] is True
    assert inner[1]["ok"] is True


def test_t_d_6_2_bandit_is_clean_and_the_tmpfs_nosec_is_the_only_one() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "bandit", "-r", str(ROOT / "cli" / "src"), "-ll"],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    source = (ROOT / "cli" / "src" / "satsgate" / "init.py").read_text(encoding="utf-8")
    assert source.count("nosec B108 - tmpfs mount target inside the read-only container, not a host temp file") == 1
    assert _nosec_count() == 1


def test_t_d_6_3_compose_bind_accepts_a_colon_in_the_source_path(tmp_path: Path) -> None:
    module = _app(tmp_path)
    http = TestClient(module.app)
    http.__enter__()
    absolute = tmp_path / "absolute" / "proxy.yaml"
    absolute.parent.mkdir()
    cases = {
        "colon": (tmp_path / "colon", "a:b.yaml", "./a:b.yaml"),
        "default": (tmp_path / "default", None, "./satsgate-proxy.yaml"),
        "absolute": (tmp_path / "abs", str(absolute), absolute.resolve().as_posix()),
    }
    try:
        for name, (work, yaml_out, source) in cases.items():
            work.mkdir()
            overrides = {"docker": True}
            if yaml_out is not None:
                overrides["yaml_out"] = yaml_out
            code, body, _out, _err = invoke(work, RecordingSync(http), **overrides)
            assert code == 0, (name, body)
            compose = (work / "docker-compose.satsgate.yml").read_text(encoding="utf-8")
            service = yaml.safe_load(compose)["services"]["satsgate-proxy"]
            assert service["volumes"] == [
                {
                    "type": "bind",
                    "source": source,
                    "target": "/etc/satsgate/proxy.yaml",
                    "read_only": True,
                }
            ]
            assert "build" not in service
            if os.environ.get("CI") == "true" and shutil.which("docker") is None:
                raise AssertionError("docker is required when CI=true")
            if shutil.which("docker") is not None:
                proc = subprocess.run(
                    ["docker", "compose", "-f", str(work / "docker-compose.satsgate.yml"), "config"],
                    check=False,
                    capture_output=True,
                    text=True,
                    cwd=work,
                )
                assert proc.returncode == 0, proc.stderr
    finally:
        http.__exit__(None, None, None)


def test_t_d_6_4_usdc_test_mode_can_be_turned_off() -> None:
    source = (ROOT / "cli" / "src" / "satsgate" / "init.py").read_text(encoding="utf-8")
    readme = (ROOT / "cli" / "README.md").read_text(encoding="utf-8")
    for text in (source, readme):
        assert "x402: false" in text
        assert "delete the route's x402 keys" in text
        assert "keys are reused" in text


def test_existing_proxy_dockerfile_is_not_deleted(tmp_path: Path) -> None:
    module = _app(tmp_path)
    http = TestClient(module.app)
    http.__enter__()
    work = tmp_path / "work"
    work.mkdir()
    sentinel = work / "Dockerfile.satsgate-proxy"
    sentinel.write_text("keep\n", encoding="utf-8")
    try:
        code, body, _out, _err = invoke(work, RecordingSync(http), docker=True)
    finally:
        http.__exit__(None, None, None)
    assert code == 0, body
    assert sentinel.read_text(encoding="utf-8") == "keep\n"
    loaded = yaml.safe_load((work / "docker-compose.satsgate.yml").read_text(encoding="utf-8"))
    assert "build" not in loaded["services"]["satsgate-proxy"]
