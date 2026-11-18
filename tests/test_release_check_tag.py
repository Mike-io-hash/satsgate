"""T-D.2.1. check_tag accepts only a release tag whose tree versions and pins agree."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release" / "check_tag.py"

_TREE = (
    "sdk/python/pyproject.toml",
    "sdk/python/src/satsgate_sdk/__init__.py",
    "proxy/pyproject.toml",
    "proxy/src/satsgate_proxy/__init__.py",
    "mcp/pyproject.toml",
    "mcp/src/satsgate_mcp/__init__.py",
    "cli/pyproject.toml",
    "cli/src/satsgate/__init__.py",
)


def _load():
    spec = importlib.util.spec_from_file_location("check_tag", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _copy_tree(tmp_path: Path) -> Path:
    for rel in _TREE:
        dest = tmp_path / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, dest)
    return tmp_path


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        check=False,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )


def test_t_d_2_1_check_tag(tmp_path: Path) -> None:
    check_tag = _load()
    help_proc = _run("--help")
    assert help_proc.returncode == 0
    assert "usage" in help_proc.stdout.lower()

    assert check_tag.satisfies("0.10.0", ">=0.10.0,<0.11")
    assert check_tag.satisfies("0.10.9", ">=0.10.0,<0.11")
    assert not check_tag.satisfies("0.11.0", ">=0.10.0,<0.11")
    assert not check_tag.satisfies("0.9.0", ">=0.10.0")

    for prefix, meta in check_tag.PACKAGES.items():
        text = (ROOT / meta["package_dir"] / "pyproject.toml").read_text(encoding="utf-8")
        loaded = tomllib.loads(text)["project"]
        assert check_tag._version_py310(text) == loaded["version"]
        py310_deps = check_tag._deps_py310(text)
        project_path = ROOT / meta["package_dir"] / "pyproject.toml"
        assert sorted(py310_deps) == sorted(check_tag._load_project(project_path)[1])
        version = loaded["version"]
        tag = f"{prefix}-v{version}"
        fields = check_tag.evaluate(tag, ROOT)
        assert fields == {
            "package_dir": meta["package_dir"],
            "dist_name": meta["dist_name"],
            "version": version,
        }
        proc = _run(tag)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == check_tag.format_output(fields)

    for tag in ("sdk-v0.10", "sdk-v0.10.0-rc1", "other-v1.0.0", "v0.2.0"):
        with pytest.raises(check_tag.ReleaseCheckError):
            check_tag.evaluate(tag, ROOT)
        assert _run(tag).returncode != 0

    with pytest.raises(check_tag.ReleaseCheckError):
        check_tag.evaluate("sdk-v0.9.9", ROOT)

    mismatch = _copy_tree(tmp_path / "mismatch")
    init = mismatch / "sdk/python/src/satsgate_sdk/__init__.py"
    init.write_text(init.read_text(encoding="utf-8").replace("0.10.0", "0.10.1", 1), encoding="utf-8")
    with pytest.raises(check_tag.ReleaseCheckError):
        check_tag.evaluate("sdk-v0.10.0", mismatch)

    broken = _copy_tree(tmp_path / "pin")
    pyproject = broken / "cli/pyproject.toml"
    pyproject.write_text(
        pyproject.read_text(encoding="utf-8").replace(
            "satsgate-sdk>=0.10.1,<0.11",
            "satsgate-sdk>=9.0.0,<9.1",
        ),
        encoding="utf-8",
    )
    cli_version = tomllib.loads((ROOT / "cli/pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    with pytest.raises(check_tag.ReleaseCheckError):
        check_tag.evaluate(f"satsgate-v{cli_version}", broken)
