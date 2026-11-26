"""Install plans stay off TestPyPI, and a closed port does not write a key."""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RELEASE = ROOT / "scripts" / "release"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, RELEASE / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _wheels(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name in (
        "satsgate_sdk-0.10.0-py3-none-any.whl",
        "satsgate_proxy-0.14.1-py3-none-any.whl",
        "satsgate_mcp-0.13.0-py3-none-any.whl",
        "satsgate-0.1.0-py3-none-any.whl",
    ):
        (directory / name).write_bytes(b"wheel")


def test_smoke_install_never_uses_testpypi_as_an_index(tmp_path: Path) -> None:
    smoke = _load("smoke_install")
    _wheels(tmp_path)
    for dist, mode in (
        ("satsgate-sdk", "pr"),
        ("satsgate-sdk", "tag"),
        ("satsgate", "pr"),
        ("satsgate", "tag"),
    ):
        planned = smoke.commands(ROOT, dist, tmp_path, mode)
        flat = " ".join(" ".join(cmd) for cmd in planned)
        assert "test.pypi.org" not in flat
        assert "extra-index-url" not in flat
        assert "https://pypi.org/simple" in flat
        for cmd in planned:
            if any(arg.endswith(".whl") for arg in cmd):
                assert "--no-deps" in cmd
        if dist == "satsgate" and mode == "tag":
            joined = " ".join(planned[0])
            assert "satsgate-sdk==0.10.1" in joined
            assert "satsgate-proxy==0.15.0" in joined


def test_hash_mismatch_names_the_file_only(tmp_path: Path) -> None:
    hashes = _load("hashes")
    payload = b"built-bytes"
    (tmp_path / "pkg.whl").write_bytes(payload)
    (tmp_path / "pkg.tar.gz").write_bytes(payload)
    sums = tmp_path / "SHA256SUMS"
    digest = __import__("hashlib").sha256(payload).hexdigest()
    sums.write_text(f"{digest}  pkg.whl\n{digest}  pkg.tar.gz\n", encoding="utf-8")
    got = tmp_path / "got"
    got.mkdir()
    (got / "pkg.whl").write_bytes(payload)
    (got / "pkg.tar.gz").write_bytes(payload)
    hashes.assert_same(sums, got)
    (got / "pkg.whl").write_bytes(b"other-bytes")
    with pytest.raises(hashes.HashError, match="hash mismatch: pkg.whl"):
        hashes.assert_same(sums, got)


def test_console_script_is_next_to_the_venv_python_symlink(tmp_path: Path) -> None:
    check = _load("smoke_check")
    real = tmp_path / "real"
    real.mkdir()
    (real / "python").write_text("#!/bin/sh\n", encoding="utf-8")
    bindir = tmp_path / "venv" / "bin"
    bindir.mkdir(parents=True)
    python = bindir / "python"
    python.symlink_to(real / "python")
    script = bindir / "satsgate-proxy"
    script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    script.chmod(0o755)
    check.check_commands(str(python), ["satsgate-proxy --help"])
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    planted = elsewhere / "satsgate-proxy"
    planted.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    planted.chmod(0o755)
    script.unlink()
    previous = os.environ.get("PATH", "")
    os.environ["PATH"] = str(elsewhere) + os.pathsep + previous
    try:
        with pytest.raises(check.SmokeError, match="missing console script"):
            check.check_commands(str(python), ["satsgate-proxy --help"])
    finally:
        os.environ["PATH"] = previous


def test_n4_main_runs_pip_check(tmp_path: Path) -> None:
    check = _load("smoke_check")
    python = tmp_path / "python"
    python.write_text(
        "#!/bin/sh\n"
        'case "$1" in\n'
        "  -c) echo 0.1.1; exit 0 ;;\n"
        "  -m) echo pip-broken >&2; exit 1 ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    python.chmod(0o755)
    code = check.main(["--python", str(python), "--module", "satsgate", "--version", "0.1.1", "--commands", ""])
    assert code == 1


def test_init_probe_on_a_closed_port_writes_no_key(tmp_path: Path) -> None:
    check = _load("smoke_check")
    env_python = os.environ.get("PYTHONPATH", "")
    parts = [
        str(ROOT / "cli" / "src"),
        str(ROOT / "sdk" / "python" / "src"),
        str(ROOT / "proxy" / "src"),
    ]
    if env_python:
        parts.append(env_python)
    os.environ["PYTHONPATH"] = os.pathsep.join(parts)
    try:
        check.init_probe(sys.executable, tmp_path)
    finally:
        if env_python:
            os.environ["PYTHONPATH"] = env_python
        else:
            os.environ.pop("PYTHONPATH", None)
    assert not (tmp_path / ".satsgate" / "account.env").exists()
