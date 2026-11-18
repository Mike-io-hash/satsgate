"""T-D.2.2. audit_dist passes a real build and fails closed without echoing a secret."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from release_build import PACKAGES, build_package

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release" / "audit_dist.py"
SECRET = "sgr_" + ("A" * 32)


def _load():
    spec = importlib.util.spec_from_file_location("audit_dist", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(directory: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(directory)],
        check=False,
        capture_output=True,
        text=True,
    )


def _inject(wheel: Path, dest: Path, member: str, payload: bytes) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(wheel, dest)
    with zipfile.ZipFile(dest, "a") as archive:
        archive.writestr(member, payload)


def test_t_d_2_2_audit_dist(tmp_path: Path) -> None:
    audit_dist = _load()
    help_proc = subprocess.run([sys.executable, str(SCRIPT), "--help"], check=False, capture_output=True, text=True)
    assert help_proc.returncode == 0
    assert "usage" in help_proc.stdout.lower()
    assert audit_dist._content_rules(b"placeholder sgr_test and sg_demo") == []
    assert audit_dist._content_rules(SECRET.encode()) == ["content:sg-token"]

    wheels: list[Path] = []
    for package in PACKAGES:
        out = tmp_path / "clean" / package.name
        proc = build_package(package, out)
        assert proc.returncode == 0, proc.stderr[-2000:]
        audited = _run(out)
        assert audited.returncode == 0, audited.stdout + audited.stderr
        assert audited.stdout == ""
        wheels.extend(out.glob("*.whl"))
    sdk_wheel = next(path for path in wheels if path.name.startswith("satsgate_sdk-"))
    cli_wheel = next(path for path in wheels if path.name.startswith("satsgate-"))

    cases = (
        ("env", "satsgate_sdk/.env", b"TOKEN=1", "member:.env"),
        ("tests", "tests/x.py", b"x = 1\n", "member:tests/"),
        ("account", "satsgate_sdk/account.env", b"A=1\n", "member:account.env"),
        ("secret", "satsgate_sdk/note.txt", SECRET.encode(), "content:sg-token"),
    )
    for name, member, payload, rule in cases:
        directory = tmp_path / name
        _inject(sdk_wheel, directory / sdk_wheel.name, member, payload)
        audited = _run(directory)
        assert audited.returncode != 0, name
        assert rule in audited.stdout, audited.stdout
        assert SECRET not in audited.stdout
        assert SECRET not in audited.stderr
    stray = tmp_path / "stray"
    _inject(cli_wheel, stray / cli_wheel.name, "satsgate_proxy/__init__.py", b"x = 1\n")
    audited = _run(stray)
    assert audited.returncode != 0
    assert "wheel:stray-module:satsgate_proxy" in audited.stdout
