"""T-D.2.3. Two builds with one SOURCE_DATE_EPOCH match; one flipped wheel byte does not."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from release_build import ROOT, build_env, build_package, source_epoch

SCRIPT = ROOT / "scripts" / "release" / "repro_check.py"
PACKAGE = ROOT / "sdk" / "python"


def _run(dir_a: Path, dir_b: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), str(dir_a), str(dir_b)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_t_d_2_3_repro_check(tmp_path: Path) -> None:
    help_proc = subprocess.run([sys.executable, str(SCRIPT), "--help"], check=False, capture_output=True, text=True)
    assert help_proc.returncode == 0
    assert "usage" in help_proc.stdout.lower()

    env = build_env(source_epoch())
    first = tmp_path / "a"
    second = tmp_path / "b"
    built_a = build_package(PACKAGE, first, env)
    built_b = build_package(PACKAGE, second, env)
    assert built_a.returncode == 0, built_a.stderr[-2000:]
    assert built_b.returncode == 0, built_b.stderr[-2000:]
    matched = _run(first, second)
    assert matched.returncode == 0, matched.stderr

    wheel = next(second.glob("*.whl"))
    payload = bytearray(wheel.read_bytes())
    payload[len(payload) // 2] ^= 0x01
    wheel.write_bytes(payload)
    flipped = _run(first, second)
    assert flipped.returncode != 0
    assert "wheel bytes differ" in flipped.stderr
