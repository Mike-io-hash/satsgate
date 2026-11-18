"""Build a package into a temp directory and remove the egg-info it leaves behind."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGES = (
    ROOT / "sdk" / "python",
    ROOT / "proxy",
    ROOT / "mcp",
    ROOT / "cli",
)


def source_epoch() -> str:
    return subprocess.check_output(["git", "log", "-1", "--format=%ct"], cwd=ROOT, text=True).strip()


def build_env(epoch: str | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env["TZ"] = "UTC"
    if epoch is not None:
        env["SOURCE_DATE_EPOCH"] = epoch
    return env


def cleanup(package: Path) -> None:
    for path in package.glob("*.egg-info"):
        shutil.rmtree(path, ignore_errors=True)
    build_dir = package / "build"
    if build_dir.is_dir():
        shutil.rmtree(build_dir, ignore_errors=True)


def build_package(package: Path, out: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    out.mkdir(parents=True, exist_ok=True)
    cleanup(package)
    try:
        return subprocess.run(
            [sys.executable, "-m", "build", "--outdir", str(out), str(package)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
    finally:
        cleanup(package)
