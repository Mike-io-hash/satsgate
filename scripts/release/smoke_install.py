"""Install a built distribution into an existing interpreter.

Our own names are never resolved from an index on the pull-request path.
On a tag, sibling packages are installed from pypi.org at the in-tree version.
TestPyPI is never used as an index.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_tag  # noqa: E402
import package_matrix  # noqa: E402

INDEX = "https://pypi.org/simple"
_SIBLINGS = ("satsgate-sdk", "satsgate-proxy")


class SmokeError(Exception):
    """The built files could not be installed safely."""


def _wheel_prefix(dist: str) -> str:
    return dist.replace("-", "_") + "-"


def find_wheel(dist: str, artifacts: Path) -> Path:
    prefix = _wheel_prefix(dist)
    found = sorted(path for path in artifacts.rglob("*.whl") if path.name.startswith(prefix))
    if len(found) != 1:
        raise SmokeError(f"expected one wheel for {dist}, found {len(found)}")
    return found[0]


def _spec(dist: str) -> dict[str, str]:
    for row in package_matrix.SPECS:
        if row["dist_name"] == dist:
            return row
    raise SmokeError(f"unknown distribution {dist}")


def commands(root: Path, dist: str, artifacts: Path, mode: str) -> list[list[str]]:
    """pip argument lists, without the interpreter. ``mode`` is ``pr`` or ``tag``."""
    if mode not in {"pr", "tag"}:
        raise SmokeError(f"unknown mode {mode}")
    spec = _spec(dist)
    ours = find_wheel(dist, artifacts)
    third = package_matrix.third_party(root, spec["package_dir"])
    if dist != "satsgate":
        planned = [["install", "--index-url", INDEX, "--no-deps", str(ours)]]
        if third:
            planned.append(["install", "--index-url", INDEX, *third])
        return planned
    if mode == "pr":
        siblings = [str(find_wheel(name, artifacts)) for name in _SIBLINGS]
        planned = [["install", "--index-url", INDEX, "--no-deps", *siblings, str(ours)]]
        sibling_third: list[str] = []
        for name in _SIBLINGS:
            sibling_third.extend(package_matrix.third_party(root, _spec(name)["package_dir"]))
        sibling_third.extend(third)
        if sibling_third:
            planned.append(["install", "--index-url", INDEX, *sibling_third])
        return planned
    versions = []
    for name in _SIBLINGS:
        version, _deps = check_tag._load_project(root / _spec(name)["package_dir"] / "pyproject.toml")
        versions.append(f"{name}=={version}")
    return [
        ["install", "--index-url", INDEX, *versions],
        ["install", "--index-url", INDEX, "--no-deps", str(ours)],
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Install built wheels without resolving our names unsafely.")
    parser.add_argument("--python", required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--dist", required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--mode", required=True, choices=("pr", "tag"))
    args = parser.parse_args(argv)
    try:
        planned = commands(args.root, args.dist, args.artifacts, args.mode)
    except (SmokeError, check_tag.ReleaseCheckError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    for pip_args in planned:
        proc = subprocess.run([args.python, "-m", "pip", *pip_args], check=False)
        if proc.returncode != 0:
            return proc.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
