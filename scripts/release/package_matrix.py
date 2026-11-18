"""Print the publish build matrix as one JSON line.

Test globs were checked against the tree: ``tests/test_sdk_*.py`` is
``tests/test_sdk_accounts.py``; ``tests/test_satsgate_mcp*.py`` is
``tests/test_satsgate_mcp.py`` and ``tests/test_satsgate_mcp_x402.py``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import check_tag  # noqa: E402

# Direct dependencies only. Optional extras are not installed by the smoke.
SPECS: tuple[dict[str, str], ...] = (
    {
        "kind": "sdk",
        "package_dir": "sdk/python",
        "dist_name": "satsgate-sdk",
        "module": "satsgate_sdk",
        "tests": "tests/test_sdk_*.py",
        "commands": "",
    },
    {
        "kind": "proxy",
        "package_dir": "proxy",
        "dist_name": "satsgate-proxy",
        "module": "satsgate_proxy",
        "tests": "tests/test_satsgate_proxy.py tests/test_proxy_parity.py",
        "commands": "satsgate-proxy --help",
    },
    {
        "kind": "mcp",
        "package_dir": "mcp",
        "dist_name": "satsgate-mcp",
        "module": "satsgate_mcp",
        "tests": "tests/test_satsgate_mcp*.py tests/test_mcp_receipts.py",
        "commands": "satsgate-mcp --help|satsgate-mcp-pay --help",
    },
    {
        "kind": "satsgate",
        "package_dir": "cli",
        "dist_name": "satsgate",
        "module": "satsgate",
        "tests": "tests/test_init_*.py tests/test_release_c.py",
        "commands": "satsgate --version|satsgate init --help",
    },
)


def third_party(root: Path, package_dir: str) -> list[str]:
    """Dependency lines that are not one of our own distributions."""
    text = (root / package_dir / "pyproject.toml").read_text(encoding="utf-8")
    if sys.version_info >= (3, 11):
        import tomllib

        deps = [str(item) for item in tomllib.loads(text)["project"].get("dependencies") or []]
    else:
        deps = check_tag._quoted_array(check_tag._section(text, "project"), "dependencies")
    lines: list[str] = []
    for dep in deps:
        name, _spec = check_tag._requirement(dep)
        if name.startswith("satsgate"):
            continue
        lines.append(dep)
    return lines


def rows(root: Path) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for spec in SPECS:
        version, _deps = check_tag._load_project(root / spec["package_dir"] / "pyproject.toml")
        found.append({**spec, "version": version})
    return found


def select(root: Path, tag: str | None, expand_python: bool) -> list[dict[str, str]]:
    selected = rows(root)
    if tag:
        fields = check_tag.evaluate(tag, root)
        selected = [row for row in selected if row["dist_name"] == fields["dist_name"]]
        if len(selected) != 1 or selected[0]["version"] != fields["version"]:
            raise check_tag.ReleaseCheckError("matrix does not match the tag")
    if not expand_python:
        return selected
    expanded: list[dict[str, str]] = []
    for row in selected:
        for python in ("3.10", "3.12"):
            expanded.append({**row, "python": python})
    return expanded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the publish matrix as JSON.")
    parser.add_argument("--tag", default=None)
    parser.add_argument("--expand-python", action="store_true")
    parser.add_argument("--root", type=Path, default=None)
    args = parser.parse_args(argv)
    root = check_tag.default_root() if args.root is None else args.root
    try:
        payload = select(root, args.tag, args.expand_python)
    except check_tag.ReleaseCheckError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    sys.stdout.write(json.dumps(payload, separators=(",", ":")))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
