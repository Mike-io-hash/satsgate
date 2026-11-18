"""Check a built distribution directory against SHA256SUMS.

The files in the directory, other than SHA256SUMS itself, must be exactly the
names listed there, and each byte hash must match. ``--expect-json`` is the
mapping the build job recorded before the tests ran. ``--copy-to`` copies only
the listed names.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path


class VerifyError(Exception):
    """The directory is not the distribution the build job produced."""


def parse_sums(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2 or len(parts[0]) != 64:
            raise VerifyError("malformed SHA256SUMS line")
        digest, name = parts
        filename = Path(name).name
        if filename in found:
            raise VerifyError(f"duplicate sum for {filename}")
        found[filename] = digest
    if not found:
        raise VerifyError("SHA256SUMS is empty")
    return found


def dumps(mapping: dict[str, str]) -> str:
    return json.dumps(mapping, sort_keys=True, separators=(",", ":"))


def verify_directory(directory: Path) -> dict[str, str]:
    sums_path = directory / "SHA256SUMS"
    if not sums_path.is_file():
        raise VerifyError(f"SHA256SUMS is missing in {directory}")
    expected = parse_sums(sums_path.read_text(encoding="utf-8"))
    present = {path.name for path in directory.iterdir() if path.is_file() and path.name != "SHA256SUMS"}
    extra = sorted(present - set(expected))
    missing = sorted(set(expected) - present)
    if extra or missing:
        detail = []
        if extra:
            detail.append("extra file: " + ", ".join(extra))
        if missing:
            detail.append("missing file: " + ", ".join(missing))
        raise VerifyError("; ".join(detail))
    for name, digest in expected.items():
        got = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        if got != digest:
            raise VerifyError(f"hash mismatch: {name}")
    return expected


def verify_root(root: Path, expect: dict[str, str] | None) -> list[dict[str, str]]:
    sums = sorted(path for path in root.rglob("SHA256SUMS") if path.is_file())
    if not sums:
        raise VerifyError("no SHA256SUMS")
    found = [verify_directory(path.parent) for path in sums]
    if expect is not None and expect not in found:
        raise VerifyError("no artifact matches the build output")
    return found


def copy_listed(directory: Path, dest: Path) -> None:
    expected = verify_directory(directory)
    dest.mkdir(parents=True, exist_ok=True)
    for name in expected:
        shutil.copyfile(directory / name, dest / name)


def _expect(raw: str | None) -> dict[str, str] | None:
    if raw is None:
        return None
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise VerifyError("build output is not JSON") from exc
    if not isinstance(loaded, dict) or not loaded or not all(isinstance(k, str) and isinstance(v, str) for k, v in loaded.items()):
        raise VerifyError("build output is not a filename map")
    return loaded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify SHA256SUMS and the build job output.")
    parser.add_argument("--dir", type=Path)
    parser.add_argument("--root", type=Path)
    parser.add_argument("--expect-json")
    parser.add_argument("--format", choices=("json",))
    parser.add_argument("--copy-to", type=Path)
    args = parser.parse_args(argv)
    try:
        expect = _expect(args.expect_json)
        if args.dir is not None:
            found = verify_directory(args.dir)
            if expect is not None and found != expect:
                raise VerifyError("SHA256SUMS does not match the build output")
            if args.copy_to is not None:
                copy_listed(args.dir, args.copy_to)
            if args.format == "json":
                sys.stdout.write(dumps(found) + "\n")
        elif args.root is not None:
            verify_root(args.root, expect)
        else:
            raise VerifyError("pass --dir or --root")
    except VerifyError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
