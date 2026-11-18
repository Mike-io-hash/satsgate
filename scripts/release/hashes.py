"""Compare downloaded distribution files with a SHA256SUMS list.

The sums file is the one produced next to the build. A mismatch names the
file and the rule, never the file bytes.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path


class HashError(Exception):
    """A downloaded file is not the file that was built."""


def _expected(sums: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in sums.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        found[Path(name.strip()).name] = digest
    if not found:
        raise HashError("SHA256SUMS is empty")
    return found


def assert_same(sums: Path, directory: Path) -> None:
    expected = _expected(sums)
    files = sorted(path for path in directory.iterdir() if path.is_file())
    names = {path.name for path in files}
    if not any(name.endswith(".whl") for name in names):
        raise HashError("no wheel")
    if not any(name.endswith(".tar.gz") for name in names):
        raise HashError("no sdist")
    for path in files:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if expected.get(path.name) != digest:
            raise HashError(f"hash mismatch: {path.name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check downloaded files against SHA256SUMS.")
    parser.add_argument("sums", type=Path)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    try:
        assert_same(args.sums, args.directory)
    except (HashError, OSError) as exc:
        sys.stderr.write(f"{exc.__class__.__name__}: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
