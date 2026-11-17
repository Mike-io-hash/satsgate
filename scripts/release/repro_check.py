"""Compare two build directories.

Wheels must be byte-identical. Sdists must list the same members and those
members must have the same bytes. Tar headers (mtime, uid, pax metadata) may differ.
"""

from __future__ import annotations

import argparse
import sys
import tarfile
from pathlib import Path


class ReproError(Exception):
    """The two directories are not a reproducible pair."""


def _named(directory: Path, suffix: str) -> dict[str, Path]:
    return {
        path.name: path
        for path in directory.iterdir()
        if path.is_file() and path.name.endswith(suffix)
    }


def _tar_members(path: Path) -> dict[str, bytes | None]:
    found: dict[str, bytes | None] = {}
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            # pax extended/global headers and GNU long-name headers are archive metadata.
            if member.type in {"x", "g", "L", "K"}:
                continue
            if member.name in found:
                raise ReproError(f"duplicate member {member.name} in {path.name}")
            if member.isfile():
                extracted = archive.extractfile(member)
                found[member.name] = b"" if extracted is None else extracted.read()
            elif member.issym() or member.islnk():
                found[member.name] = (member.linkname or "").encode("utf-8")
            else:
                found[member.name] = None
    return found


def compare(dir_a: Path, dir_b: Path) -> None:
    """Raise ``ReproError`` when the two directories would not publish the same bytes."""
    if not dir_a.is_dir() or not dir_b.is_dir():
        raise ReproError("both arguments must be directories")
    for suffix, identical in ((".whl", True), (".tar.gz", False)):
        left = _named(dir_a, suffix)
        right = _named(dir_b, suffix)
        if not left and not right:
            continue
        if sorted(left) != sorted(right):
            raise ReproError(f"{suffix} names differ: {sorted(left)} vs {sorted(right)}")
        for name in sorted(left):
            if identical:
                if left[name].read_bytes() != right[name].read_bytes():
                    raise ReproError(f"wheel bytes differ: {name}")
                continue
            members_a = _tar_members(left[name])
            members_b = _tar_members(right[name])
            if members_a != members_b:
                raise ReproError(f"sdist members differ: {name}")
    if not _named(dir_a, ".whl") and not _named(dir_a, ".tar.gz"):
        raise ReproError("no wheel or sdist to compare")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check that two package builds are reproducible.")
    parser.add_argument("dir_a", type=Path)
    parser.add_argument("dir_b", type=Path)
    args = parser.parse_args(argv)
    try:
        compare(args.dir_a, args.dir_b)
    except (ReproError, OSError, tarfile.TarError) as exc:
        sys.stderr.write(f"{exc.__class__.__name__}: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
