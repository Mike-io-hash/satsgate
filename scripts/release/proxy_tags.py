"""Tags for the public proxy image. ``latest`` is only the highest proxy-v* tag."""

from __future__ import annotations

import argparse
import re
import sys

IMAGE = "ghcr.io/mike-io-hash/satsgate-proxy"
_TAG = re.compile(r"^proxy-v(\d+)\.(\d+)\.(\d+)$")
_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def _version(text: str) -> tuple[int, int, int]:
    matched = _VERSION.fullmatch(text.strip())
    if matched is None:
        raise ValueError(f"unsupported version {text}")
    return int(matched.group(1)), int(matched.group(2)), int(matched.group(3))


def tag_lines(version: str, existing: list[str]) -> list[str]:
    """metadata-action ``type=raw`` lines for this proxy version."""
    current = _version(version)
    known = [current]
    for tag in existing:
        matched = _TAG.fullmatch(tag.strip())
        if matched:
            known.append((int(matched.group(1)), int(matched.group(2)), int(matched.group(3))))
    names = [version, f"{current[0]}.{current[1]}"]
    if current == max(known):
        names.append("latest")
    return [f"type=raw,value={name}" for name in names]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print GHCR tag definitions for one proxy version.")
    parser.add_argument("version")
    parser.add_argument("tags", nargs="*")
    args = parser.parse_args(argv)
    try:
        lines = tag_lines(args.version, list(args.tags))
    except ValueError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    sys.stdout.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
