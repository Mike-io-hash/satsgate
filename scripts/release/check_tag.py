"""Map a release tag to one package and refuse a tag the tree does not match.

Stdlib only. Python 3.10 or newer. Prints ``package_dir``, ``dist_name`` and
``version`` as ``key=value`` lines for ``$GITHUB_OUTPUT``.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

TAG_RE = re.compile(r"^(sdk|proxy|mcp|satsgate)-v(\d+)\.(\d+)\.(\d+)$")
_VERSION_RE = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']', re.M)
_REQ_RE = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(?:\[[^\]]+\])?\s*(.*)$"
)
_SPEC_RE = re.compile(r"^(===|==|!=|<=|>=|~=|<|>)\s*([0-9]+(?:\.[0-9]+)*)$")

# Tag prefix → directory, distribution name, import package __init__.
PACKAGES: dict[str, dict[str, str]] = {
    "sdk": {
        "package_dir": "sdk/python",
        "dist_name": "satsgate-sdk",
        "init": "sdk/python/src/satsgate_sdk/__init__.py",
    },
    "proxy": {
        "package_dir": "proxy",
        "dist_name": "satsgate-proxy",
        "init": "proxy/src/satsgate_proxy/__init__.py",
    },
    "mcp": {
        "package_dir": "mcp",
        "dist_name": "satsgate-mcp",
        "init": "mcp/src/satsgate_mcp/__init__.py",
    },
    "satsgate": {
        "package_dir": "cli",
        "dist_name": "satsgate",
        "init": "cli/src/satsgate/__init__.py",
    },
}

# Distribution name → pyproject that carries its in-tree version.
_DIST_PYPROJECT = {
    "satsgate-sdk": "sdk/python/pyproject.toml",
    "satsgate-proxy": "proxy/pyproject.toml",
    "satsgate-mcp": "mcp/pyproject.toml",
    "satsgate": "cli/pyproject.toml",
}


class ReleaseCheckError(Exception):
    """The tag is not a release of the tree that was checked."""


def default_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _version_tuple(version: str) -> tuple[int, ...]:
    if not re.fullmatch(r"\d+(?:\.\d+)*", version):
        raise ReleaseCheckError(f"unsupported version {version!r}")
    return tuple(int(part) for part in version.split("."))


def _cmp(left: tuple[int, ...], right: tuple[int, ...]) -> int:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1
    return 0


def satisfies(version: str, spec: str) -> bool:
    """True when ``version`` meets a comma-separated PEP 440 subset."""
    text = spec.strip()
    if not text:
        return True
    current = _version_tuple(version)
    for part in (item.strip() for item in text.split(",")):
        if not part:
            continue
        matched = _SPEC_RE.fullmatch(part.replace(" ", ""))
        if matched is None:
            raise ReleaseCheckError(f"unsupported specifier {part!r}")
        op, raw = matched.group(1), matched.group(2)
        other = _version_tuple(raw)
        order = _cmp(current, other)
        if op in ("==", "===") and order != 0:
            return False
        if op == "!=" and order == 0:
            return False
        if op == "<" and order >= 0:
            return False
        if op == "<=" and order > 0:
            return False
        if op == ">" and order <= 0:
            return False
        if op == ">=" and order < 0:
            return False
        if op == "~=":
            if len(other) < 2:
                raise ReleaseCheckError(f"unsupported specifier {part!r}")
            if order < 0 or _cmp(current[: len(other) - 1], other[:-1]) != 0:
                return False
    return True


def _load_project(path: Path) -> tuple[str, list[str]]:
    text = path.read_text(encoding="utf-8")
    if sys.version_info >= (3, 11):
        import tomllib

        project = tomllib.loads(text)["project"]
        deps = list(project.get("dependencies") or [])
        extras = project.get("optional-dependencies") or {}
        for values in extras.values():
            deps.extend(values)
        return str(project["version"]), [str(item) for item in deps]
    return _version_py310(text), _deps_py310(text)


def _section(text: str, header: str) -> str:
    matched = re.search(rf"(?m)^\[{re.escape(header)}\]\s*$", text)
    if matched is None:
        return ""
    rest = text[matched.end() :]
    nxt = re.search(r"(?m)^\[", rest)
    return rest[: nxt.start()] if nxt else rest


def _quoted_array(body: str, key: str) -> list[str]:
    matched = re.search(rf"(?ms)^{re.escape(key)}\s*=\s*\[(.*?)\]", body)
    if matched is None:
        return []
    return re.findall(r'"([^"]+)"', matched.group(1))


def _version_py310(text: str) -> str:
    matched = re.search(r'(?m)^version\s*=\s*"([^"]+)"\s*$', _section(text, "project"))
    if matched is None:
        raise ReleaseCheckError("pyproject has no project.version")
    return matched.group(1)


def _deps_py310(text: str) -> list[str]:
    deps = _quoted_array(_section(text, "project"), "dependencies")
    extras = _section(text, "project.optional-dependencies")
    deps.extend(re.findall(r'"([^"]+)"', extras))
    return deps


def _dunder_version(path: Path) -> str:
    matched = _VERSION_RE.search(path.read_text(encoding="utf-8"))
    if matched is None:
        raise ReleaseCheckError(f"no __version__ in {path.as_posix()}")
    return matched.group(1)


def _requirement(dep: str) -> tuple[str, str]:
    body = dep.split(";", 1)[0].strip()
    matched = _REQ_RE.fullmatch(body)
    if matched is None:
        raise ReleaseCheckError(f"unsupported requirement {dep!r}")
    return _norm_name(matched.group(1)), matched.group(2).strip()


def _check_pins(root: Path, package_dir: str) -> None:
    _version, deps = _load_project(root / package_dir / "pyproject.toml")
    known = {_norm_name(name): rel for name, rel in _DIST_PYPROJECT.items()}
    for dep in deps:
        name, spec = _requirement(dep)
        rel = known.get(name)
        if rel is None:
            continue
        pinned, _pinned_deps = _load_project(root / rel)
        if not satisfies(pinned, spec):
            raise ReleaseCheckError(f"internal pin {dep!r} does not admit in-tree {pinned}")


def evaluate(tag: str, root: Path | None = None) -> dict[str, str]:
    """Return the output fields for ``tag`` or raise ``ReleaseCheckError``."""
    tree = default_root() if root is None else root
    matched = TAG_RE.fullmatch(tag.strip())
    if matched is None:
        raise ReleaseCheckError(f"not a release tag: {tag}")
    prefix, major, minor, patch = matched.group(1), matched.group(2), matched.group(3), matched.group(4)
    meta = PACKAGES[prefix]
    tag_version = f"{major}.{minor}.{patch}"
    py_version, _deps = _load_project(tree / meta["package_dir"] / "pyproject.toml")
    init_version = _dunder_version(tree / meta["init"])
    if not (tag_version == py_version == init_version):
        raise ReleaseCheckError(
            f"version mismatch for {tag}: tag {tag_version}, pyproject {py_version}, __version__ {init_version}"
        )
    _check_pins(tree, meta["package_dir"])
    return {
        "package_dir": meta["package_dir"],
        "dist_name": meta["dist_name"],
        "version": tag_version,
    }


def format_output(fields: dict[str, str]) -> str:
    return (
        f"package_dir={fields['package_dir']}\n"
        f"dist_name={fields['dist_name']}\n"
        f"version={fields['version']}\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check a sdk/proxy/mcp/satsgate release tag against this tree."
    )
    parser.add_argument("tag", help="Tag, for example sdk-v0.10.0")
    parser.add_argument("--root", type=Path, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        sys.stdout.write(format_output(evaluate(args.tag, args.root)))
    except ReleaseCheckError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
