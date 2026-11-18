"""Refuse a built sdist or wheel that carries a secret, a test, or a stray module.

Prints ``artifact: member: rule-id`` lines only. Matching file contents are
never written to stdout or stderr.
"""

from __future__ import annotations

import argparse
import re
import sys
import tarfile
import zipfile
from pathlib import Path

# Distribution name (normalized) → the only top-level import module allowed.
_MODULES = {
    "satsgate-sdk": "satsgate_sdk",
    "satsgate-proxy": "satsgate_proxy",
    "satsgate-mcp": "satsgate_mcp",
    "satsgate": "satsgate",
}

_CONTENT = (
    ("content:sg-token", re.compile(rb"\bsg[rec]?_[A-Za-z0-9_-]{20,}")),
    ("content:private-key", re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("content:nsec", re.compile(rb"\bnsec1[0-9a-z]{20,}")),
    ("content:hex-key", re.compile(rb"0x[0-9a-fA-F]{64}\b")),
)

_DIR_RULES = {
    "tests": "member:tests/",
    ".satsgate": "member:.satsgate/",
    ".git": "member:.git/",
    "__pycache__": "member:__pycache__/",
    "node_modules": "member:node_modules/",
    "data": "member:data/",
    "backups": "member:backups/",
}


class AuditError(Exception):
    """The artifact directory could not be audited."""


def _norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parts(name: str) -> list[str]:
    return [part for part in name.replace("\\", "/").split("/") if part not in ("", ".")]


def member_rules(name: str) -> list[str]:
    """Rule ids hit by this archive member name. Contents are not inspected."""
    parts = _parts(name)
    if not parts:
        return []
    base = parts[-1]
    found: list[str] = []
    if base == ".env":
        found.append("member:.env")
    if base.startswith(".env."):
        found.append("member:.env.*")
    if base == "account.env":
        found.append("member:account.env")
    if base.endswith(".sqlite3"):
        found.append("member:*.sqlite3")
    if base.endswith(".db"):
        found.append("member:*.db")
    if base.endswith(".pem"):
        found.append("member:*.pem")
    if base.endswith(".key"):
        found.append("member:*.key")
    if base.endswith(".pyc"):
        found.append("member:*.pyc")
    if base.startswith("connect-link"):
        found.append("member:connect-link*")
    if base.startswith("id_"):
        found.append("member:id_*")
    if base.startswith("buyer_key"):
        found.append("member:buyer_key*")
    if base.startswith("origin_secret"):
        found.append("member:origin_secret*")
    directories = parts if name.endswith("/") else parts[:-1]
    if base in _DIR_RULES and (name.endswith("/") or "." not in base):
        directories = [*directories, base]
    for part in directories:
        rule = _DIR_RULES.get(part)
        if rule and rule not in found:
            found.append(rule)
    return found


def _content_rules(payload: bytes) -> list[str]:
    return [rule for rule, pattern in _CONTENT if pattern.search(payload)]


def _metadata_name(payload: bytes) -> str:
    for line in payload.decode("latin-1").splitlines():
        if line.startswith("Name:"):
            return line.split(":", 1)[1].strip()
    raise AuditError("wheel METADATA has no Name")


def _top_modules(names: list[str]) -> set[str]:
    modules: set[str] = set()
    for name in names:
        top = name.split("/")[0]
        if top.endswith(".dist-info") or top.endswith(".data"):
            continue
        if top.endswith(".py"):
            top = top[:-3]
        modules.add(top)
    return modules


def _wheel_module_rules(archive: zipfile.ZipFile) -> list[str]:
    names = archive.namelist()
    meta = next((name for name in names if name.endswith(".dist-info/METADATA")), "")
    if not meta:
        return ["wheel:no-metadata"]
    dist = _norm_name(_metadata_name(archive.read(meta)))
    expected = _MODULES.get(dist)
    if expected is None:
        return [f"wheel:unknown-distribution:{dist}"]
    modules = _top_modules(names)
    found: list[str] = []
    if expected not in modules:
        found.append("wheel:missing-module")
    for module in sorted(modules - {expected}):
        found.append(f"wheel:stray-module:{module}")
    return found


def _scan_zip(path: Path) -> list[str]:
    findings: list[str] = []
    with zipfile.ZipFile(path) as archive:
        for rule in _wheel_module_rules(archive):
            findings.append(f"{path.name}: {rule}")
        for info in archive.infolist():
            for rule in member_rules(info.filename):
                findings.append(f"{path.name}: {info.filename}: {rule}")
            if info.is_dir():
                continue
            for rule in _content_rules(archive.read(info)):
                findings.append(f"{path.name}: {info.filename}: {rule}")
    return findings


def _scan_tar(path: Path) -> list[str]:
    findings: list[str] = []
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            # pax extended/global headers and GNU long-name headers are archive metadata.
            if member.type in {"x", "g", "L", "K"}:
                continue
            for rule in member_rules(member.name + ("/" if member.isdir() else "")):
                findings.append(f"{path.name}: {member.name}: {rule}")
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            payload = b"" if extracted is None else extracted.read()
            for rule in _content_rules(payload):
                findings.append(f"{path.name}: {member.name}: {rule}")
    return findings


def audit(directory: Path) -> list[str]:
    """Return findings for every wheel and sdist in ``directory``."""
    if not directory.is_dir():
        raise AuditError(f"not a directory: {directory}")
    artifacts = sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and (path.name.endswith(".whl") or path.name.endswith(".tar.gz"))
    )
    if not artifacts:
        raise AuditError(f"no wheel or sdist in {directory}")
    findings: list[str] = []
    for path in artifacts:
        if path.name.endswith(".whl"):
            findings.extend(_scan_zip(path))
        else:
            findings.extend(_scan_tar(path))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit built wheels and sdists for secrets and stray files.")
    parser.add_argument("directory", type=Path, help="Directory of wheels and sdists")
    args = parser.parse_args(argv)
    try:
        findings = audit(args.directory)
    except (AuditError, OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
        sys.stderr.write(f"{exc.__class__.__name__}: {exc}\n")
        return 1
    if findings:
        sys.stdout.write("\n".join(findings) + "\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
