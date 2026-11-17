"""Atomic local files for `satsgate init`. Never follow a symlink."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path

ACCOUNT_KEY = "SATSGATE_ACCOUNT_KEY"
API_KEY = "SATSGATE_API_KEY"
ORIGIN_SECRET = "SATSGATE_ORIGIN_SECRET"
ENV_KEYS = (API_KEY, ORIGIN_SECRET)
_ASSIGN = re.compile(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$")


class FileRefusal(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def permissions_restricted() -> bool:
    """POSIX can lock a file to the owner. Windows cannot, and says so."""
    return os.name != "nt"


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.lstat().st_mode)


def refuse_symlink(path: Path) -> None:
    if path.is_symlink():
        raise FileRefusal("symlink_refused", f"{path.name} is a symlink")


def ensure_dir(path: Path, mode: int = 0o700) -> bool:
    refuse_symlink(path)
    path.mkdir(parents=True, exist_ok=True)
    if not permissions_restricted():
        return False
    os.chmod(path, mode)
    return mode_of(path) == mode


def atomic_write(path: Path, text: str, *, mode: int = 0o600) -> bool:
    """Replace `path` by rename. A symlink is refused and its target is not opened."""
    refuse_symlink(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    tmp = Path(name)
    closed = False
    try:
        os.write(fd, text.encode("utf-8"))
        if permissions_restricted():
            os.fchmod(fd, mode)
        os.close(fd)
        closed = True
        os.replace(tmp, path)
        tmp = None
    finally:
        if not closed:
            os.close(fd)
        if tmp is not None:
            tmp.unlink(missing_ok=True)
    if not permissions_restricted():
        return False
    os.chmod(path, mode)
    return mode_of(path) == mode


def read_text(path: Path) -> str:
    refuse_symlink(path)
    return path.read_text(encoding="utf-8")


def unquote(value: str) -> str:
    text = value.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1]
    return text


def parse_env(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ASSIGN.match(stripped)
        if match is not None:
            found[match.group(1)] = unquote(match.group(2))
    return found


def merge_env(text: str, updates: dict[str, str], *, replace: set[str]) -> tuple[str, dict[str, str]]:
    """Append missing keys. A different value is a conflict unless `replace` names it.

    On conflict the original text is returned unchanged.
    """
    lines = text.splitlines(keepends=True)
    seen: set[str] = set()
    conflicts: dict[str, str] = {}
    rewritten: list[str] = []
    for line in lines:
        match = _ASSIGN.match(line.strip())
        key = match.group(1) if match is not None else None
        if key in updates and key not in seen:
            seen.add(key)
            current = unquote(match.group(2)) if match is not None else ""
            if current == updates[key]:
                rewritten.append(line if line.endswith("\n") else line + "\n")
            elif key in replace:
                prefix = "export " if line.strip().startswith("export ") else ""
                rewritten.append(f"{prefix}{key}={updates[key]}\n")
            else:
                conflicts[key] = current
                rewritten.append(line if line.endswith("\n") else line + "\n")
        else:
            rewritten.append(line if line.endswith("\n") else line + "\n")
    if conflicts:
        return text, conflicts
    body = "".join(rewritten)
    missing = [key for key in updates if key not in seen]
    if missing:
        if body and not body.endswith("\n"):
            body += "\n"
        for key in updates:
            if key in missing:
                body += f"{key}={updates[key]}\n"
    return body, {}


def inside_work_tree(cwd: Path) -> bool:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(cwd),
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def env_is_ignored(cwd: Path) -> bool:
    try:
        proc = subprocess.run(
            ["git", "check-ignore", "-q", "--", ".env"],
            cwd=str(cwd),
            check=False,
            capture_output=True,
        )
    except OSError:
        return False
    return proc.returncode == 0
