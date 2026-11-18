"""Check an installed distribution: version, console scripts, and the init probe."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

_MODULE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class SmokeError(Exception):
    """The installed distribution did not pass the smoke check."""


def _run(argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, env=env, check=False, capture_output=True, text=True)


def check_version(python: str, module: str, version: str) -> None:
    if _MODULE_RE.fullmatch(module) is None:
        raise SmokeError(f"refusing module name {module}")
    proc = _run([python, "-c", f"import {module}; print({module}.__version__)"])
    if proc.returncode != 0:
        raise SmokeError(proc.stderr.strip() or "import failed")
    got = proc.stdout.strip()
    if got != version:
        raise SmokeError(f"version {got} != {version}")


def check_commands(python: str, commands: list[str]) -> None:
    env = os.environ.copy()
    # A venv python is a symlink. resolve() would point at the base interpreter
    # and miss the console scripts installed next to the symlink.
    bindir = Path(python).absolute().parent
    env["PATH"] = str(bindir) + os.pathsep + env.get("PATH", "")
    for command in commands:
        argv = command.split()
        if not argv:
            continue
        script = bindir / argv[0]
        if not script.is_file():
            raise SmokeError(f"missing console script {argv[0]}")
        proc = _run([str(script), *argv[1:]], env=env)
        if proc.returncode != 0:
            raise SmokeError(f"{command} exited {proc.returncode}")


def check_pip(python: str) -> None:
    proc = _run([python, "-m", "pip", "check"])
    if proc.returncode != 0:
        detail = (proc.stdout or proc.stderr).strip()
        raise SmokeError(detail or "pip check failed")


def init_probe(python: str, work: Path) -> None:
    """``satsgate init`` against a closed port must fail before it writes a key."""
    env = os.environ.copy()
    env.pop("SATSGATE_API_URL", None)
    proc = _run(
        [
            python,
            "-m",
            "satsgate",
            "init",
            "--json",
            "--api-url",
            "http://127.0.0.1:9",
            "--lightning-address",
            "test@example.com",
        ],
        cwd=work,
        env=env,
    )
    if proc.returncode != 1:
        raise SmokeError(f"init exited {proc.returncode}, expected 1")
    try:
        body = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SmokeError("init did not print JSON") from exc
    error = body.get("error") or {}
    if body.get("ok") is not False or error.get("code") != "network":
        raise SmokeError("init was not a network error")
    if (work / ".satsgate" / "account.env").exists():
        raise SmokeError("init wrote a key file")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Smoke-check an installed satsgate distribution.")
    parser.add_argument("--python", required=True)
    parser.add_argument("--module", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commands", default="")
    parser.add_argument("--init-probe", action="store_true")
    parser.add_argument("--work", type=Path, default=None)
    args = parser.parse_args(argv)
    commands = [item for item in args.commands.split("|") if item]
    try:
        check_version(args.python, args.module, args.version)
        check_pip(args.python)
        check_commands(args.python, commands)
        if args.init_probe:
            work = args.work or Path.cwd()
            init_probe(args.python, work)
    except SmokeError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
