"""`satsgate init`. The console script parses arguments and calls `run_init`."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TextIO


@dataclass
class InitOptions:
    """Flags for one `satsgate init` run. `want_usdc` None means the human is asked."""

    api_url: str | None = None
    lightning_address: str | None = None
    want_usdc: bool | None = None
    json_mode: bool = False
    docker: bool = False
    framework: str | None = None
    path: str = "/paid/**"
    upstream: str = "http://127.0.0.1:3000"
    public_url: str = "http://127.0.0.1:8080"
    yaml_out: str | None = None
    new_account: bool = False
    replace_lightning_address: bool = False
    cwd: Path | None = None


def run_init(
    options: InitOptions,
    *,
    transport: Any = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    """Run init. `transport` is injected into every HTTP client this function creates."""
    del options, transport
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr
    del stdin
    err.write("satsgate init is not implemented\n")
    out.write("")
    return 2
