"""CLI version entry on the import path. The 3.10 job runs this module."""

from __future__ import annotations

import argparse
import io
import sys

from satsgate.__main__ import build_parser, run, version_line


def test_init_version_line_names_the_three_packages() -> None:
    text = version_line()
    assert text.startswith("satsgate 0.1.0\n")
    assert "satsgate-sdk 0.10.0\n" in text
    assert text.endswith("satsgate-proxy 0.14.1\n")
    stdout = io.StringIO()
    previous = sys.stdout
    sys.stdout = stdout
    try:
        assert run(["--version"]) == 0
    finally:
        sys.stdout = previous
    assert stdout.getvalue() == text
    parser = build_parser()
    sub = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
    assert list(sub.choices) == ["init"]
    assert "init" in parser.format_help()
