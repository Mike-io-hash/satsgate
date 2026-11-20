"""Startup error text for proxy routes.

T-CE.1 through T-CE.4. MCP routes name the route. Classic and shared text stays.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from satsgate_proxy.config import ConfigError
from test_satsgate_proxy import KEY, SECRET, _load

ROOT = Path(__file__).resolve().parents[1]

_HEAD = textwrap.dedent(
    """\
    core:
      base_url: http://core.test
      api_key_env: SATSGATE_API_KEY
    upstream:
      base_url: http://upstream.test
    origin:
      secret_env: SATSGATE_ORIGIN_SECRET
    """
)


def _expect(tmp_path, monkeypatch, text: str, message: str) -> None:
    with pytest.raises(ConfigError) as caught:
        _load(tmp_path, monkeypatch, _HEAD + textwrap.dedent(text))
    assert str(caught.value) == message


@pytest.mark.parametrize(
    ("text", "message"),
    (
        pytest.param(
            """\
            routes:
              - name: report
                methods: [GET]
                path: /report
                price_sats: 21
                access: sometimes
                scope: route
            """,
            "access must be per_request, uses:N, or pass:<seconds>",
            id="ce2-access-sometimes",
        ),
        pytest.param(
            """\
            routes:
              - name: report
                methods: [GET]
                path: /report
                price_sats: 21
                access: 5
                scope: route
            """,
            "access must be a string",
            id="ce2-access-number",
        ),
        pytest.param(
            """\
            routes:
              - name: report
                methods: [GET]
                path: /report
                price_sats: 21
                access: uses:0
                scope: route
            """,
            "uses must be from 1 to 100000",
            id="ce2-uses-zero",
        ),
        pytest.param(
            """\
            routes:
              - name: report
                methods: [GET]
                path: /report
                price_sats: 21
                access: pass:0
                scope: route
            """,
            "pass seconds must be from 1 to 604800",
            id="ce2-pass-zero",
        ),
        pytest.param(
            """\
            routes:
              - name: report
                methods: [GET]
                path: /report
                price_sats: 21
                access: per_request
                scope: route
                description: 5
            """,
            "description must be a string",
            id="ce2-description-number",
        ),
        pytest.param(
            """\
            routes:
              - name: report
                methods: [GET]
                path: r
                price_sats: 21
                access: per_request
                scope: route
            """,
            "path must start with /: 'r'",
            id="ce2-path-slash",
        ),
        pytest.param(
            """\
            routes:
              - name: report
                methods: [GET]
                path: /r/
                price_sats: 21
                access: per_request
                scope: route
            """,
            "empty path segment: /r/",
            id="ce2-empty-segment",
        ),
        pytest.param(
            """\
            routes:
              - name: report
                methods: [GET]
                path: /r?
                price_sats: 21
                access: per_request
                scope: route
            """,
            "only a whole-segment * and a trailing ** are supported: /r?",
            id="ce2-path-mark",
        ),
    ),
)
def test_ce_2_classic_startup_messages_are_unchanged(tmp_path, monkeypatch, text: str, message: str) -> None:
    _expect(tmp_path, monkeypatch, text, message)


@pytest.mark.parametrize(
    ("text", "message"),
    (
        pytest.param(
            """\
            routes:
              - name: tools
                pathh: /mcp
                path: /mcp
                methods: [POST]
                mcp:
                  default: free
            """,
            "unknown route key: pathh",
            id="ce3-unknown-key",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                x402: true
                mcp:
                  default: free
            """,
            "server.public_base is required when a route sets x402: true",
            id="ce3-public-base",
        ),
    ),
)
def test_ce_3_shared_messages_stay_as_they_are(tmp_path, monkeypatch, text: str, message: str) -> None:
    _expect(tmp_path, monkeypatch, text, message)


_ACCESS = "access must be per_request, uses:N, or pass:<seconds>"
_TOOL_QUOTE = "route tools tool quote"
_DEFAULT = "route tools mcp default"


@pytest.mark.parametrize(
    ("text", "message"),
    (
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                mcp:
                  default: free
                  tools:
                    quote:
                      price_sats: 21
                      access: sometimes
            """,
            f"{_TOOL_QUOTE}: {_ACCESS}",
            id="ce1-1-tool-access-sometimes",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                mcp:
                  default: free
                  tools:
                    quote:
                      price_sats: 21
                      access: uses:x
            """,
            f"{_TOOL_QUOTE}: {_ACCESS}",
            id="ce1-2-tool-access-uses-text",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                mcp:
                  default: free
                  tools:
                    quote:
                      price_sats: 21
                      access: 5
            """,
            f"{_TOOL_QUOTE}: access must be a string",
            id="ce1-3-tool-access-number",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                mcp:
                  default: free
                  tools:
                    quote:
                      price_sats: 21
                      access: uses:0
            """,
            f"{_TOOL_QUOTE}: uses must be from 1 to 100000",
            id="ce1-4-tool-uses-zero",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                mcp:
                  default: free
                  tools:
                    quote:
                      price_sats: 21
                      access: pass:0
            """,
            f"{_TOOL_QUOTE}: pass seconds must be from 1 to 604800",
            id="ce1-5-tool-pass-zero",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                mcp:
                  default: free
                  tools:
                    quote:
                      price_sats: 21
                      access: per_request
                      description: 5
            """,
            f"{_TOOL_QUOTE}: description must be a string",
            id="ce1-6-tool-description-number",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                mcp:
                  default:
                    price_sats: 21
                    access: sometimes
            """,
            f"{_DEFAULT}: {_ACCESS}",
            id="ce1-7-default-access-sometimes",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                mcp:
                  default:
                    price_sats: 21
                    access: [x]
            """,
            f"{_DEFAULT}: access must be a string",
            id="ce1-8-default-access-list",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                mcp:
                  default:
                    price_sats: 21
                    access: uses:0
            """,
            f"{_DEFAULT}: uses must be from 1 to 100000",
            id="ce1-9-default-uses-zero",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                mcp:
                  default:
                    price_sats: 21
                    access: pass:0
            """,
            f"{_DEFAULT}: pass seconds must be from 1 to 604800",
            id="ce1-10-default-pass-zero",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                mcp:
                  default:
                    price_sats: 21
                    access: per_request
                    description: 5
            """,
            f"{_DEFAULT}: description must be a string",
            id="ce1-11-default-description-number",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                description: 5
                mcp:
                  default: free
            """,
            "route tools: description must be a string",
            id="ce1-12-route-description-number",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: mcp
                methods: [POST]
                mcp:
                  default: free
            """,
            "route tools: path must start with /: 'mcp'",
            id="ce1-13-path-slash",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp/
                methods: [POST]
                mcp:
                  default: free
            """,
            "route tools: empty path segment: /mcp/",
            id="ce1-14-empty-segment",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp?
                methods: [POST]
                mcp:
                  default: free
            """,
            "route tools: only a whole-segment * and a trailing ** are supported: /mcp?",
            id="ce1-15-path-mark",
        ),
        pytest.param(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                mcp:
                  default: free
                  tools:
                    quote:
                      price_sats: 21
            """,
            "route tools tool quote access is required",
            id="ce1-tool-access-required",
        ),
    ),
)
def test_ce_1_mcp_startup_messages_name_the_route(tmp_path, monkeypatch, text: str, message: str) -> None:
    _expect(tmp_path, monkeypatch, text, message)


def test_ce_4_exit_code(tmp_path: Path) -> None:
    config = tmp_path / "proxy.yaml"
    config.write_text(
        _HEAD
        + textwrap.dedent(
            """\
            routes:
              - name: tools
                path: /mcp
                methods: [POST]
                mcp:
                  default: free
                  tools:
                    quote:
                      price_sats: 21
                      access: sometimes
            """
        ),
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT / "proxy" / "src") + os.pathsep + env.get("PYTHONPATH", "")
    env["SATSGATE_API_KEY"] = KEY
    env["SATSGATE_ORIGIN_SECRET"] = SECRET
    result = subprocess.run(
        [sys.executable, "-m", "satsgate_proxy", "--config", str(config)],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        check=False,
    )
    assert result.returncode == 2
    assert result.stderr.splitlines() == [
        "satsgate-proxy: route tools tool quote: access must be per_request, uses:N, or pass:<seconds>"
    ]
