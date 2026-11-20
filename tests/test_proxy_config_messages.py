"""Startup error text for proxy routes.

T-CE.2 and T-CE.3 pin messages that must stay as they are.
"""

from __future__ import annotations

import textwrap

import pytest

from satsgate_proxy.config import ConfigError
from test_satsgate_proxy import _load

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
