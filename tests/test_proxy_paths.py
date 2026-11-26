"""Request path checks for the proxy.

T-PT.1 through T-PT.10. Every request is a raw HTTP/1.1 line on 127.0.0.1 so a
dot segment reaches the server unchanged.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import socket
import sqlite3
import textwrap
import time
from pathlib import Path

import pytest

from proxy_mcp_harness import LocalServer
from satsgate_proxy import __version__
from satsgate_proxy.app import build_app
from satsgate_proxy.config import load_settings
from test_satsgate_proxy import KEY, SECRET, World

MCP_BODY = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"quote"}}'
MCP_HEADERS = (
    ("Accept", "application/json, text/event-stream"),
    ("Content-Type", "application/json"),
)
_LIMIT = 1024

_BASE_YAML = textwrap.dedent(
    f"""\
    core:
      base_url: http://core.test
      api_key_env: SATSGATE_API_KEY
    upstream:
      base_url: http://upstream.test
    origin:
      secret_env: SATSGATE_ORIGIN_SECRET
    limits:
      max_request_bytes: {_LIMIT}
    free_paths:
      - /static/**
    routes:
      - name: report
        path: /api/report
        methods: [GET, POST]
        price_sats: 21
        access: per_request
        scope: route
      - name: files
        path: /files/**
        methods: [GET]
        price_sats: 21
        access: per_request
        scope: route
      - name: tools
        path: /mcp
        methods: [POST]
        mcp:
          signal: http_402
          default: free
          tools:
            quote:
              price_sats: 21
              access: per_request
    """
)

# {x} is replaced with api/report or mcp. A template without {x} is one path.
_LITERAL = (
    ("1", "/static/../{x}"),
    ("2", "/static/./../{x}"),
    ("3", "/static/x/../../{x}"),
    ("4", "/static/.././{x}"),
    ("5", "/static//../{x}"),
    ("6a", "/static/.."),
    ("6b", "/static/../"),
    ("7a", "/static/."),
    ("7b", "/static/./x"),
    ("8", "/static/x%23/../../{x}"),
    ("9", "/static/../../{x}"),
)
_ENCODED = (
    ("1a", "/static/%2e%2e/{x}"),
    ("1b", "/static/%2E%2E/{x}"),
    ("1c", "/static/%2e%2E/{x}"),
    ("2a", "/static/.%2e/{x}"),
    ("2b", "/static/%2e./{x}"),
    ("2c", "/static/.%2E/{x}"),
    ("3", "/static/%2e/{x}"),
    ("4", "/static/%252e%252e/{x}"),
    ("5", "/static/%25252e%25252e/{x}"),
    ("6", "/static/%2525252e%2525252e/{x}"),
)
_SEPARATORS = (
    ("1a", "/static/..%2f{x}"),
    ("1b", "/static/..%2F{x}"),
    ("2", "/static%2f..%2f{x}"),
    ("3", "/static/..\\{x}"),
    ("4a", "/static/..%5c{x}"),
    ("4b", "/static/..%5C{x}"),
    ("5", "/static/..%255c{x}"),
    ("6a", "/static/a%2Fb"),
    ("6b", "/static/a%2fb"),
    ("7", "/static/a%5Cb"),
    ("8", "/static/a\\b"),
)
_PARAMETERS = (
    ("1", "/static/..;/{x}"),
    ("2", "/static/..;x=1/{x}"),
    ("3", "/static/.;/{x}"),
    ("4", "/static/%2e%2e;/{x}"),
)
_ACCEPTED = (
    "/static/.well-known/x",
    "/static/a.b",
    "/static/...",
    "/static/a..b",
    "/static/.hidden",
    "/static/..a",
    "/static/%2e%2e%2e",
    "/static/x%20y",
    "/static/100%25",
    "/static/x?q=/../y",
    "/static/x//y",
    "/static/x;v=1",
    "/static/%7Bid%7D",
    "/static/caf%C3%A9",
)


class Reply:
    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body


class Proxy:
    def __init__(self, port: int, world: World, unknown: Reply) -> None:
        self.port = port
        self.world = world
        self.unknown = unknown


def _fill(template: str, value: str) -> str:
    return template.replace("{x}", value)


def _request_params(group: str, rows: tuple[tuple[str, str], ...]):
    params = []
    for case_id, template in rows:
        if "{x}" in template:
            choices = (
                ("get-report", "GET", _fill(template, "api/report"), False),
                ("post-report", "POST", _fill(template, "api/report"), False),
                ("post-mcp", "POST", _fill(template, "mcp"), True),
            )
        else:
            choices = (
                ("get", "GET", template, False),
                ("post", "POST", template, False),
                ("post-mcp", "POST", template, True),
            )
        for suffix, method, target, mcp in choices:
            params.append(pytest.param(method, target, mcp, id=f"pt{group}-{case_id}-{suffix}"))
    return params


def _targets(rows: tuple[tuple[str, str], ...]) -> list[str]:
    found: list[str] = []
    for _case_id, template in rows:
        if "{x}" in template:
            found.append(_fill(template, "api/report"))
            found.append(_fill(template, "mcp"))
        else:
            found.append(template)
    return found


def _rejected_paths() -> list[str]:
    paths = []
    for rows in (_LITERAL, _ENCODED, _SEPARATORS, _PARAMETERS):
        paths.extend(_targets(rows))
    paths.extend(
        (
            "/static/../api/report",
            "/files/../static/x",
            "/files/%2e%2e/static/x",
            "/static/../mcp",
            "/static/../healthz",
            "/static/../report",
            "/static/%2e%2e/report",
        )
    )
    unique: list[str] = []
    seen: set[str] = set()
    for path in paths:
        if path not in seen:
            seen.add(path)
            unique.append(path)
    return unique


def _env_guard():
    previous = {name: os.environ.get(name) for name in ("SATSGATE_API_KEY", "SATSGATE_ORIGIN_SECRET")}
    os.environ["SATSGATE_API_KEY"] = KEY
    os.environ["SATSGATE_ORIGIN_SECRET"] = SECRET
    return previous


def _env_restore(previous: dict[str, str | None]) -> None:
    for name, value in previous.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _read_reply(sock: socket.socket, *, read_body: bool) -> Reply:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data.extend(chunk)
    if b"\r\n\r\n" not in data:
        raise AssertionError(f"short response {bytes(data[:120])!r}")
    head, _, rest = bytes(data).partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split(" ", 2)[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    if not read_body:
        return Reply(status, headers, b"")
    body = bytearray(rest)
    if "content-length" in headers:
        need = int(headers["content-length"])
        while len(body) < need:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body.extend(chunk)
        body = body[:need]
    else:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            body.extend(chunk)
    return Reply(status, headers, bytes(body))


def send_raw(
    port: int,
    method: str,
    target: str,
    *,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
    read_body: bool = True,
) -> Reply:
    fields = [
        f"{method} {target} HTTP/1.1".encode("ascii"),
        f"Host: 127.0.0.1:{port}".encode("ascii"),
        b"Connection: close",
        f"Content-Length: {len(body)}".encode("ascii"),
    ]
    for name, value in headers:
        fields.append(f"{name}: {value}".encode("ascii"))
    payload = b"\r\n".join(fields) + b"\r\n\r\n" + body
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(payload)
        return _read_reply(sock, read_body=read_body)


def exchange(
    proxy: Proxy,
    method: str,
    target: str,
    *,
    headers: tuple[tuple[str, str], ...] = (),
    body: bytes = b"",
    quiet: bool = True,
) -> Reply:
    proxy.world.core_calls.clear()
    proxy.world.up_calls.clear()
    logger = logging.getLogger("satsgate_proxy")
    caught: list[logging.LogRecord] = []

    class _Catch(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            caught.append(record)

    handler = _Catch()
    previous = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        reply = send_raw(
            proxy.port,
            method,
            target,
            headers=headers,
            body=body,
            read_body=method != "HEAD",
        )
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous)
    if quiet:
        assert [record.getMessage() for record in caught] == []
    return reply


def _mcp_parts(mcp: bool, extra: tuple[tuple[str, str], ...] = ()) -> tuple[tuple[tuple[str, str], ...], bytes]:
    headers = extra + (MCP_HEADERS if mcp else ())
    return headers, MCP_BODY if mcp else b""


def assert_not_found(proxy: Proxy, reply: Reply, *, body: bool = True) -> None:
    assert reply.status == proxy.unknown.status == 404
    assert reply.headers.get("cache-control") == proxy.unknown.headers.get("cache-control") == "no-store"
    assert reply.headers.get("content-type") == proxy.unknown.headers.get("content-type")
    assert reply.headers["content-type"].startswith("application/json")
    assert "www-authenticate" not in reply.headers
    assert "allow" not in reply.headers
    if body:
        assert reply.body == proxy.unknown.body
        assert json.loads(reply.body) == {"ok": False, "error": "not_found"}
    assert proxy.world.core_calls == []
    assert proxy.world.up_calls == []


def _start(yaml_text: str, directory: Path) -> tuple[LocalServer, World, Path]:
    config = directory / "proxy.yaml"
    config.write_text(yaml_text, encoding="utf-8")
    world = World()
    app = build_app(load_settings(config), transport=world)
    server = LocalServer(app)
    server.start()
    return server, world, config


@pytest.fixture(scope="module")
def proxy(tmp_path_factory: pytest.TempPathFactory):
    previous = _env_guard()
    server, world, _config = _start(_BASE_YAML, tmp_path_factory.mktemp("paths"))
    try:
        unknown = send_raw(server.port, "GET", "/no-such-path")
        yield Proxy(server.port, world, unknown)
    finally:
        server.stop()
        _env_restore(previous)


def _receipt_yaml(store: Path) -> str:
    return textwrap.dedent(
        f"""\
        mode: receipt
        core:
          base_url: http://core.test
        upstream:
          base_url: http://upstream.test
        origin:
          secret_env: SATSGATE_ORIGIN_SECRET
        receipt:
          site: my-shop
          store: {store}
        limits:
          max_request_bytes: {_LIMIT}
        free_paths:
          - /static/**
        routes:
          - name: report
            methods: [GET]
            path: /report
            price_sats: 21
            access: per_request
            scope: route
        """
    )


@pytest.fixture(scope="module")
def receipt_proxy(tmp_path_factory: pytest.TempPathFactory):
    previous = _env_guard()
    directory = tmp_path_factory.mktemp("receipt-paths")
    store = directory / "uses.sqlite3"
    server, world, _config = _start(_receipt_yaml(store), directory)
    try:
        unknown = send_raw(server.port, "GET", "/no-such-path")
        yield Proxy(server.port, world, unknown), store
    finally:
        server.stop()
        _env_restore(previous)


def _sign_receipt(secret: str, *, path: str, jti: str) -> str:
    now = int(time.time())
    claims = {
        "amt": {"sats": 21},
        "aud": "my-shop",
        "exp": now + 3600,
        "iat": now - 5,
        "iss": "https://gate.satsgate.org",
        "jti": jti,
        "ph": "ab" * 32,
        "rail": "lightning",
        "res": f"gate:my-shop:{path}",
        "sub": path,
        "uses": 1,
    }
    header = {
        "alg": "HS256",
        "kid": hashlib.sha256(secret.encode()).hexdigest()[:16],
        "typ": "satsgate-receipt+jwt",
    }

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    head = b64(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    body = b64(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    digest = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
    return f"{head}.{body}.{b64(digest)}"


def _store_counts(path: Path) -> tuple[int, int]:
    with sqlite3.connect(path) as conn:
        uses = int(conn.execute("SELECT COUNT(*) FROM receipt_uses").fetchone()[0])
        held = int(conn.execute("SELECT COUNT(*) FROM receipt_reservations").fetchone()[0])
    return uses, held


def _reject(proxy: Proxy, method: str, target: str, mcp: bool, extra: tuple[tuple[str, str], ...] = ()) -> None:
    headers, body = _mcp_parts(mcp, extra)
    reply = exchange(proxy, method, target, headers=headers, body=body)
    assert_not_found(proxy, reply, body=method != "HEAD")


@pytest.mark.parametrize(("method", "target", "mcp"), _request_params("1", _LITERAL))
def test_pt_1_literal_dot_segments(proxy: Proxy, method: str, target: str, mcp: bool) -> None:
    _reject(proxy, method, target, mcp)


@pytest.mark.parametrize(("method", "target", "mcp"), _request_params("2", _ENCODED))
def test_pt_2_percent_encoded_dots(proxy: Proxy, method: str, target: str, mcp: bool) -> None:
    _reject(proxy, method, target, mcp)


@pytest.mark.parametrize(("method", "target", "mcp"), _request_params("3", _SEPARATORS))
def test_pt_3_separators(proxy: Proxy, method: str, target: str, mcp: bool) -> None:
    _reject(proxy, method, target, mcp)


@pytest.mark.parametrize(("method", "target", "mcp"), _request_params("4", _PARAMETERS))
def test_pt_4_path_parameters(proxy: Proxy, method: str, target: str, mcp: bool) -> None:
    _reject(proxy, method, target, mcp)


@pytest.mark.parametrize(
    ("method", "target", "mcp", "extra"),
    (
        pytest.param("HEAD", "/static/../api/report", False, (), id="pt5-1-head"),
        pytest.param("PUT", "/static/../api/report", False, (), id="pt5-1-put"),
        pytest.param("PATCH", "/static/../api/report", False, (), id="pt5-1-patch"),
        pytest.param("DELETE", "/static/../api/report", False, (), id="pt5-1-delete"),
        pytest.param("OPTIONS", "/static/../api/report", False, (), id="pt5-1-options"),
        pytest.param("GET", "/files/../static/x", False, (), id="pt5-2-literal"),
        pytest.param("GET", "/files/%2e%2e/static/x", False, (), id="pt5-2-encoded"),
        pytest.param("GET", "/static/../mcp", False, (), id="pt5-3-wrong-method"),
        pytest.param(
            "POST",
            "/static/../mcp",
            True,
            (("Authorization", "L402 bWFjYXJvb24:" + "ab" * 32),),
            id="pt5-4-l402",
        ),
        pytest.param(
            "POST",
            "/static/../mcp",
            True,
            (("PAYMENT-SIGNATURE", "dGVzdC1zaWduYXR1cmU"),),
            id="pt5-4-payment-signature",
        ),
    ),
)
def test_pt_5_methods_and_route_kinds(
    proxy: Proxy,
    method: str,
    target: str,
    mcp: bool,
    extra: tuple[tuple[str, str], ...],
) -> None:
    _reject(proxy, method, target, mcp, extra)
    assert all(not call["path"].endswith("/challenge") for call in proxy.world.core_calls)


@pytest.mark.parametrize(
    "case",
    (
        pytest.param("oversized", id="pt6-1-oversized"),
        pytest.param("healthz-get", id="pt6-2-healthz-get"),
        pytest.param("healthz-head", id="pt6-2-healthz-head"),
        pytest.param("healthz-dot", id="pt6-2-healthz-dot"),
    ),
)
def test_pt_6_precedence(proxy: Proxy, case: str) -> None:
    if case == "oversized":
        payload = b"x" * (_LIMIT + 1)
        baseline = exchange(proxy, "POST", "/no-such-path", body=payload, quiet=False)
        reply = exchange(proxy, "POST", "/static/../mcp", headers=MCP_HEADERS, body=payload)
        assert reply.status == baseline.status == 413
        assert reply.body == baseline.body
        assert json.loads(reply.body) == {"ok": False, "error": "request_too_large"}
        assert reply.headers.get("cache-control") == baseline.headers.get("cache-control") == "no-store"
        assert proxy.world.core_calls == []
        assert proxy.world.up_calls == []
        return
    if case == "healthz-get":
        reply = exchange(proxy, "GET", "/healthz", quiet=False)
        assert reply.status == 200
        assert json.loads(reply.body) == {"ok": True, "component": "satsgate-proxy", "version": __version__}
        assert proxy.world.core_calls == []
        assert proxy.world.up_calls == []
        return
    if case == "healthz-head":
        reply = exchange(proxy, "HEAD", "/healthz", quiet=False)
        assert reply.status == 200
        assert reply.headers.get("content-type", "").startswith("application/json")
        assert proxy.world.core_calls == []
        assert proxy.world.up_calls == []
        return
    _reject(proxy, "GET", "/static/../healthz", False)


@pytest.mark.parametrize(
    "case",
    (
        pytest.param("literal", id="pt7-literal"),
        pytest.param("encoded", id="pt7-encoded"),
        pytest.param("receipt", id="pt7-receipt"),
        pytest.param("normal", id="pt7-normal"),
    ),
)
def test_pt_7_receipt_mode(receipt_proxy: tuple[Proxy, Path], case: str) -> None:
    proxy, store = receipt_proxy
    before = _store_counts(store)
    if case == "normal":
        token = _sign_receipt(SECRET, path="/report", jti="rcp_report0000000000000")
        paid = exchange(proxy, "GET", "/report", headers=(("Satsgate-Receipt", token),), quiet=False)
        assert paid.status == 200
        assert paid.body == b"origin-ok"
        assert proxy.world.core_calls == []
        assert len(proxy.world.up_calls) == 1
        assert proxy.world.up_calls[0]["raw_path"] == "/report"
        uses, held = _store_counts(store)
        assert uses == before[0] + 1
        assert held == before[1]
        used = exchange(proxy, "GET", "/report", headers=(("Satsgate-Receipt", token),), quiet=False)
        assert used.status == 401
        assert json.loads(used.body)["error"] == "receipt_used_up"
        assert proxy.world.up_calls == []
        return
    if case == "literal":
        target, token = "/static/../report", None
    elif case == "encoded":
        target, token = "/static/%2e%2e/report", None
    else:
        target = "/static/../report"
        token = _sign_receipt(SECRET, path="/static/../report", jti="rcp_dotpath000000000000")
    headers = (("Satsgate-Receipt", token),) if token else ()
    reply = exchange(proxy, "GET", target, headers=headers)
    assert_not_found(proxy, reply)
    assert _store_counts(store) == before


@pytest.mark.parametrize(
    "case",
    tuple(pytest.param(("free", path), id=f"pt8-{index}") for index, path in enumerate(_ACCEPTED, start=1))
    + (
        pytest.param(("classic", "/api/report"), id="pt8-classic-challenge"),
        pytest.param(("mcp", "/mcp"), id="pt8-mcp-challenge"),
    ),
)
def test_pt_8_accepted_paths_forwarded_byte_identical(proxy: Proxy, case: tuple[str, str]) -> None:
    kind, target = case
    if kind == "classic":
        reply = exchange(proxy, "GET", target, quiet=False)
        assert reply.status == 402
        assert len(proxy.world.core_calls) == 1
        assert proxy.world.core_calls[0]["path"].endswith("/challenge")
        assert proxy.world.up_calls == []
        return
    if kind == "mcp":
        headers, body = _mcp_parts(True)
        reply = exchange(proxy, "POST", target, headers=headers, body=body, quiet=False)
        assert reply.status == 402
        assert len(proxy.world.core_calls) == 1
        assert proxy.world.core_calls[0]["path"].endswith("/challenge")
        assert proxy.world.up_calls == []
        return
    reply = exchange(proxy, "GET", target, quiet=False)
    assert reply.status == 200
    assert reply.body == b"origin-ok"
    assert proxy.world.core_calls == []
    assert len(proxy.world.up_calls) == 1
    assert proxy.world.up_calls[0]["raw_path"] == target


def _predicate_rows():
    rows = []
    for index, path in enumerate(_rejected_paths(), start=1):
        rows.append(pytest.param(path.encode("ascii"), True, id=f"pt9-reject-{index}"))
    for index, path in enumerate(_ACCEPTED, start=1):
        rows.append(pytest.param(path.encode("ascii"), False, id=f"pt9-accept-{index}"))
    rows.append(pytest.param(b"/", False, id="pt9-root"))
    rows.append(pytest.param(b"/a?x=/../b", False, id="pt9-query"))
    wide = b"/" + b"%25" * 5461
    assert len(wide) == 16 * 1024
    rows.append(pytest.param(wide, False, id="pt9-wide"))
    return rows


@pytest.mark.parametrize(("raw", "expected"), _predicate_rows())
def test_pt_9_predicate_table(raw: bytes, expected: bool) -> None:
    from satsgate_proxy.match import unsafe_request_path

    assert unsafe_request_path(raw) is expected


@pytest.mark.parametrize(
    "path",
    (
        pytest.param("/static/../mcp", id="pt10-mcp"),
        pytest.param("/static/a/../../api/report", id="pt10-report"),
    ),
)
def test_pt_10_fallback_without_raw_path(tmp_path: Path, path: str) -> None:
    previous = _env_guard()
    try:
        config = tmp_path / "proxy.yaml"
        config.write_text(_BASE_YAML, encoding="utf-8")
        world = World()
        app = build_app(load_settings(config), transport=world)
        messages: list[dict] = []

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict) -> None:
            messages.append(message)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "query_string": b"",
            "headers": [(b"host", b"test"), (b"content-length", b"0")],
            "client": ("127.0.0.1", 1234),
            "server": ("127.0.0.1", 80),
        }

        async def run() -> None:
            await app(scope, receive, send)

        asyncio.run(run())
    finally:
        _env_restore(previous)
    start = next(item for item in messages if item["type"] == "http.response.start")
    body = b"".join(item.get("body", b"") for item in messages if item["type"] == "http.response.body")
    headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in start["headers"]}
    assert start["status"] == 404
    assert json.loads(body) == {"ok": False, "error": "not_found"}
    assert headers.get("cache-control") == "no-store"
    assert headers.get("content-type", "").startswith("application/json")
    assert world.core_calls == []
    assert world.up_calls == []
