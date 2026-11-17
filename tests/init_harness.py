"""In-process core for satsgate init tests. Refuses the public hosts."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from satsgate.init import InitOptions, run_init

API = "http://127.0.0.1:9"
ADDRESS = "merchant@pay.example"
_FORBIDDEN = frozenset({"api.satsgate.org", "gate.satsgate.org"})


class RecordingAsync(httpx.AsyncBaseTransport):
    """Proxy-side transport. Core calls stay in-process. Other hosts are the origin."""

    def __init__(self, app: object) -> None:
        self._core = httpx.ASGITransport(app=app)
        self.core_requests: list[httpx.Request] = []
        self.origin_requests: list[httpx.Request] = []
        self.origin = None

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host in _FORBIDDEN:
            raise AssertionError(f"init test called {request.url.host}")
        if request.url.host == "127.0.0.1" and request.url.port == 9:
            self.core_requests.append(request)
            return await self._core.handle_async_request(request)
        self.origin_requests.append(request)
        if self.origin is not None:
            return self.origin(request)
        raise httpx.ConnectError("origin is not called by the unpaid test")


class RecordingSync(httpx.BaseTransport):
    def __init__(self, app_client: TestClient) -> None:
        self._app = app_client
        self.requests: list[httpx.Request] = []
        self.async_transport = RecordingAsync(app_client.app)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host in _FORBIDDEN:
            raise AssertionError(f"init test called {request.url.host}")
        self.requests.append(request)
        url = request.url.path
        if request.url.query:
            url = f"{url}?{request.url.query.decode()}"
        headers = {key: value for key, value in request.headers.items() if key.lower() != "host"}
        response = self._app.request(request.method, url, headers=headers, content=request.content)
        return httpx.Response(
            status_code=response.status_code,
            headers=dict(response.headers),
            content=response.content,
        )


class Bound:
    def __init__(self, sdk: httpx.BaseTransport) -> None:
        self.sdk = sdk
        self.proxy = getattr(sdk, "async_transport", None)


class Scripted:
    def __init__(self, lines: list[str], *, tty: bool) -> None:
        self.lines = list(lines)
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty

    def readline(self) -> str:
        if not self.lines:
            raise AssertionError("unexpected stdin read")
        return self.lines.pop(0)

    def read(self, _n: int = -1) -> str:
        raise AssertionError("unexpected stdin read")


class Closed:
    def isatty(self) -> bool:
        return False

    def readline(self) -> str:
        raise AssertionError("stdin read")

    def read(self, _n: int = -1) -> str:
        raise AssertionError("stdin read")


def options(root: Path, **overrides: object) -> InitOptions:
    values: dict[str, object] = {
        "api_url": API,
        "lightning_address": ADDRESS,
        "want_usdc": False,
        "json_mode": True,
        "framework": "none",
        "cwd": root,
    }
    values.update(overrides)
    return InitOptions(**values)  # type: ignore[arg-type]


def invoke(root: Path, transport: RecordingSync, **overrides: object):
    stdout_lines: list[str] = []
    stderr_lines: list[str] = []
    stdout_tty = bool(overrides.pop("stdout_tty", False))

    class _Buf:
        def __init__(self, sink: list[str], *, tty: bool) -> None:
            self.sink = sink
            self._tty = tty

        def write(self, text: str) -> int:
            self.sink.append(text)
            return len(text)

        def flush(self) -> None:
            return None

        def isatty(self) -> bool:
            return self._tty

    stdin = overrides.pop("stdin", Closed())
    stdout = _Buf(stdout_lines, tty=stdout_tty)
    stderr = _Buf(stderr_lines, tty=False)
    code = run_init(options(root, **overrides), transport=Bound(transport), stdin=stdin, stdout=stdout, stderr=stderr)
    out = "".join(stdout_lines)
    err = "".join(stderr_lines)
    body = json.loads(out) if out.strip().startswith("{") else None
    return code, body, out, err


def posts(transport: RecordingSync, path: str) -> list[httpx.Request]:
    return [item for item in transport.requests if item.method == "POST" and item.url.path == path]
