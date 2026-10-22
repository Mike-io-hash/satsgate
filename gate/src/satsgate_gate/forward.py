"""Forward a paid request. Redirects are not followed, including same-origin ones.

A redirect would change the request that was signed. The buyer gets HTTP 502
and no Location header. The body is read in chunks up to the size cap and is
not sent until the whole body is within that cap, so a paid response is never
truncated. Nothing in this process stores the body.
"""

from __future__ import annotations

import logging
import time
from urllib.parse import urlsplit, urlunsplit

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from satsgate_gate.cache import CachedSite
from satsgate_gate.config import Settings
from satsgate_gate.core_client import SPENT_NOTE
from satsgate_gate.headers import filter_request_headers, filter_response_headers
from satsgate_gate.origin import sign_origin
from satsgate_gate.ssrf import SSRFError, guard_url, pinned_host, pinned_ip

log = logging.getLogger("satsgate_gate")


def origin_target(origin_url: str, route_path: str, query: str) -> tuple[str, str]:
    """Absolute origin URL and the request target both sides sign."""
    parts = urlsplit(origin_url)
    base = (parts.path or "").rstrip("/")
    extra = "" if route_path == "/" else route_path
    path = base + extra
    if not path.startswith("/"):
        path = "/" + path
    if ".." in path or "\\" in path or "//" in path:
        raise SSRFError("destination_rejected")
    target = f"{path}?{query}" if query else path
    url = urlunsplit(("https", parts.netloc, path, query, ""))
    return url, target


def _failure(error: str, status: int, *, use_spent: bool | None) -> JSONResponse:
    body: dict[str, object] = {"ok": False, "error": error}
    if use_spent is True:
        body["use_spent"] = True
        body["note"] = SPENT_NOTE
    elif use_spent is False:
        body["use_spent"] = False
    return JSONResponse(body, status_code=status, headers={"Cache-Control": "no-store"})


def _upstream_response(
    content: bytes,
    status_code: int,
    header_items: list[tuple[str, str]],
    extra: tuple[tuple[str, str], ...] = (),
) -> Response:
    raw = filter_response_headers(header_items)
    raw.append((b"cache-control", b"no-store"))
    for name, value in extra:
        if name and value and "\r" not in value and "\n" not in value:
            raw.append((name.encode("latin-1"), value.encode("latin-1")))
    if status_code >= 200 and status_code not in {204, 304}:
        raw.append((b"content-length", str(len(content)).encode("ascii")))
    response = Response(content=content, status_code=status_code, headers={"Cache-Control": "no-store"})
    response.raw_headers = raw
    if hasattr(response, "_headers"):
        delattr(response, "_headers")
    return response


class OriginExchange:
    """A finished origin call. ``error`` is set when the gate did not get a body to return."""

    def __init__(
        self,
        *,
        error: str = "",
        status: int = 502,
        content: bytes = b"",
        header_items: list[tuple[str, str]] | None = None,
    ) -> None:
        self.error = error
        self.status = status
        self.content = content
        self.header_items = header_items or []

    def response(
        self,
        *,
        use_spent: bool | None,
        extra: tuple[tuple[str, str], ...] = (),
    ) -> Response:
        if self.error:
            return _failure(self.error, self.status, use_spent=use_spent)
        return _upstream_response(self.content, self.status, self.header_items, extra)


async def call_origin(
    request: Request,
    settings: Settings,
    site: CachedSite,
    *,
    route_path: str,
    payment_hash: str,
    resource: str,
    paid_sats: int | None = None,
    paid_usd_atomic: int | None = None,
) -> OriginExchange:
    query = request.scope.get("query_string") or b""
    if isinstance(query, bytes):
        query_text = query.decode("latin-1")
    else:
        query_text = str(query)
    if any(char in query_text for char in "\r\n\0") or len(query_text) > 2048:
        return OriginExchange(error="upstream_unavailable", status=502)
    try:
        upstream, target = origin_target(site.origin_url, route_path, query_text)
        guarded = guard_url(upstream, resolver=settings.resolver)
    except SSRFError:
        log.warning("origin rejected before connect")
        return OriginExchange(error="upstream_unavailable", status=502)

    client: httpx.AsyncClient = request.app.state.origin_client
    timestamp = int(time.time())
    headers = filter_request_headers(list(request.headers.raw))
    headers.append(("X-Satsgate-Payment-Hash", payment_hash))
    headers.append(("X-Satsgate-Resource", resource))
    if paid_usd_atomic is not None:
        headers.append(("X-Satsgate-Paid-Usd-Atomic", str(int(paid_usd_atomic))))
    else:
        headers.append(("X-Satsgate-Paid-Sats", str(int(paid_sats or 0))))
    headers.append(
        (
            "X-Satsgate-Signature",
            sign_origin(
                secret=site.origin_secret,
                timestamp=timestamp,
                method=request.method,
                target=target,
                payment_hash=payment_hash,
            ),
        )
    )
    deadline = time.monotonic() + settings.upstream_timeout
    ip_token = pinned_ip.set(guarded.ip)
    host_token = pinned_host.set(guarded.host)
    try:
        async with client.stream(
            request.method,
            guarded.url,
            headers=headers,
            content=request.state.body,
            timeout=httpx.Timeout(settings.upstream_timeout),
            follow_redirects=False,
        ) as response:
            if 300 <= response.status_code < 400:
                log.warning("upstream redirect status %s", response.status_code)
                return OriginExchange(error="upstream_redirect", status=502)
            declared = response.headers.get("content-length")
            if declared is not None and declared.isdigit() and int(declared) > settings.max_response_bytes:
                log.warning("upstream response declared too large")
                return OriginExchange(error="upstream_response_too_large", status=502)
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                if time.monotonic() > deadline:
                    log.warning("upstream time cap")
                    return OriginExchange(error="upstream_timeout", status=504)
                total += len(chunk)
                if total > settings.max_response_bytes:
                    log.warning("upstream response too large")
                    return OriginExchange(error="upstream_response_too_large", status=502)
                chunks.append(chunk)
            return OriginExchange(
                status=response.status_code,
                content=b"".join(chunks),
                header_items=list(response.headers.multi_items()),
            )
    except httpx.TimeoutException:
        log.warning("upstream timeout")
        return OriginExchange(error="upstream_timeout", status=504)
    except (httpx.HTTPError, SSRFError):
        log.warning("upstream unavailable")
        return OriginExchange(error="upstream_unavailable", status=502)
    finally:
        pinned_ip.reset(ip_token)
        pinned_host.reset(host_token)
