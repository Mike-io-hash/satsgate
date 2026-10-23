"""Forward a paid or free request. Redirects are not followed."""

from __future__ import annotations

import logging
import time

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from satsgate_proxy.config import Settings
from satsgate_proxy.core_client import SPENT_NOTE
from satsgate_proxy.headers import filter_request_headers, filter_response_headers
from satsgate_proxy.origin import request_target, sign_origin

log = logging.getLogger("satsgate_proxy")


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


class UpstreamExchange:
    """A finished origin call. ``error`` is set when there is no body to return."""

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


async def call_upstream(
    request: Request,
    settings: Settings,
    *,
    payment_hash: str | None,
    resource: str | None,
    paid_sats: int | None = None,
    paid_usd_atomic: int | None = None,
) -> UpstreamExchange:
    client: httpx.AsyncClient = request.app.state.http
    target = request_target(request.scope)
    headers = filter_request_headers(list(request.headers.raw), inject=settings.inject_headers)
    if payment_hash and resource is not None and (paid_sats is not None or paid_usd_atomic is not None):
        timestamp = int(time.time())
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
                    secret=settings.origin_secret,
                    timestamp=timestamp,
                    method=request.method,
                    target=target,
                    payment_hash=payment_hash,
                ),
            )
        )
    upstream = settings.upstream_base_url + target
    deadline = time.monotonic() + settings.upstream_timeout
    try:
        async with client.stream(
            request.method,
            upstream,
            headers=headers,
            content=request.state.body,
            timeout=httpx.Timeout(settings.upstream_timeout),
            follow_redirects=False,
        ) as response:
            if 300 <= response.status_code < 400:
                log.warning("upstream redirect status %s", response.status_code)
                return UpstreamExchange(error="upstream_redirect", status=502)
            declared = response.headers.get("content-length")
            if declared is not None and declared.isdigit() and int(declared) > settings.max_response_bytes:
                log.warning("upstream response declared too large")
                return UpstreamExchange(error="upstream_response_too_large", status=502)
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                if time.monotonic() > deadline:
                    log.warning("upstream time cap")
                    return UpstreamExchange(error="upstream_timeout", status=504)
                total += len(chunk)
                if total > settings.max_response_bytes:
                    log.warning("upstream response too large")
                    return UpstreamExchange(error="upstream_response_too_large", status=502)
                chunks.append(chunk)
            return UpstreamExchange(
                status=response.status_code,
                content=b"".join(chunks),
                header_items=list(response.headers.multi_items()),
            )
    except httpx.TimeoutException:
        log.warning("upstream timeout")
        return UpstreamExchange(error="upstream_timeout", status=504)
    except httpx.HTTPError:
        log.warning("upstream unavailable")
        return UpstreamExchange(error="upstream_unavailable", status=502)


async def forward(
    request: Request,
    settings: Settings,
    *,
    payment_hash: str | None,
    resource: str | None,
    paid_sats: int | None,
    use_spent: bool,
) -> Response:
    """Free paths, and any caller that already decided the use. Paid rails use call_upstream."""
    exchanged = await call_upstream(
        request,
        settings,
        payment_hash=payment_hash,
        resource=resource,
        paid_sats=paid_sats,
    )
    return exchanged.response(use_spent=True if use_spent else None)
