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


def _failure(error: str, status: int, *, use_spent: bool) -> JSONResponse:
    body: dict[str, object] = {"ok": False, "error": error}
    if use_spent:
        body["use_spent"] = True
        body["note"] = SPENT_NOTE
    return JSONResponse(body, status_code=status)


def _upstream_response(content: bytes, status_code: int, header_items: list[tuple[str, str]]) -> Response:
    raw = filter_response_headers(header_items)
    if status_code >= 200 and status_code not in {204, 304}:
        raw.append((b"content-length", str(len(content)).encode("ascii")))
    response = Response(content=content, status_code=status_code)
    response.raw_headers = raw
    if hasattr(response, "_headers"):
        delattr(response, "_headers")
    return response


async def forward(
    request: Request,
    settings: Settings,
    *,
    payment_hash: str | None,
    resource: str | None,
    paid_sats: int | None,
    use_spent: bool,
) -> Response:
    client: httpx.AsyncClient = request.app.state.http
    target = request_target(request.scope)
    headers = filter_request_headers(list(request.headers.raw), inject=settings.inject_headers)
    if payment_hash and resource is not None and paid_sats is not None:
        timestamp = int(time.time())
        headers.append(("X-Satsgate-Payment-Hash", payment_hash))
        headers.append(("X-Satsgate-Resource", resource))
        headers.append(("X-Satsgate-Paid-Sats", str(int(paid_sats))))
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
                log.warning("upstream redirect status %s consume=%s", response.status_code, use_spent)
                return _failure("upstream_redirect", 502, use_spent=use_spent)
            declared = response.headers.get("content-length")
            if declared is not None and declared.isdigit() and int(declared) > settings.max_response_bytes:
                log.warning("upstream response declared too large consume=%s", use_spent)
                return _failure("upstream_response_too_large", 502, use_spent=use_spent)
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                if time.monotonic() > deadline:
                    log.warning("upstream time cap consume=%s", use_spent)
                    return _failure("upstream_timeout", 504, use_spent=use_spent)
                total += len(chunk)
                if total > settings.max_response_bytes:
                    log.warning("upstream response too large consume=%s", use_spent)
                    return _failure("upstream_response_too_large", 502, use_spent=use_spent)
                chunks.append(chunk)
            if response.status_code >= 500:
                log.warning("upstream status %s consume=%s", response.status_code, use_spent)
            return _upstream_response(b"".join(chunks), response.status_code, list(response.headers.multi_items()))
    except httpx.TimeoutException:
        log.warning("upstream timeout consume=%s", use_spent)
        return _failure("upstream_timeout", 504, use_spent=use_spent)
    except httpx.HTTPError:
        log.warning("upstream unavailable consume=%s", use_spent)
        return _failure("upstream_unavailable", 502, use_spent=use_spent)
