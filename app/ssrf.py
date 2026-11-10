"""HTTPS fetches that refuse private, loopback, and link-local targets.

LNURL-pay callbacks are attacker-influenced (the payee's provider chooses the
URL). Every outbound request is https-only, DNS-resolved before connect, pinned
to a public address, and capped in time and size. Redirects are not followed.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit, urlencode, urlunsplit

import httpx

MAX_RESPONSE_BYTES = 64 * 1024
DEFAULT_TIMEOUT_SECONDS = 5.0

_BLOCKED_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
    }
)
_BLOCKED_SUFFIXES = (".local", ".localhost", ".localdomain", ".internal")

# Shared across calls. trust_env is off so HTTP_PROXY cannot punch through.
_local = threading.local()
_client_lock = threading.Lock()
_client: httpx.Client | None = None


class SSRFError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class GuardedURL:
    url: str
    host: str
    ip: str
    port: int


def is_public_ip(value: str) -> bool:
    """True only for globally routable unicast addresses."""
    text = value.split("%", 1)[0].strip()
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    # is_global is False for CGNAT, documentation, and reserved ranges on 3.12+.
    # Multicast can still report is_global, so exclude it explicitly.
    if addr.is_multicast or addr.is_private or addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_reserved or addr.is_unspecified or not addr.is_global:
        return False
    if addr in ipaddress.ip_network("100.64.0.0/10"):
        return False
    return True


def _blocked_hostname(host: str) -> bool:
    name = host.lower().rstrip(".")
    if name in _BLOCKED_NAMES:
        return True
    return any(name.endswith(suffix) for suffix in _BLOCKED_SUFFIXES)


def guard_url(url: str, *, resolver: Callable | None = None) -> GuardedURL:
    """Reject non-https and non-public targets. Does not connect."""
    try:
        parsed = urlsplit((url or "").strip())
    except ValueError as exc:
        raise SSRFError("destination_rejected") from exc
    if parsed.scheme != "https":
        raise SSRFError("destination_rejected")
    if parsed.username or parsed.password:
        raise SSRFError("destination_rejected")
    try:
        host = parsed.hostname
    except ValueError as exc:
        raise SSRFError("destination_rejected") from exc
    if not host:
        raise SSRFError("destination_rejected")
    try:
        host_idna = host.encode("idna").decode("ascii").lower().rstrip(".")
    except Exception as exc:  # noqa: BLE001
        raise SSRFError("destination_rejected") from exc
    if _blocked_hostname(host_idna) or _blocked_hostname(host):
        raise SSRFError("destination_rejected")

    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise SSRFError("destination_rejected") from exc
    if port < 1 or port > 65535:
        raise SSRFError("destination_rejected")

    lookup = resolver or socket.getaddrinfo
    try:
        infos = lookup(host_idna, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFError("destination_rejected") from exc

    ips: list[str] = []
    for info in infos:
        candidate = str(info[4][0]).split("%", 1)[0]
        if candidate not in ips:
            ips.append(candidate)
    if not ips or any(not is_public_ip(ip) for ip in ips):
        raise SSRFError("destination_rejected")

    return GuardedURL(url=url.strip(), host=host_idna, ip=ips[0], port=port)


class _PinnedNetworkBackend:
    """httpcore backend that connects to the thread-local public IP, never the hostname."""

    def __init__(self) -> None:
        import httpcore

        self._inner = httpcore.SyncBackend()

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):  # noqa: ANN001
        pinned_ip = getattr(_local, "pinned_ip", None)
        pinned_host = getattr(_local, "pinned_host", None)
        if not pinned_ip or not is_public_ip(pinned_ip):
            raise SSRFError("destination_rejected")
        if pinned_host and str(host).lower().rstrip(".") != pinned_host:
            raise SSRFError("destination_rejected")
        return self._inner.connect_tcp(pinned_ip, port, timeout, local_address, socket_options)

    def connect_unix_socket(self, path, timeout=None, socket_options=None):  # noqa: ANN001
        raise SSRFError("destination_rejected")

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


def _shared_client() -> httpx.Client:
    global _client
    with _client_lock:
        if _client is None:
            import httpcore
            import ssl

            ssl_context = ssl.create_default_context()
            pool = httpcore.ConnectionPool(
                ssl_context=ssl_context,
                max_connections=20,
                max_keepalive_connections=10,
                retries=0,
                network_backend=_PinnedNetworkBackend(),
            )
            transport = httpx.HTTPTransport(retries=0, trust_env=False)
            transport._pool.close()
            transport._pool = pool
            _client = httpx.Client(
                transport=transport,
                timeout=httpx.Timeout(DEFAULT_TIMEOUT_SECONDS),
                follow_redirects=False,
                trust_env=False,
            )
        return _client


def close() -> None:
    global _client
    with _client_lock:
        if _client is not None:
            _client.close()
            _client = None


def _with_params(url: str, params: dict | None) -> str:
    if not params:
        return url
    parts = urlsplit(url)
    extra = urlencode({k: v for k, v in params.items()})
    query = extra if not parts.query else f"{parts.query}&{extra}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def safe_get_bytes(
    url: str,
    *,
    params: dict | None = None,
    client: httpx.Client | None = None,
    resolver: Callable | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> bytes:
    guarded = guard_url(url, resolver=resolver)
    target = _with_params(guarded.url, params)
    # Params must not be able to retarget the host. Re-guard the full URL.
    guarded = guard_url(target, resolver=resolver)
    http = client or _shared_client()
    _local.pinned_ip = guarded.ip
    _local.pinned_host = guarded.host
    try:
        with http.stream("GET", target, timeout=timeout, follow_redirects=False) as response:
            if 300 <= response.status_code < 400:
                raise SSRFError("redirects_not_allowed")
            if response.status_code != 200:
                raise SSRFError("fetch_failed")
            declared = response.headers.get("content-length")
            if declared is not None:
                try:
                    if int(declared) > MAX_RESPONSE_BYTES:
                        raise SSRFError("response_too_large")
                except ValueError as exc:
                    raise SSRFError("invalid_response") from exc
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > MAX_RESPONSE_BYTES:
                    raise SSRFError("response_too_large")
                chunks.append(chunk)
            return b"".join(chunks)
    except SSRFError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise SSRFError("fetch_failed") from exc
    finally:
        _local.pinned_ip = None
        _local.pinned_host = None


def _request_headers(extra: dict | None) -> dict[str, str]:
    headers = {"content-type": "application/json"}
    if not extra:
        return headers
    for key, value in extra.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise SSRFError("invalid_response")
        if any(char in key or char in value for char in "\r\n\0"):
            raise SSRFError("invalid_response")
        headers[key] = value
    return headers


def safe_get_response(
    url: str,
    *,
    headers: dict | None = None,
    resolver: Callable | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> tuple[int, bytes]:
    """GET and return status plus a capped body. Redirects are rejected.

    A non-200 is returned, not raised, so a caller can tell auth from a crash.
    Header values are not logged.
    """
    guarded = guard_url(url, resolver=resolver)
    request_headers = _request_headers(headers)
    request_headers.pop("content-type", None)
    http = _shared_client()
    _local.pinned_ip = guarded.ip
    _local.pinned_host = guarded.host
    try:
        with http.stream(
            "GET",
            guarded.url,
            headers=request_headers,
            timeout=timeout,
            follow_redirects=False,
        ) as response:
            if 300 <= response.status_code < 400:
                raise SSRFError("redirects_not_allowed")
            declared = response.headers.get("content-length")
            if declared is not None:
                try:
                    if int(declared) > int(max_bytes):
                        raise SSRFError("response_too_large")
                except ValueError as exc:
                    raise SSRFError("invalid_response") from exc
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_bytes():
                total += len(chunk)
                if total > int(max_bytes):
                    raise SSRFError("response_too_large")
                chunks.append(chunk)
            return response.status_code, b"".join(chunks)
    except SSRFError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise SSRFError("fetch_failed") from exc
    finally:
        _local.pinned_ip = None
        _local.pinned_host = None


def safe_post_json(
    url: str,
    payload: dict,
    *,
    headers: dict | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    resolver: Callable | None = None,
) -> tuple[int, dict | None]:
    """POST JSON and return status plus a dict body. Redirects are rejected.

    A non-JSON body comes back as None. The caller decides what a non-200 means.
    Extra headers (an Authorization bearer) are not logged.
    """
    guarded = guard_url(url, resolver=resolver)
    raw = json.dumps(payload).encode("utf-8")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise SSRFError("request_too_large")
    http = _shared_client()
    _local.pinned_ip = guarded.ip
    _local.pinned_host = guarded.host
    try:
        response = http.post(
            guarded.url,
            content=raw,
            headers=_request_headers(headers),
            timeout=timeout,
            follow_redirects=False,
        )
        if 300 <= response.status_code < 400:
            raise SSRFError("redirects_not_allowed")
        body = response.content
        if len(body) > MAX_RESPONSE_BYTES:
            raise SSRFError("response_too_large")
        if not body:
            return response.status_code, None
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return response.status_code, None
        if not isinstance(data, dict):
            return response.status_code, None
        return response.status_code, data
    except SSRFError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise SSRFError("fetch_failed") from exc
    finally:
        _local.pinned_ip = None
        _local.pinned_host = None


# How long to wait, after closing the socket, for the delivery thread to exit.
_ABORT_GRACE_SECONDS = 0.1
# Slow DNS cannot pile up one thread per attempt.
_RESOLVER_LIMIT = 4
_resolver_slots = threading.BoundedSemaphore(_RESOLVER_LIMIT)


def _read_raw_capped(response: httpx.Response, limit: int, deadline_at: float) -> tuple[bytes, bool]:
    """Raw response bytes, never decoded, and no further read once ``limit`` is met.

    Returns ``(body, timed_out)``. ``deadline_at`` is the delivery deadline.
    A byte that arrives and then a stall is still a timeout.
    """
    if limit <= 0:
        return b"", False
    chunks: list[bytes] = []
    total = 0
    timed_out = False
    stream = response.iter_raw()
    try:
        while total < limit:
            if deadline_at - time.monotonic() <= 0:
                timed_out = True
                break
            try:
                chunk = next(stream)
            except StopIteration:
                break
            except Exception:
                timed_out = True
                break
            if not chunk:
                continue
            room = limit - total
            if len(chunk) > room:
                chunks.append(chunk[:room])
                break
            chunks.append(chunk)
            total += len(chunk)
            if total >= limit:
                break
    finally:
        try:
            stream.close()
        except RuntimeError:
            pass
    return b"".join(chunks), timed_out


def _resolve_limited(lookup: Callable, host: str, port: int, args: tuple, kwargs: dict, deadline_at: float):
    """DNS with at most ``_RESOLVER_LIMIT`` outstanding lookups.

    A full set of lookups fails the next one immediately. A lookup that is
    still running at the deadline does not start the HTTP request. If the
    worker cannot be constructed or started, the permit is returned once
    here. A worker that did start releases it, including after this caller
    has already timed out.
    """
    remaining = deadline_at - time.monotonic()
    if remaining <= 0:
        raise SSRFError("fetch_failed")
    if not _resolver_slots.acquire(blocking=False):
        raise SSRFError("fetch_failed")
    box: dict = {}
    started = False

    def run() -> None:
        try:
            box["value"] = lookup(host, port, *args, **kwargs)
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc
        finally:
            _resolver_slots.release()

    try:
        try:
            worker = threading.Thread(target=run, name="satsgate-webhook-dns", daemon=True)
            worker.start()
        except Exception as exc:
            raise SSRFError("fetch_failed") from exc
        started = True
        worker.join(remaining)
        if worker.is_alive():
            raise SSRFError("fetch_failed")
        if "error" in box:
            raise box["error"]
        return box.get("value")
    finally:
        if not started:
            _resolver_slots.release()


def _abort_active_connections(client: httpx.Client | None) -> None:
    """Close the connection this delivery is using so the pool slot is freed."""
    if client is None:
        return
    transport = getattr(client, "_transport", None)
    pool = getattr(transport, "_pool", None)
    if pool is None:
        return
    for conn in list(getattr(pool, "_connections", ())):
        try:
            if conn.is_closed() or conn.is_idle():
                continue
        except Exception:
            pass
        inner = getattr(conn, "_connection", None)
        stream = getattr(inner, "_network_stream", None) if inner is not None else None
        if stream is not None:
            try:
                stream.close()
            except Exception:
                pass
        try:
            conn.close()
        except Exception:
            pass


def safe_post_bytes(
    url: str,
    body: bytes,
    *,
    headers: dict | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    deadline: float | None = None,
    resolver: Callable | None = None,
    max_bytes: int = 4 * 1024,
    client: httpx.Client | None = None,
) -> tuple[int, bytes]:
    """POST exact bytes and return status plus a capped raw body. Redirects are rejected.

    The cap counts undecoded socket bytes. ``Accept-Encoding: identity`` is
    sent and ``Content-Encoding`` is not decoded, so a tiny gzip bomb cannot
    expand before the cap. Once ``max_bytes`` is in hand, no further read is
    started. ``deadline`` is one wall-clock budget for DNS, connect, TLS, the
    request, the headers, and the body. It is not restarted when the body
    starts. The caller signs ``body`` and must pass those same bytes. Header
    values are not logged.
    """
    if not isinstance(body, (bytes, bytearray)):
        raise SSRFError("request_too_large")
    raw = bytes(body)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise SSRFError("request_too_large")
    limit = int(max_bytes)
    if limit < 0:
        raise SSRFError("response_too_large")
    budget = float(timeout if deadline is None else deadline)
    if budget <= 0:
        raise SSRFError("fetch_failed")
    # One expiry for every phase. A slow header must not get a fresh 5 s.
    deadline_at = time.monotonic() + budget
    lookup = resolver or socket.getaddrinfo

    def bounded_lookup(host, port, *args, **kwargs):
        return _resolve_limited(lookup, host, port, args, kwargs, deadline_at)

    guarded = guard_url(url, resolver=bounded_lookup)
    if deadline_at - time.monotonic() <= 0:
        raise SSRFError("fetch_failed")
    http = client if client is not None else _delivery_client()
    owns_client = client is None
    box: dict = {}

    def work() -> None:
        try:
            box["value"] = _post_bounded(
                guarded,
                raw,
                headers=headers,
                timeout=float(timeout),
                deadline_at=deadline_at,
                limit=limit,
                client=http,
            )
        except BaseException as exc:  # noqa: BLE001
            box["error"] = exc

    worker = threading.Thread(target=work, name="satsgate-webhook-http", daemon=True)
    worker.start()
    try:
        worker.join(max(0.0, deadline_at - time.monotonic()))
        if worker.is_alive():
            # The read is still inside httpx. Closing the stream unblocks it
            # and gives the pool slot back before we return.
            _abort_active_connections(http)
            worker.join(_ABORT_GRACE_SECONDS)
            raise SSRFError("fetch_failed")
        if "error" in box:
            err = box["error"]
            if isinstance(err, SSRFError):
                raise err
            raise SSRFError("fetch_failed") from err
        return box["value"]
    finally:
        if owns_client:
            try:
                http.close()
            except Exception:
                pass


def _delivery_client() -> httpx.Client:
    """A private client so one slow receiver cannot fill the shared pool."""
    import httpcore
    import ssl

    ssl_context = ssl.create_default_context()
    pool = httpcore.ConnectionPool(
        ssl_context=ssl_context,
        max_connections=2,
        max_keepalive_connections=1,
        retries=0,
        network_backend=_PinnedNetworkBackend(),
    )
    transport = httpx.HTTPTransport(retries=0, trust_env=False)
    transport._pool.close()
    transport._pool = pool
    return httpx.Client(
        transport=transport,
        timeout=httpx.Timeout(DEFAULT_TIMEOUT_SECONDS),
        follow_redirects=False,
        trust_env=False,
    )


def _capped_timeout(timeout: float | None, deadline_at: float) -> float:
    """Time left until ``deadline_at``, and never more than ``timeout``.

    A non-positive result means the caller must not start that socket call.
    """
    remaining = deadline_at - time.monotonic()
    if remaining <= 0:
        raise SSRFError("fetch_failed")
    if timeout is None:
        return remaining
    return min(float(timeout), remaining)


class _DeadlineStream:
    """Recalculate the socket timeout before every blocking read, write, and handshake."""

    def __init__(self, inner, deadline_at: float) -> None:
        self._inner = inner
        self._deadline_at = deadline_at

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        return self._inner.read(max_bytes, _capped_timeout(timeout, self._deadline_at))

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        self._inner.write(buffer, _capped_timeout(timeout, self._deadline_at))

    def close(self) -> None:
        self._inner.close()

    def start_tls(self, ssl_context, server_hostname=None, timeout=None):  # noqa: ANN001
        capped = _capped_timeout(timeout, self._deadline_at)
        tls = self._inner.start_tls(ssl_context, server_hostname, capped)
        return _DeadlineStream(tls, self._deadline_at)

    def get_extra_info(self, info: str):
        return self._inner.get_extra_info(info)


class _DeadlineBackend:
    """Cap connect, then wrap the stream so later I/O sees the same deadline."""

    def __init__(self, inner, deadline_at: float) -> None:
        self._inner = inner
        self._deadline_at = deadline_at

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):  # noqa: ANN001
        capped = _capped_timeout(timeout, self._deadline_at)
        stream = self._inner.connect_tcp(host, port, capped, local_address, socket_options)
        return _DeadlineStream(stream, self._deadline_at)

    def connect_unix_socket(self, path, timeout=None, socket_options=None):  # noqa: ANN001
        raise SSRFError("destination_rejected")

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


def _install_deadline_backend(client: httpx.Client, deadline_at: float):
    transport = getattr(client, "_transport", None)
    pool = getattr(transport, "_pool", None)
    if pool is None:
        return None
    original = pool._network_backend
    pool._network_backend = _DeadlineBackend(original, deadline_at)
    return original


def _restore_deadline_backend(client: httpx.Client, original) -> None:
    if original is None:
        return
    transport = getattr(client, "_transport", None)
    pool = getattr(transport, "_pool", None)
    if pool is not None:
        pool._network_backend = original


def _post_bounded(
    guarded: GuardedURL,
    raw: bytes,
    *,
    headers: dict | None,
    timeout: float,
    deadline_at: float,
    limit: int,
    client: httpx.Client,
) -> tuple[int, bytes]:
    """Connect through body, measured against the deadline chosen before DNS."""
    if deadline_at - time.monotonic() <= 0:
        raise SSRFError("fetch_failed")
    request_headers = _request_headers(headers)
    # Do not invite a compressed body. Decoding is what blows the cap.
    request_headers["accept-encoding"] = "identity"
    remaining = deadline_at - time.monotonic()
    if remaining <= 0:
        raise SSRFError("fetch_failed")
    # The request timeout is an upper bound. Each later socket call is capped
    # again to whatever is still left, on the stream that actually blocks.
    op_timeout = min(float(timeout), remaining)
    # This thread performs the connect, so the pin has to be set here.
    _local.pinned_ip = guarded.ip
    _local.pinned_host = guarded.host
    original_backend = _install_deadline_backend(client, deadline_at)
    try:
        with client.stream(
            "POST",
            guarded.url,
            content=raw,
            headers=request_headers,
            timeout=op_timeout,
            follow_redirects=False,
        ) as response:
            if 300 <= response.status_code < 400:
                raise SSRFError("redirects_not_allowed")
            if deadline_at - time.monotonic() <= 0:
                raise SSRFError("fetch_failed")
            # A preloaded body is already bytes; slice it and do not decode.
            # A streamed body is read raw so Content-Encoding is not expanded.
            if hasattr(response, "_content"):
                if deadline_at - time.monotonic() <= 0:
                    raise SSRFError("fetch_failed")
                return response.status_code, bytes(response._content)[:limit]
            payload, timed_out = _read_raw_capped(response, limit, deadline_at)
            # Any miss, including after a few body bytes, is a failed attempt.
            if timed_out:
                raise SSRFError("fetch_failed")
            return response.status_code, payload
    finally:
        _restore_deadline_backend(client, original_backend)
        _local.pinned_ip = None
        _local.pinned_host = None


def safe_get_json(
    url: str,
    *,
    params: dict | None = None,
    client: httpx.Client | None = None,
    resolver: Callable | None = None,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    body = safe_get_bytes(url, params=params, client=client, resolver=resolver, timeout=timeout)
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise SSRFError("invalid_response") from exc
    if not isinstance(data, dict):
        raise SSRFError("invalid_response")
    return data
