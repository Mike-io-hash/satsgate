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
    parsed = urlsplit((url or "").strip())
    if parsed.scheme != "https":
        raise SSRFError("destination_rejected")
    if parsed.username or parsed.password:
        raise SSRFError("destination_rejected")
    host = parsed.hostname
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
