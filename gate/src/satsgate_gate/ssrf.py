"""HTTPS fetches that refuse private, loopback, and link-local targets.

The origin hostname is resolved on every forward. The TCP connection uses the
public address from that lookup, not a later DNS answer, so a name that
changes to a private address between the check and the connect (DNS rebinding)
is not followed. TLS still uses the original hostname for SNI and certificate
checks. Redirects are not followed.
"""

from __future__ import annotations

import contextvars
import ipaddress
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpcore
import httpx

_BLOCKED_NAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
    }
)
_BLOCKED_SUFFIXES = (".local", ".localhost", ".localdomain", ".internal")

pinned_ip: contextvars.ContextVar[str | None] = contextvars.ContextVar("satsgate_gate_pinned_ip", default=None)
pinned_host: contextvars.ContextVar[str | None] = contextvars.ContextVar("satsgate_gate_pinned_host", default=None)


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


def _ip_trick(host: str) -> bool:
    """Decimal, hex, and zero-padded forms that some resolvers treat as addresses."""
    if host.startswith(("0x", "0X")):
        return True
    if host.isdigit():
        return True
    parts = host.split(".")
    if 1 < len(parts) <= 4 and all(part.isdigit() for part in parts):
        if any(len(part) > 1 and part.startswith("0") for part in parts):
            return True
    return False


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
    if _blocked_hostname(host_idna) or _blocked_hostname(host) or _ip_trick(host_idna):
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


class PinnedAsyncBackend(httpcore.AsyncNetworkBackend):
    """Connect to the context-local public IP. The URL hostname is only for TLS."""

    def __init__(self, inner: httpcore.AsyncNetworkBackend | None = None) -> None:
        self._inner = inner or httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):  # noqa: ANN001
        chosen = pinned_ip.get()
        expected = pinned_host.get()
        if not chosen or not is_public_ip(chosen):
            raise SSRFError("destination_rejected")
        if expected and str(host).lower().rstrip(".") != expected:
            raise SSRFError("destination_rejected")
        return await self._inner.connect_tcp(chosen, port, timeout, local_address, socket_options)

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):  # noqa: ANN001
        raise SSRFError("destination_rejected")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


async def build_origin_client(*, timeout: float) -> httpx.AsyncClient:
    ssl_context = ssl.create_default_context()
    pool = httpcore.AsyncConnectionPool(
        ssl_context=ssl_context,
        max_connections=50,
        max_keepalive_connections=20,
        retries=0,
        network_backend=PinnedAsyncBackend(),
    )
    transport = httpx.AsyncHTTPTransport(retries=0, trust_env=False)
    await transport._pool.aclose()
    transport._pool = pool
    return httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        trust_env=False,
    )
