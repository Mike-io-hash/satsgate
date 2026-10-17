"""Client IP for rate limits.

Forwarded headers are honored only when the TCP peer is a configured proxy.
Anyone else is keyed by the peer address, even if they send X-Forwarded-For.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress


def _parse_trusted(raw: str) -> tuple[set[str], list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    literals: set[str] = set()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in (raw or "").split(","):
        item = part.strip()
        if not item:
            continue
        if item in {"*", "0.0.0.0/0", "::/0"}:
            # validate_startup rejects these; ignore if one slips through.
            continue
        try:
            if "/" in item:
                networks.append(ipaddress.ip_network(item, strict=False))
            else:
                literals.add(str(ipaddress.ip_address(item)))
        except ValueError:
            # Allow an explicit non-IP peer (tests, unix sockets) as an exact match.
            if len(item) <= 64:
                literals.add(item)
    return literals, networks


def _is_trusted(
    peer: str,
    literals: set[str],
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    if peer in literals:
        return True
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(addr in network for network in networks)


def _valid_ip(value: str) -> str | None:
    text = value.strip()
    if not text:
        return None
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return None
        text = text[1:end]
    elif text.count(":") == 1 and "." in text:
        host, _, port = text.rpartition(":")
        if port.isdigit():
            text = host
    try:
        return str(ipaddress.ip_address(text.split("%", 1)[0]))
    except ValueError:
        return None


def peer_is_trusted(peer: str | None, trusted_proxies: str) -> bool:
    """True when this TCP peer may supply forwarded client addresses."""
    peer_text = (peer or "").strip() or "unknown"
    if len(peer_text) > 64:
        return False
    literals, networks = _parse_trusted(trusted_proxies)
    return _is_trusted(peer_text, literals, networks)


def buyer_ip_from_trusted_proxy(*, peer: str | None, header: str | None, trusted_proxies: str) -> str | None:
    """End-buyer IP from a proxy header.

    The header is ignored unless the TCP peer is in `trusted_proxies` (the same
    list as X-Forwarded-For). A blank header is absent. A trusted peer that
    sends a value which is not one IP raises ValueError('invalid_buyer_ip').
    The returned address is canonical; it is not yet truncated or hashed.
    """
    text = (header or "").strip()
    if not text:
        return None
    if not peer_is_trusted(peer, trusted_proxies):
        return None
    if len(text) > 128:
        raise ValueError("invalid_buyer_ip")
    ip = _valid_ip(text)
    if ip is None:
        raise ValueError("invalid_buyer_ip")
    return ip


def truncate_buyer_ip(ip: str) -> str:
    """Privacy boundary for a buyer address.

    IPv4 keeps the /24 (last octet zeroed). IPv6 keeps the /64. IPv4-mapped
    IPv6 is folded to IPv4 first so those two spellings share one bucket.
    """
    addr = ipaddress.ip_address(ip)
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    if isinstance(addr, ipaddress.IPv4Address):
        octets = str(addr).split(".")
        octets[3] = "0"
        return ".".join(octets)
    network = ipaddress.IPv6Network(f"{addr}/64", strict=False)
    return str(network.network_address)


def hash_buyer_ip(ip: str, *, secret: str) -> str:
    """HMAC-SHA256 of the truncated address, keyed by the server secret.

    The raw address is not recoverable from the digest. The same deployment
    maps a /24 or /64 to one stable bucket. A different secret does not.
    """
    truncated = truncate_buyer_ip(ip)
    return hmac.new(
        secret.encode("utf-8"),
        b"satsgate.buyer-ip.v1:" + truncated.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def resolve_client_ip(*, peer: str | None, forwarded_for: str | None, trusted_proxies: str) -> str:
    """Return the address that should own this request's anonymous rate-limit bucket."""
    peer_text = (peer or "").strip() or "unknown"
    if len(peer_text) > 64:
        peer_text = "unknown"

    literals, networks = _parse_trusted(trusted_proxies)
    if not _is_trusted(peer_text, literals, networks):
        return peer_text

    parts = [part.strip() for part in (forwarded_for or "").split(",") if part.strip()]
    for hop in reversed(parts):
        ip = _valid_ip(hop)
        if ip is None:
            continue
        if not _is_trusted(ip, literals, networks):
            return ip
    return peer_text
