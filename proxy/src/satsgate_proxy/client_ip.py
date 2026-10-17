"""Buyer address for the proxy.

Same forwarding rule as the core: X-Forwarded-For counts only when the TCP
peer is listed in this proxy's trusted_proxies. The core applies that rule
again to X-Satsgate-Buyer-Ip, using the proxy's egress address.
"""

from __future__ import annotations

import ipaddress


def _parse_trusted(raw: str) -> tuple[set[str], list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    literals: set[str] = set()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in (raw or "").split(","):
        item = part.strip()
        if not item:
            continue
        if item in {"*", "0.0.0.0/0", "::/0"}:
            continue
        try:
            if "/" in item:
                networks.append(ipaddress.ip_network(item, strict=False))
            else:
                literals.add(str(ipaddress.ip_address(item)))
        except ValueError:
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


def resolve_client_ip(*, peer: str | None, forwarded_for: str | None, trusted_proxies: str) -> str:
    """Return the address that should own this request's buyer bucket."""
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


def buyer_ip_for_core(*, peer: str | None, forwarded_for: str | None, trusted_proxies: str) -> str | None:
    """Canonical IP to send as X-Satsgate-Buyer-Ip, or None when it is not an IP.

    A non-IP peer such as the test client is omitted. The core rejects a
    non-IP value when the caller is trusted, and ignores the header otherwise.
    """
    resolved = resolve_client_ip(peer=peer, forwarded_for=forwarded_for, trusted_proxies=trusted_proxies)
    try:
        return str(ipaddress.ip_address(resolved))
    except ValueError:
        return None
