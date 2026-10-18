"""Buyer address for the gate.

X-Forwarded-For counts only when the TCP peer is Caddy (or another proxy
listed in SATSGATE_GATE_TRUSTED_PROXIES). The gate then sends that address to
core as X-Satsgate-Buyer-Ip. Core applies its own trusted-proxy check and
honors the header only from the gate container.
"""

from __future__ import annotations

import ipaddress


def _parse_trusted(raw: str) -> tuple[set[str], list[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    literals: set[str] = set()
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in (raw or "").split(","):
        item = part.strip()
        if not item or item in {"*", "0.0.0.0/0", "::/0"}:
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
    resolved = resolve_client_ip(peer=peer, forwarded_for=forwarded_for, trusted_proxies=trusted_proxies)
    try:
        return str(ipaddress.ip_address(resolved))
    except ValueError:
        return None
