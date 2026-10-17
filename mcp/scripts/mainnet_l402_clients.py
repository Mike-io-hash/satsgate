"""Show that a live satsgate-proxy 402 is shaped for lnget and Alby fetch402.

This script does not pay. Run it on your machine against a proxy you control:

    python mcp/scripts/mainnet_l402_clients.py https://your-proxy.example/blog/post

It prints the WWW-Authenticate header, whether the lnget and fetch402 parsers accept it,
and the commands that do spend sats. CI never runs this against mainnet.
"""

from __future__ import annotations

import sys

import httpx

from satsgate_mcp.clients import fetch402_global_strip_keeps_macaroon, parse_fetch402, parse_lnget


def main() -> None:
    if len(sys.argv) != 2:
        print(
            "Usage: python mcp/scripts/mainnet_l402_clients.py <url>\n"
            "The URL should be a satsgate-proxy route. This command does not pay.",
            file=sys.stderr,
        )
        raise SystemExit(2)
    url = sys.argv[1]
    try:
        response = httpx.get(url, timeout=20, follow_redirects=False, trust_env=False)
    except httpx.HTTPError as exc:
        print(f"Request failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1) from None
    header = response.headers.get("www-authenticate", "")
    print(f"HTTP {response.status_code}")
    print(header)
    lnget = parse_lnget(header)
    fetch402 = parse_fetch402(header)
    print(f"lnget parser: {'match' if lnget else 'no match'}")
    print(f"fetch402 parser: {'match' if fetch402 else 'no match'}")
    if lnget and fetch402 and lnget[0] == fetch402[0] and lnget[1] == fetch402[1]:
        print("both parsers agree on the macaroon and the invoice")
        kept = fetch402_global_strip_keeps_macaroon(header, lnget[0])
        print(f"macaroon survives an L402/LSAT global strip: {kept}")
    print()
    print("To pay from this machine (these commands spend sats):")
    print(f"  lnget {url}")
    print(f"  node mcp/scripts/fetch402.mjs {url}")
    print("lnget retries with Authorization: L402 <macaroon>:<preimage>.")
    print("fetch402 does the same. A phone wallet that does not return a preimage")
    print("should pay the invoice and then retry with Authorization: L402 <macaroon>.")


if __name__ == "__main__":
    main()
