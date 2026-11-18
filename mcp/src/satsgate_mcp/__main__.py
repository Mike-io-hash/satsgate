"""stdio entrypoint: python -m satsgate_mcp"""

from __future__ import annotations

import sys

from satsgate_mcp import __version__

# One line each. Never print a value.
_ENV_HELP = (
    "SATSGATE_MCP_NWC_URI  Lightning wallet URI for NWC mode. Not a tool argument.",
    "SATSGATE_MCP_MAX_PAYMENT_SATS  Largest Lightning payment, in sats.",
    "SATSGATE_MCP_DAILY_MAX_SATS  Lightning spend cap for the day, in sats.",
    "SATSGATE_MCP_MAX_PAYMENT_USD  Largest USDC payment, in USD.",
    "SATSGATE_MCP_DAILY_MAX_USD  USDC spend cap for the day, in USD.",
    "SATSGATE_MCP_AUTO_PAY  When set, a fresh invoice inside the budget can be paid.",
    "SATSGATE_MCP_DATA_DIR  Where invoices and spend records are stored.",
    "SATSGATE_MCP_CORE_URL  Core API used by the read-only tools.",
    "SATSGATE_MCP_API_KEY  Restricted sgr_ key for the read-only merchant tools.",
    "SATSGATE_MCP_URL_ALLOWLIST  Hosts the buyer may call, comma-separated.",
    "SATSGATE_MCP_HTTP_TIMEOUT  HTTP timeout in seconds.",
    "SATSGATE_MCP_MAX_BODY_BYTES  Largest response body to read.",
    "SATSGATE_MCP_REGISTRY  Optional file or URL that replaces the public site directory.",
    "SATSGATE_MCP_GATE_HOSTS  Hosts treated as the hosted gate.",
)


def usage_text() -> str:
    lines = [
        "usage: satsgate-mcp [--help] [--version]",
        "",
        "Buyer-side MCP server. With no arguments, speak MCP on stdio.",
        "",
        "Environment variables:",
        *_ENV_HELP,
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    if args in (["--help"], ["-h"]):
        sys.stdout.write(usage_text())
        return
    if args == ["--version"]:
        sys.stdout.write(f"satsgate-mcp {__version__}\n")
        return
    if args:
        sys.stderr.write(usage_text())
        raise SystemExit(2)

    import logging

    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(name)s %(message)s")
    from satsgate_mcp.redact import install

    install()
    from satsgate_mcp.server import build_server

    build_server().run(transport="stdio")


if __name__ == "__main__":
    main()
