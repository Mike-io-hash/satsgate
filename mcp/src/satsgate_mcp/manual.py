"""Pay one URL from a terminal. Human QR by default. NWC only with --nwc.

Nothing here prints the wallet URI, the API key, or the macaroon.
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from satsgate_mcp.buyer import Buyer, BuyerError
from satsgate_mcp.config import ConfigError, load_settings
from satsgate_mcp.redact import install
from satsgate_mcp.store import Store
from satsgate_mcp.urls import UrlError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Pay a Satsgate L402 URL from this machine.")
    parser.add_argument("url", help="http(s) URL that returns 402")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--body", default=None, help="Optional POST body")
    parser.add_argument(
        "--nwc",
        action="store_true",
        help="Pay with SATSGATE_MCP_NWC_URI instead of showing a QR. Budgets still apply.",
    )
    parser.add_argument("--polls", type=int, default=40, help="How many check_payment rounds after the QR")
    return parser


async def _run(argv: list[str]) -> int:
    args = _parser().parse_args(argv)
    install()
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(exc, file=sys.stderr)
        return 2
    buyer = Buyer(settings, store=Store(settings.data_dir))
    mode = "nwc" if args.nwc else "human"
    try:
        first = await buyer.pay_and_fetch(args.url, mode, args.method, args.body)
    except (BuyerError, UrlError) as exc:
        print(getattr(exc, "message", str(exc)), file=sys.stderr)
        return 1
    payload = first.payload
    if payload.get("payment_required") is not True and payload.get("ok") is True and "body" in payload:
        _print_content(payload)
        return 0
    if payload.get("error") and payload.get("action") != "pay_invoice":
        print(payload.get("detail") or payload.get("error"), file=sys.stderr)
        return 1
    print(payload.get("summary") or "")
    print(f"amount_sats: {payload.get('amount_sats')}")
    print(f"payment_hash: {payload.get('payment_hash')}")
    print(payload.get("invoice") or "")
    if payload.get("qr_text"):
        print(payload["qr_text"])
    if first.qr_png:
        path = settings.data_dir / f"invoice-{(payload.get('payment_hash') or 'pay')[:8]}.png"
        path.write_bytes(first.qr_png)
        print(f"QR image: {path}")
    if mode == "nwc":
        if payload.get("ok") and payload.get("body") is not None:
            _print_content(payload)
            return 0
        print(payload.get("detail") or "NWC payment did not return content.", file=sys.stderr)
        return 1
    payment_hash = str(payload.get("payment_hash") or "")
    print("Pay the invoice, then this process will poll. No preimage is required.")
    for _ in range(max(1, args.polls)):
        try:
            step = await buyer.check_payment(payment_hash)
        except BuyerError as exc:
            print(exc.message, file=sys.stderr)
            return 1
        body = step.payload
        if body.get("ok") and body.get("payment_required") is not True:
            _print_content(body)
            return 0
        if body.get("error") == "payment_pending":
            wait = int(body.get("retry_after_seconds") or 2)
            print(f"pending, retrying in {wait}s")
            await asyncio.sleep(wait)
            continue
        print(body.get("detail") or body.get("error"), file=sys.stderr)
        return 1
    print("Still pending. Run check_payment again with this payment_hash.", file=sys.stderr)
    return 1


def _print_content(payload: dict) -> None:
    print(f"HTTP {payload.get('status')}")
    if "body" in payload:
        print(payload["body"])
    elif payload.get("binary"):
        print("Binary response. body_base64 is in the tool result when you use the MCP server.")


def main() -> None:
    try:
        code = asyncio.run(_run(sys.argv[1:]))
    except KeyboardInterrupt:
        code = 130
    raise SystemExit(code)


if __name__ == "__main__":
    main()
