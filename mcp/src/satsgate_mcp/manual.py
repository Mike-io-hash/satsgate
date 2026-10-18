"""Pay one URL from a terminal. Human QR by default. NWC only with --nwc.

Nothing here prints the wallet URI, the API key, or the macaroon.
Polling waits until the invoice expires, unless --polls or --timeout says otherwise.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import re
import shlex
import sys
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from satsgate_mcp.buyer import Buyer, BuyerError
from satsgate_mcp.config import ConfigError, load_settings
from satsgate_mcp.redact import install
from satsgate_mcp.store import Store
from satsgate_mcp.urls import UrlError

_BACKOFF_START = 2
_BACKOFF_CAP = 15
_HASH = re.compile(r"^[0-9a-fA-F]{64}$")
_LOG_STAMP = "%Y-%m-%dT%H:%M:%SZ"


@dataclass(frozen=True)
class PollResult:
    status: str
    reason: str
    checks: int
    waits: tuple[int, ...]
    payload: dict


def poll_wait_seconds(attempt: int, retry_after: object) -> int:
    """Seconds to wait after check number `attempt` (0 on the first wait).

    The wait starts at 2 seconds and grows by one second up to 15.
    A larger Retry-After is kept, still capped at 15. A smaller hint does not shorten the wait.
    """
    grown = min(_BACKOFF_CAP, _BACKOFF_START + max(0, attempt))
    if isinstance(retry_after, bool) or not isinstance(retry_after, int):
        return grown
    if retry_after > grown:
        return min(_BACKOFF_CAP, retry_after)
    return grown


def resume_command(data_dir: Path | str, payment_hash: str) -> str:
    return (
        f"SATSGATE_MCP_DATA_DIR={shlex.quote(str(data_dir))} "
        f"python -m satsgate_mcp.manual --resume {shlex.quote(payment_hash)}"
    )


def format_log_line(message: str, *, now: Callable[[], float] | None = None) -> str:
    moment = int(time.time() if now is None else now())
    stamp = datetime.fromtimestamp(moment, tz=timezone.utc).strftime(_LOG_STAMP)
    return f"{stamp} {message}"


def configure_manual_logging() -> None:
    install()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s", datefmt=_LOG_STAMP)
    formatter.converter = time.gmtime
    named = logging.getLogger("satsgate_mcp")
    for handler in named.handlers:
        handler.setFormatter(formatter)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Pay a Satsgate L402 URL from this machine.")
    parser.add_argument("url", nargs="?", help="http(s) URL that returns 402")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--body", default=None, help="Optional POST body")
    parser.add_argument(
        "--nwc",
        action="store_true",
        help="Pay with SATSGATE_MCP_NWC_URI instead of showing a QR. Budgets still apply.",
    )
    parser.add_argument(
        "--resume",
        default=None,
        metavar="PAYMENT_HASH",
        help="Keep polling a payment_hash already stored in SATSGATE_MCP_DATA_DIR.",
    )
    parser.add_argument(
        "--polls",
        type=int,
        default=None,
        help="Optional cap on check_payment rounds. Default: poll until the invoice expires.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Optional cap in seconds, counted from the start of polling. Default: invoice expiry only.",
    )
    return parser


def _positive(name: str, value: int | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool) or value < 1:
        return f"{name} must be at least 1."
    return None


def _expiry_for(store: Store, payment_hash: str) -> int | None:
    row = store.quote_by_hash(payment_hash)
    if row is not None and row["invoice_expires_at"] is not None:
        return int(row["invoice_expires_at"])
    token = store.token_by_hash(payment_hash)
    if token is not None and token["invoice_expires_at"] is not None:
        return int(token["invoice_expires_at"])
    return None


def _stored_resume(store: Store, payment_hash: str) -> dict:
    row = store.quote_by_hash(payment_hash)
    if row is not None:
        return {
            "kind": "quote",
            "amount_sats": row["amount_sats"],
            "invoice": row["invoice"],
            "invoice_expires_at": None if row["invoice_expires_at"] is None else int(row["invoice_expires_at"]),
        }
    token = store.token_by_hash(payment_hash)
    if token is not None:
        return {
            "kind": "token",
            "amount_sats": token["amount_sats"],
            "invoice": None,
            "invoice_expires_at": None if token["invoice_expires_at"] is None else int(token["invoice_expires_at"]),
        }
    return {}


def _is_paid(payload: dict) -> bool:
    return bool(payload.get("ok")) and payload.get("payment_required") is not True


async def poll_until(
    check: Callable[[], Awaitable[dict]],
    *,
    expires_at: int | None,
    polls: int | None,
    timeout: int | None,
    now: Callable[[], float],
    sleep: Callable[[int], Awaitable[None]],
    log: Callable[[str], None],
) -> PollResult:
    """Poll until the invoice is paid or a bound is hit.

    Bounds are invoice expiry, `--polls`, and `--timeout`. The first one reached stops the loop.
    A sleep that would run past expiry or the timeout is shortened, then one more check runs,
    so a payment that landed during that last sleep is still collected.
    """
    started = int(now())
    attempt = 0
    waits: list[int] = []
    payload: dict = {}
    last_check = False

    while True:
        current = int(now())
        elapsed = current - started
        if not last_check and attempt > 0:
            if timeout is not None and elapsed >= timeout:
                return PollResult("pending", "timeout", attempt, tuple(waits), payload)
            if expires_at is not None and current >= expires_at:
                return PollResult("pending", "expired", attempt, tuple(waits), payload)
        if polls is not None and attempt >= polls:
            return PollResult("pending", "polls", attempt, tuple(waits), payload)

        payload = await check()
        attempt += 1
        last_check = False
        if _is_paid(payload):
            return PollResult("paid", "paid", attempt, tuple(waits), payload)
        if payload.get("error") != "payment_pending":
            return PollResult("error", "error", attempt, tuple(waits), payload)

        if polls is not None and attempt >= polls:
            return PollResult("pending", "polls", attempt, tuple(waits), payload)
        current = int(now())
        elapsed = current - started
        if timeout is not None and elapsed >= timeout:
            return PollResult("pending", "timeout", attempt, tuple(waits), payload)
        if expires_at is not None and current >= expires_at:
            return PollResult("pending", "expired", attempt, tuple(waits), payload)

        wait = poll_wait_seconds(attempt - 1, payload.get("retry_after_seconds"))
        room: list[int] = []
        if expires_at is not None:
            room.append(expires_at - current)
        if timeout is not None:
            room.append(timeout - elapsed)
        if room:
            nearest = min(room)
            if nearest <= 0:
                reason = "expired" if expires_at is not None and current >= expires_at else "timeout"
                return PollResult("pending", reason, attempt, tuple(waits), payload)
            if wait >= nearest:
                wait = nearest
                last_check = True
        waits.append(wait)
        log(f"pending, retrying in {wait}s")
        await sleep(wait)


def _emit(message: str, *, now: Callable[[], float]) -> None:
    print(format_log_line(message, now=now), flush=True)


def _give_up(data_dir: Path, payment_hash: str, reason: str, *, now: Callable[[], float]) -> None:
    print(format_log_line(f"Stopped ({reason}). Resume with:", now=now), file=sys.stderr)
    print(resume_command(data_dir, payment_hash), file=sys.stderr)


async def _run(
    argv: list[str],
    *,
    buyer: Buyer | None = None,
    now: Callable[[], float] | None = None,
    sleep: Callable[[int], Awaitable[None]] | None = None,
) -> int:
    args = _parser().parse_args(argv)
    if args.resume and args.url:
        print("Pass a URL or --resume, not both.", file=sys.stderr)
        return 2
    if args.nwc and args.resume:
        print("--nwc cannot be combined with --resume.", file=sys.stderr)
        return 2
    if not args.resume and not args.url:
        print("Pass a URL, or --resume PAYMENT_HASH.", file=sys.stderr)
        return 2
    for name, value in (("--polls", args.polls), ("--timeout", args.timeout)):
        problem = _positive(name, value)
        if problem:
            print(problem, file=sys.stderr)
            return 2
    if args.resume is not None and not _HASH.fullmatch(args.resume):
        print("payment_hash must be 64 hex characters.", file=sys.stderr)
        return 1

    configure_manual_logging()
    clock = now or (lambda: int(time.time()))
    if buyer is None:
        try:
            settings = load_settings()
        except ConfigError as exc:
            print(exc, file=sys.stderr)
            return 2
        buyer = Buyer(settings, store=Store(settings.data_dir))
    pauser = sleep or _wall_sleep

    if args.resume:
        payment_hash = args.resume.lower()
        stored = _stored_resume(buyer.store, payment_hash)
        if not stored:
            print(
                f"No stored invoice uses that payment_hash. SATSGATE_MCP_DATA_DIR is {buyer.settings.data_dir}.",
                file=sys.stderr,
            )
            return 1
        expires = stored["invoice_expires_at"]
        _emit(f"resuming {payment_hash}", now=clock)
        _emit(f"amount_sats: {stored['amount_sats']}", now=clock)
        if stored["invoice"]:
            print(stored["invoice"])
        return await _watch(buyer, payment_hash, expires, args, clock, pauser)

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
    _emit(payload.get("summary") or "Pay this invoice.", now=clock)
    _emit(f"amount_sats: {payload.get('amount_sats')}", now=clock)
    _emit(f"payment_hash: {payload.get('payment_hash')}", now=clock)
    print(payload.get("invoice") or "")
    if payload.get("qr_text"):
        print(payload["qr_text"])
    if first.qr_png:
        path = buyer.settings.data_dir / f"invoice-{(payload.get('payment_hash') or 'pay')[:8]}.png"
        path.write_bytes(first.qr_png)
        _emit(f"QR image: {path}", now=clock)
    if mode == "nwc":
        if payload.get("ok") and payload.get("body") is not None:
            _print_content(payload)
            return 0
        print(payload.get("detail") or "NWC payment did not return content.", file=sys.stderr)
        return 1
    payment_hash = str(payload.get("payment_hash") or "")
    if not _HASH.fullmatch(payment_hash):
        print("The 402 did not include a payment_hash.", file=sys.stderr)
        return 1
    expires = payload.get("invoice_expires_at")
    if not isinstance(expires, int) or isinstance(expires, bool):
        expires = _expiry_for(buyer.store, payment_hash.lower())
    _emit("Pay the invoice. This process polls until it expires. No preimage is required.", now=clock)
    return await _watch(buyer, payment_hash.lower(), expires, args, clock, pauser)


async def _watch(buyer: Buyer, payment_hash: str, expires: int | None, args, clock, pauser) -> int:
    async def check() -> dict:
        step = await buyer.check_payment(payment_hash)
        return step.payload

    try:
        result = await poll_until(
            check,
            expires_at=expires,
            polls=args.polls,
            timeout=args.timeout,
            now=clock,
            sleep=pauser,
            log=lambda message: _emit(message, now=clock),
        )
    except BuyerError as exc:
        print(exc.message, file=sys.stderr)
        return 1
    if result.status == "paid":
        _print_content(result.payload)
        return 0
    if result.reason == "error":
        print(result.payload.get("detail") or result.payload.get("error"), file=sys.stderr)
        _give_up(buyer.settings.data_dir, payment_hash, "error", now=clock)
        return 1
    _give_up(buyer.settings.data_dir, payment_hash, result.reason, now=clock)
    return 1


def _print_content(payload: dict) -> None:
    print(f"HTTP {payload.get('status')}")
    if "body" in payload:
        print(payload["body"])
    elif payload.get("binary"):
        print("Binary response. body_base64 is in the tool result when you use the MCP server.")


async def _wall_sleep(seconds: int) -> None:
    await asyncio.sleep(seconds)


def main() -> None:
    try:
        code = asyncio.run(_run(sys.argv[1:]))
    except KeyboardInterrupt:
        code = 130
    raise SystemExit(code)


if __name__ == "__main__":
    main()
