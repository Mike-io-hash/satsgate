"""Local OFAC screen for EVM payees. Fail-open when the file is missing.

Core never downloads the list. A missing file is reported on the admin view
and once in the log. A file older than 7 days is stale and still used.
On reload, a verified payee that is now listed is flagged, its sites lose
x402, and a confirmed alert address is mailed. The full address is not logged.
"""

from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from . import config
from .email_templates import shorten_evm

log = logging.getLogger("satsgate.ofac")
_STALE_SECONDS = 7 * 24 * 60 * 60
_lock = threading.Lock()
_addresses: frozenset[str] = frozenset()
_mtime: float | None = None
_generated = ""
_state = "missing"
_missing_logged = False


def _parse(text: str) -> tuple[frozenset[str], str]:
    found: set[str] = set()
    generated = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if "generated=" in stripped:
                generated = stripped.split("generated=", 1)[1].split()[0]
            continue
        if stripped.startswith("0x") and len(stripped) == 42:
            found.add(stripped.lower())
    return frozenset(found), generated


def refresh() -> str:
    global _addresses, _mtime, _generated, _state, _missing_logged
    path = Path(config.OFAC_EVM_FILE)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        with _lock:
            _addresses = frozenset()
            _mtime = None
            _generated = ""
            _state = "missing"
            if not _missing_logged:
                log.warning("ofac_list: missing")
                _missing_logged = True
        return "missing"
    with _lock:
        if _mtime == mtime and _state in {"ok", "stale"}:
            return _state
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            _state = "missing"
            if not _missing_logged:
                log.warning("ofac_list: missing")
                _missing_logged = True
            return "missing"
        addresses, generated = _parse(text)
        changed = addresses != _addresses
        previous = _addresses
        _addresses = addresses
        _mtime = mtime
        _generated = generated
        _missing_logged = False
        age = time.time() - mtime
        _state = "stale" if age > _STALE_SECONDS else "ok"
        stamp = _state
        listed_now = addresses
    if changed and listed_now != previous:
        _flag_matches(listed_now)
    return stamp


def listed(address: str) -> bool:
    refresh()
    if _state == "missing":
        return False
    return address.lower() in _addresses


def status() -> dict:
    refresh()
    body = {"ofac_list": _state, "ofac_count": len(_addresses)}
    if _generated:
        body["ofac_generated"] = _generated
    return body


def _flag_matches(addresses: frozenset[str]) -> None:
    if not addresses:
        return
    from . import db_x402, email_send

    now = int(time.time())
    for row in db_x402.verified_payees(config.DB_PATH):
        address = row.get("address")
        if not isinstance(address, str) or address.lower() not in addresses or row.get("flagged_at"):
            continue
        queued = db_x402.flag_payee(config.DB_PATH, client_id=int(row["client_id"]), now=now)
        log.warning(
            "payee flagged by OFAC screen client=%s address=%s",
            row["client_id"],
            shorten_evm(address),
        )
        if getattr(queued, "email", False):
            email_send.notify()
        if getattr(queued, "webhook", False):
            from . import webhook_send

            webhook_send.notify()
