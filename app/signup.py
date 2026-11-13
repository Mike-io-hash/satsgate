"""Account creation caps. Shared by POST /v1/accounts and a Lightning top-up that mints a key.

Counters live in the database so two workers cannot each accept the daily maximum.
The day is UTC. A refused call rolls the increment back with the transaction.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from . import config
from .db import _connect, _insert_client


class SignupLimited(Exception):
    def __init__(self, code: str, retry_after: int) -> None:
        super().__init__(code)
        self.code = code
        self.retry_after = max(1, int(retry_after))


def current_time() -> int:
    return int(time.time())


def utc_day(now: int) -> str:
    moment = datetime.fromtimestamp(int(now), tz=timezone.utc)
    return moment.strftime("%Y-%m-%d")


def seconds_until_next_utc_day(now: int) -> int:
    moment = datetime.fromtimestamp(int(now), tz=timezone.utc)
    nxt = datetime(moment.year, moment.month, moment.day, tzinfo=timezone.utc) + timedelta(days=1)
    return max(1, int(nxt.timestamp()) - int(now))


def _count(conn, scope: str, day: str) -> int:
    row = conn.execute(
        "SELECT n FROM signup_daily WHERE scope = ? AND day_utc = ?",
        (scope, day),
    ).fetchone()
    return 0 if row is None else int(row["n"])


def _bump(conn, scope: str, day: str) -> int:
    conn.execute(
        """
        INSERT INTO signup_daily(scope, day_utc, n) VALUES(?, ?, 1)
        ON CONFLICT(scope, day_utc) DO UPDATE SET n = n + 1
        """,
        (scope, day),
    )
    return _count(conn, scope, day)


def room_for_signup(conn, *, ip: str | None, now: int) -> None:
    """Refuse before an invoice is minted when the counters are already full."""
    day = utc_day(now)
    retry = seconds_until_next_utc_day(now)
    if ip and _count(conn, f"ip:{ip}", day) >= int(config.SIGNUP_MAX_PER_IP_PER_DAY):
        raise SignupLimited("signup_ip_limit", retry)
    if _count(conn, "global", day) >= int(config.SIGNUP_MAX_GLOBAL_PER_DAY):
        raise SignupLimited("signup_global_limit", retry)


def consume_signup(conn, *, ip: str | None, now: int) -> None:
    """Count one new account. Caller holds the write transaction and rolls it back on error."""
    day = utc_day(now)
    retry = seconds_until_next_utc_day(now)
    ip_n = _bump(conn, f"ip:{ip}", day) if ip else 0
    global_n = _bump(conn, "global", day)
    if ip and ip_n > int(config.SIGNUP_MAX_PER_IP_PER_DAY):
        raise SignupLimited("signup_ip_limit", retry)
    if global_n > int(config.SIGNUP_MAX_GLOBAL_PER_DAY):
        raise SignupLimited("signup_global_limit", retry)


def create_account(db_path: str, *, ip: str | None, now: int | None = None) -> tuple[str, int]:
    """Insert one client inside the signup counters. Returns the one-time key and the id."""
    now = current_time() if now is None else int(now)
    with _connect(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE")
        try:
            consume_signup(conn, ip=ip, now=now)
            api_key, client_id = _insert_client(conn, now)
        except SignupLimited:
            conn.execute("ROLLBACK")
            raise
        conn.execute("COMMIT")
    return api_key, client_id
