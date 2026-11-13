"""T-5.2 and T-5.3. Formula rows, locked debit, and the 500-unlock quota."""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

os.environ.setdefault("SATSGATE_ENV", "test")
os.environ.setdefault("SATSGATE_MACAROON_SECRET", "test-secret")

RATE_DEN = 100_000_000
# US$80,070 per BTC. US$0.001 = 1,248 msat.
_RATE_NUM = 80_070 * RATE_DEN


def setup_module() -> None:
    global db, ledger, config
    from app import config as app_config
    from app import db as app_db
    from app import ledger as app_ledger

    db = app_db
    ledger = app_ledger
    config = app_config


def _db(tmp_path: Path) -> str:
    path = str(tmp_path / "formula.sqlite3")
    db.init_db(path)
    return path


def _client(path: str, *, balance: int = 0, lightning: str | None = None) -> int:
    with db._connect(path) as conn:
        cur = conn.execute(
            """
            INSERT INTO clients(api_key_hash, credits, balance_msat, created_at, payee_lightning_address)
            VALUES(?, ?, ?, 1, ?)
            """,
            (f"h-{balance}-{lightning}-{threading.get_ident()}-{os.urandom(4).hex()}", balance // 2000, balance, lightning),
        )
        return int(cur.lastrowid)


def _challenge(path: str, client_id: int, payment_hash: str, amount_sats: int, *, fee: int | None = None, test_mode: int = 0) -> None:
    now = 1_700_000_000
    with db._connect(path) as conn:
        conn.execute(
            """
            INSERT INTO paywall_challenges(
              payment_hash, client_id, invoice, amount_sats, resource, created_at, expires_at,
              uses_consumed, satsgate_fee_msat, test_mode
            ) VALUES(?, ?, 'inv', ?, 'demo', ?, ?, 0, ?, ?)
            """,
            (payment_hash, client_id, amount_sats, now, now + 3600, fee, test_mode),
        )


def _deltas(path: str, client_id: int) -> list[int]:
    with db._connect(path) as conn:
        rows = conn.execute(
            "SELECT delta_msat FROM ledger WHERE client_id = ? AND reason = 'paywall_verify' ORDER BY id",
            (client_id,),
        ).fetchall()
    return [int(row[0]) for row in rows]


def test_t_5_2_table_and_lightning_boundaries() -> None:
    from app.pricing import item_msat_from_usd, lightning_fee_msat, usdc_fee_msat
    from app.charging import lightning_item_fee, usdc_item_fee

    assert lightning_fee_msat(10_000) == 1_000  # T-5.2.1 and T-5.2.16: 10 sats, floor not applied
    assert lightning_item_fee(10) == 1_000
    assert lightning_fee_msat(20_000) == 2_000
    assert lightning_fee_msat(21_000) == 2_000
    assert lightning_fee_msat(1_000) == 100  # T-5.2.9
    assert lightning_fee_msat(19_000) == 1_900
    usd_0005 = item_msat_from_usd(5_000, _RATE_NUM, RATE_DEN)
    assert usd_0005 == 6_244
    assert usdc_item_fee(usd_0005, rate_num=_RATE_NUM, rate_den=RATE_DEN) == 1_248
    usd_010 = item_msat_from_usd(100_000, _RATE_NUM, RATE_DEN)
    # Brief's "≈ 124,891" is the same conversion; the integer floor is 124,890.
    assert usd_010 == (100_000 * RATE_DEN * 100_000) // _RATE_NUM
    assert usd_010 == 124_890
    assert usdc_fee_msat(usd_010, 1_248) == 2_000
    usd_0001 = item_msat_from_usd(1_000, _RATE_NUM, RATE_DEN)
    assert usdc_fee_msat(usd_0001, 1_248) == 1_248
    with pytest.raises(ValueError):
        lightning_fee_msat(0)
    with pytest.raises(ValueError):
        lightning_fee_msat(-1)


def test_t_5_2_11_locked_fee_is_what_is_debited(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "FREE_QUOTA", 0)
    path = _db(tmp_path)
    client_id = _client(path, balance=50_000)
    _challenge(path, client_id, "ph-lock", 21, fee=2_000)
    # A later rate change must not recompute the debit. The row already holds 2,000.
    monkeypatch.setattr(config, "FEE_MSAT", 5_000)
    from app.db_verify import verify_once_and_spend

    first = verify_once_and_spend(path, client_id=client_id, payment_hash="ph-lock", cost=1, resource="demo")
    assert first["charged_msat"] == 2_000
    assert _deltas(path, client_id) == [-2_000]


def test_t_5_2_12_and_14_replay_and_cost_credits_are_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "FREE_QUOTA", 0)
    path = _db(tmp_path)
    client_id = _client(path, balance=50_000)
    _challenge(path, client_id, "ph-a", 10, fee=None)
    _challenge(path, client_id, "ph-b", 10, fee=None)
    from app.db_verify import verify_once_and_spend

    one = verify_once_and_spend(path, client_id=client_id, payment_hash="ph-a", cost=1, resource="demo")
    fifty = verify_once_and_spend(path, client_id=client_id, payment_hash="ph-b", cost=50, resource="demo")
    again = verify_once_and_spend(path, client_id=client_id, payment_hash="ph-a", cost=50, resource="demo")
    assert one["charged_msat"] == 1_000
    assert fifty["charged_msat"] == 1_000
    assert again["charged_msat"] == 0
    assert _deltas(path, client_id) == [-1_000, -1_000]


def test_t_5_2_13_test_mode_does_not_debit_or_count(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "FREE_QUOTA", 2)
    path = _db(tmp_path)
    client_id = _client(path, balance=10_000)
    _challenge(path, client_id, "ph-test", 21, test_mode=1)
    from app.db_verify import verify_once_and_spend
    from app.quota import free_remaining

    spent = verify_once_and_spend(path, client_id=client_id, payment_hash="ph-test", cost=0, resource="demo")
    assert spent["charged_msat"] == 0
    with db._connect(path) as conn:
        assert free_remaining(conn, client_id, 1_700_000_000) == 2
        balance = conn.execute("SELECT balance_msat FROM clients WHERE id = ?", (client_id,)).fetchone()
    assert int(balance[0]) == 10_000
    assert _deltas(path, client_id) == []


def test_t_5_2_15_each_live_debit_path_uses_the_formula(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "FREE_QUOTA", 0)
    path = _db(tmp_path)
    client_id = _client(path, balance=80_000)
    from app.db_verify import charge_after_delivery, confirm_payment, settle_and_consume, verify_once_and_spend

    _challenge(path, client_id, "ph-verify", 10)
    verify_once_and_spend(path, client_id=client_id, payment_hash="ph-verify", cost=1, resource="demo")
    _challenge(path, client_id, "ph-settle", 10)
    settle_and_consume(
        path,
        client_id=client_id,
        payment_hash="ph-settle",
        cost=1,
        resource="demo",
        api_key_id=None,
        consume=False,
        access_cap_seconds=3600,
    )
    _challenge(path, client_id, "ph-deliver", 10)
    confirm_payment(path, client_id=client_id, payment_hash="ph-deliver", cost=1, access_cap_seconds=3600)
    charge_after_delivery(path, client_id=client_id, payment_hash="ph-deliver", cost=1, resource="demo", api_key_id=None)
    assert _deltas(path, client_id) == [-1_000, -1_000, -1_000]


def test_t_5_2_17_is_the_http_challenge_not_a_helper() -> None:
    """T-5.2.17 is test_usdc_fee_is_refused_on_the_challenge_when_the_rate_is_missing."""
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    body = (root / "tests" / "test_pricing_finish.py").read_text(encoding="utf-8")
    assert "rate_unavailable" in body
    charging = (root / "app" / "charging.py").read_text(encoding="utf-8")
    assert "def strict_usdc_issue" not in charging


def test_t_5_3_1_free_then_paid(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "FREE_QUOTA", 2)
    path = _db(tmp_path)
    client_id = _client(path, balance=20_000)
    from app.db_verify import verify_once_and_spend

    for index in range(3):
        _challenge(path, client_id, f"ph-{index}", 21, fee=2_000)
        verify_once_and_spend(path, client_id=client_id, payment_hash=f"ph-{index}", cost=1, resource="demo")
    assert _deltas(path, client_id) == [-2_000]
    with db._connect(path) as conn:
        used = conn.execute("SELECT used_unlocks FROM quota_buckets").fetchone()
    assert int(used[0]) == 3


def test_t_5_3_1_boundary_at_500(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "FREE_QUOTA", 500)
    path = _db(tmp_path)
    client_id = _client(path, balance=10_000)
    now = int(datetime(2026, 11, 12, tzinfo=timezone.utc).timestamp())
    from app.quota import commit_slot, period_utc

    with db._connect(path) as conn:
        bucket = f"client:{client_id}"
        period = period_utc(now)
        conn.execute(
            "INSERT INTO quota_buckets(bucket_id, period_utc, used_unlocks) VALUES(?, ?, 499)",
            (bucket, period),
        )
        conn.execute(
            "INSERT INTO client_quota(client_id, period_utc, bucket_id, used_unlocks) VALUES(?, ?, ?, 499)",
            (client_id, period, bucket),
        )
        assert commit_slot(conn, client_id=client_id, payment_hash="free", now=now) is True
        assert commit_slot(conn, client_id=client_id, payment_hash="paid", now=now) is False
        used = conn.execute("SELECT used_unlocks FROM quota_buckets WHERE bucket_id = ?", (bucket,)).fetchone()
    assert int(used[0]) == 501


def test_t_5_3_2_quota_does_not_carry_across_utc_midnight(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "FREE_QUOTA", 500)
    path = _db(tmp_path)
    client_id = _client(path, balance=5_000)
    october = int(datetime(2026, 10, 31, 23, 59, 59, tzinfo=timezone.utc).timestamp())
    november = int(datetime(2026, 11, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp())
    from app.quota import commit_slot, free_remaining, period_utc

    with db._connect(path) as conn:
        period = period_utc(october)
        conn.execute(
            "INSERT INTO quota_buckets(bucket_id, period_utc, used_unlocks) VALUES(?, ?, 30)",
            (f"client:{client_id}", period),
        )
        conn.execute(
            "INSERT INTO client_quota(client_id, period_utc, bucket_id, used_unlocks) VALUES(?, ?, ?, 30)",
            (client_id, period, f"client:{client_id}"),
        )
        assert free_remaining(conn, client_id, october) == 470
        assert commit_slot(conn, client_id=client_id, payment_hash="nov", now=november) is True
        assert free_remaining(conn, client_id, november) == 499
        balance = conn.execute("SELECT balance_msat FROM clients WHERE id = ?", (client_id,)).fetchone()
    assert int(balance[0]) == 5_000


def test_t_5_3_3_and_4_shared_bucket_sums(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "FREE_QUOTA", 500)
    path = _db(tmp_path)
    alice = _client(path, balance=0)
    bob = _client(path, balance=0, lightning="same@pay.example")
    now = int(datetime(2026, 11, 15, tzinfo=timezone.utc).timestamp())
    from app.quota import free_remaining, period_utc, sync_membership

    period = period_utc(now)
    with db._connect(path) as conn:
        conn.execute(
            "INSERT INTO quota_buckets(bucket_id, period_utc, used_unlocks) VALUES(?, ?, 200)",
            (f"client:{alice}", period),
        )
        conn.execute(
            "INSERT INTO client_quota(client_id, period_utc, bucket_id, used_unlocks) VALUES(?, ?, ?, 200)",
            (alice, period, f"client:{alice}"),
        )
        conn.execute(
            "INSERT INTO quota_buckets(bucket_id, period_utc, used_unlocks) VALUES(?, ?, 400)",
            ("ln:same@pay.example", period),
        )
        conn.execute(
            "INSERT INTO client_quota(client_id, period_utc, bucket_id, used_unlocks) VALUES(?, ?, ?, 400)",
            (bob, period, "ln:same@pay.example"),
        )
        conn.execute("UPDATE clients SET payee_lightning_address = ? WHERE id = ?", ("same@pay.example", alice))
        sync_membership(conn, alice, now)
        used = conn.execute(
            "SELECT used_unlocks FROM quota_buckets WHERE bucket_id = ?",
            ("ln:same@pay.example",),
        ).fetchone()
        # max(200, 400) would leave 400 and the next unlock would still be free.
        assert int(used[0]) == 600
        assert free_remaining(conn, alice, now) == 0
        assert free_remaining(conn, bob, now) == 0


def test_t_5_3_6_concurrent_500th(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(config, "FREE_QUOTA", 500)
    path = _db(tmp_path)
    client_id = _client(path, balance=100_000)
    now = int(datetime(2026, 11, 12, tzinfo=timezone.utc).timestamp())
    from app.ledger import take_live_fee
    from app.quota import period_utc

    period = period_utc(now)
    with db._connect(path) as conn:
        conn.execute(
            "INSERT INTO quota_buckets(bucket_id, period_utc, used_unlocks) VALUES(?, ?, 499)",
            (f"client:{client_id}", period),
        )
        conn.execute(
            "INSERT INTO client_quota(client_id, period_utc, bucket_id, used_unlocks) VALUES(?, ?, ?, 499)",
            (client_id, period, f"client:{client_id}"),
        )
    results: list[bool] = []
    barrier = threading.Barrier(2)

    def _once(tag: str) -> None:
        barrier.wait(timeout=5)
        with db._connect(path) as conn:
            conn.execute("BEGIN IMMEDIATE")
            free = take_live_fee(
                conn,
                client_id=client_id,
                payment_hash=tag,
                fee_msat=2_000,
                reason="paywall_verify",
                resource="demo",
                api_key_id=None,
                now=now,
            )["free"]
            results.append(bool(free))

    threads = [threading.Thread(target=_once, args=(tag,)) for tag in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert sorted(results) == [False, True]
    with db._connect(path) as conn:
        used = conn.execute("SELECT used_unlocks FROM quota_buckets").fetchone()
        balance = conn.execute("SELECT balance_msat FROM clients WHERE id = ?", (client_id,)).fetchone()
        total = conn.execute("SELECT COALESCE(SUM(delta_msat), 0) FROM ledger WHERE client_id = ?", (client_id,)).fetchone()
    assert int(used[0]) == 501
    assert int(balance[0]) == 98_000
    assert int(total[0]) == -2_000


def test_t_5_3_7_reset_instant_is_utc_and_the_display_zone_is_separate() -> None:
    from app.quota import reset_displays

    moment = int(datetime(2026, 11, 12, 22, 0, tzinfo=timezone.utc).timestamp())
    utc, local = reset_displays(moment, "America/Argentina/Buenos_Aires")
    assert utc == "2026-12-01T00:00:00Z"
    assert local.startswith("2026-11-30T21:00:00")
    utc_only, shown = reset_displays(moment, "UTC")
    assert shown.startswith("2026-12-01T00:00:00")
    assert utc_only == "2026-12-01T00:00:00Z"
