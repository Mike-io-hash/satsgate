"""T-5.1 and T-5.1-M. Milisat storage, rounding, and the credit conversion tool."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from pathlib import Path

import pytest

os.environ.setdefault("SATSGATE_ENV", "test")
os.environ.setdefault("SATSGATE_MACAROON_SECRET", "test-secret")


def setup_module() -> None:
    global db, ledger, MigrationError, apply, dry_run, main, reverse
    global credit_msat_for_principal, require_int, round_down_msat, round_up_msat
    from app import db as app_db
    from app import ledger as app_ledger
    from app.migrate_credits_to_msat import MigrationError as _MigrationError
    from app.migrate_credits_to_msat import apply as _apply
    from app.migrate_credits_to_msat import dry_run as _dry_run
    from app.migrate_credits_to_msat import main as _main
    from app.migrate_credits_to_msat import reverse as _reverse
    from app.pricing import credit_msat_for_principal as _credit
    from app.pricing import require_int as _require_int
    from app.pricing import round_down_msat as _down
    from app.pricing import round_up_msat as _up

    db = app_db
    ledger = app_ledger
    MigrationError = _MigrationError
    apply = _apply
    dry_run = _dry_run
    main = _main
    reverse = _reverse
    credit_msat_for_principal = _credit
    require_int = _require_int
    round_down_msat = _down
    round_up_msat = _up

_OLD = """
CREATE TABLE clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  credits INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  delta_credits INTEGER NOT NULL,
  reason TEXT NOT NULL,
  ref TEXT,
  created_at INTEGER NOT NULL
);
"""


def _fresh(tmp_path: Path) -> str:
    path = str(tmp_path / "msat.sqlite3")
    db.init_db(path)
    return path


def _client(path: str, credits: int = 0) -> int:
    with db._connect(path) as conn:
        cur = conn.execute(
            "INSERT INTO clients(api_key_hash, credits, balance_msat, created_at) VALUES(?, ?, 0, 1)",
            (f"hash-{credits}-{threading.get_ident()}", credits),
        )
        return int(cur.lastrowid)


def _sum(path: str, client_id: int) -> int:
    with db._connect(path) as conn:
        total = conn.execute(
            "SELECT COALESCE(SUM(delta_msat), 0) FROM ledger WHERE client_id = ?",
            (client_id,),
        ).fetchone()
        balance = conn.execute("SELECT balance_msat FROM clients WHERE id = ?", (client_id,)).fetchone()
    assert int(total[0]) == int(balance[0])
    return int(balance[0])


def test_t_5_1_1_schema_rejects_a_negative_balance(tmp_path: Path) -> None:
    path = _fresh(tmp_path)
    client_id = _client(path)
    with db._connect(path) as conn:
        row = conn.execute("SELECT balance_msat FROM clients WHERE id = ?", (client_id,)).fetchone()
        assert int(row["balance_msat"]) == 0
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute("UPDATE clients SET balance_msat = -1 WHERE id = ?", (client_id,))
    with pytest.raises(ValueError, match="insufficient balance"):
        ledger.apply(path, client_id=client_id, delta_msat=-1, reason="paywall_verify", ref="x")
    with db._connect(path) as conn:
        balance = conn.execute("SELECT balance_msat FROM clients WHERE id = ?", (client_id,)).fetchone()
    assert int(balance["balance_msat"]) == 0


def test_t_5_1_2_invariant_after_topup_spends_and_refund(tmp_path: Path) -> None:
    path = _fresh(tmp_path)
    client_id = _client(path)
    ledger.apply(path, client_id=client_id, delta_msat=10_000, reason="topup_settled", ref="in")
    ledger.apply(path, client_id=client_id, delta_msat=-2_000, reason="paywall_verify", ref="a")
    ledger.apply(path, client_id=client_id, delta_msat=-3_000, reason="paywall_verify", ref="b")
    ledger.apply(path, client_id=client_id, delta_msat=2_000, reason="refund_automatic", ref="a")
    assert _sum(path, client_id) == 7_000


def test_t_5_1_3_ledger_amounts_are_ints_and_a_float_is_refused(tmp_path: Path) -> None:
    path = _fresh(tmp_path)
    client_id = _client(path)
    ledger.apply(path, client_id=client_id, delta_msat=4_000, reason="topup_settled", ref="in")
    ledger.apply(path, client_id=client_id, delta_msat=-1_500, reason="paywall_verify", ref="a")
    with db._connect(path) as conn:
        balance = conn.execute("SELECT balance_msat FROM clients WHERE id = ?", (client_id,)).fetchone()
        deltas = conn.execute("SELECT delta_msat FROM ledger WHERE client_id = ?", (client_id,)).fetchall()
    assert type(int(balance["balance_msat"])) is int
    assert type(balance["balance_msat"]) is int
    for row in deltas:
        assert type(row["delta_msat"]) is int
    with pytest.raises(TypeError):
        ledger.apply(path, client_id=client_id, delta_msat=1.5, reason="paywall_verify", ref="float")
    with pytest.raises(TypeError):
        require_int(True, "delta_msat")


def test_t_5_1_4_fee_rounds_down_and_credit_rounds_up() -> None:
    assert round_down_msat(12_489, 10) == 1_248
    assert round_up_msat(10_001, 10) == 1_001
    assert credit_msat_for_principal(1_000) == 1_000_000


def test_t_5_1_5_concurrent_spends_only_one_commits(tmp_path: Path) -> None:
    path = _fresh(tmp_path)
    client_id = _client(path)
    ledger.apply(path, client_id=client_id, delta_msat=2_000, reason="topup_settled", ref="in")
    barrier = threading.Barrier(2)
    results: list[str] = []

    def _once() -> None:
        barrier.wait(timeout=5)
        try:
            ledger.apply(path, client_id=client_id, delta_msat=-2_000, reason="paywall_verify", ref="race")
            results.append("ok")
        except ValueError as exc:
            results.append(str(exc))

    threads = [threading.Thread(target=_once) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)
    assert sorted(results) == ["insufficient balance", "ok"]
    assert _sum(path, client_id) == 0


def _legacy(path: Path, balances: dict[int, int]) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(_OLD)
    for client_id, credits in balances.items():
        conn.execute("INSERT INTO clients(id, credits) VALUES(?, ?)", (client_id, credits))
        conn.execute(
            "INSERT INTO ledger(client_id, delta_credits, reason, ref, created_at) VALUES(?, ?, 'topup_settled', ?, 1)",
            (client_id, credits, f"ref-{client_id}"),
        )
    conn.commit()
    conn.close()


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_t_5_1m_1_dry_run_does_not_write(tmp_path: Path) -> None:
    path = tmp_path / "copy.sqlite3"
    _legacy(path, {1: 0, 2: 200, 3: 576})
    before = _sha(path)
    report = dry_run(str(path))
    assert _sha(path) == before
    assert report["status"] == "dry_run"
    by_id = {row["client_id"]: row for row in report["rows"]}
    assert by_id[1] == {"client_id": 1, "old_credits": 0, "new_msat": 0}
    assert by_id[2]["new_msat"] == 400_000
    assert by_id[3]["new_msat"] == 1_152_000
    assert report["old_credits_sum"] * 2000 == report["new_msat_sum"]


def test_t_5_1m_2_apply_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "copy.sqlite3"
    _legacy(path, {1: 0, 2: 200, 3: 576})
    report = apply(str(path))
    assert report["status"] == "applied"
    conn = sqlite3.connect(path)
    balances = dict(conn.execute("SELECT id, balance_msat FROM clients"))
    deltas = list(conn.execute("SELECT delta_msat FROM ledger ORDER BY client_id"))
    stored = conn.execute("SELECT factor, checksum, completed FROM credit_migration").fetchone()
    conn.close()
    assert balances == {1: 0, 2: 400_000, 3: 1_152_000}
    assert [row[0] for row in deltas] == [0, 400_000, 1_152_000]
    assert stored[0] == 2000 and stored[2] == 1 and stored[1] == report["checksum"]
    again = apply(str(path))
    assert again["status"] == "already_migrated"
    conn = sqlite3.connect(path)
    assert dict(conn.execute("SELECT id, balance_msat FROM clients")) == balances
    conn.close()


def test_t_5_1m_3_divergent_ledger_aborts_without_writing(tmp_path: Path) -> None:
    path = tmp_path / "copy.sqlite3"
    _legacy(path, {1: 10})
    conn = sqlite3.connect(path)
    conn.execute("UPDATE ledger SET delta_credits = 4 WHERE client_id = 1")
    conn.commit()
    conn.close()
    before = path.read_bytes()
    with pytest.raises(MigrationError, match="credits 10"):
        apply(str(path))
    assert path.read_bytes() == before


def test_t_5_1m_4_reverse_then_apply_again(tmp_path: Path) -> None:
    path = tmp_path / "copy.sqlite3"
    _legacy(path, {1: 576, 2: 200})
    apply(str(path))
    undone = reverse(str(path))
    assert undone["status"] == "reversed"
    conn = sqlite3.connect(path)
    credits = dict(conn.execute("SELECT id, credits FROM clients"))
    deltas = list(conn.execute("SELECT delta_credits, delta_msat FROM ledger ORDER BY client_id"))
    completed = conn.execute("SELECT completed FROM credit_migration").fetchone()[0]
    conn.close()
    assert credits == {1: 576, 2: 200}
    assert deltas == [(576, 0), (200, 0)]
    assert completed == 0
    restored = apply(str(path))
    assert restored["status"] == "applied"
    conn = sqlite3.connect(path)
    assert dict(conn.execute("SELECT id, balance_msat FROM clients"))[1] == 1_152_000
    conn.close()


def test_t_5_1m_5_reverse_refuses_after_a_non_aligned_fee(tmp_path: Path) -> None:
    path = tmp_path / "copy.sqlite3"
    _legacy(path, {1: 576})
    apply(str(path))
    conn = sqlite3.connect(path)
    conn.execute("UPDATE clients SET balance_msat = balance_msat - 1248 WHERE id = 1")
    conn.execute(
        "INSERT INTO ledger(client_id, delta_credits, delta_msat, reason, created_at) VALUES(1, 0, -1248, 'paywall_verify', 2)"
    )
    conn.commit()
    before = dict(conn.execute("SELECT id, balance_msat FROM clients"))
    conn.close()
    with pytest.raises(MigrationError, match="not a multiple"):
        reverse(str(path))
    conn = sqlite3.connect(path)
    assert dict(conn.execute("SELECT id, balance_msat FROM clients")) == before
    conn.close()


def test_t_5_1m_6_tool_only_opens_the_path_it_is_given(tmp_path: Path) -> None:
    prod = tmp_path / "client1-prod.sqlite3"
    _legacy(prod, {1: 3})
    decoy = tmp_path / "satsgate.sqlite3"
    decoy.write_bytes(b"untouched")
    before = decoy.read_bytes()
    assert main(["--db", str(prod), "--dry-run"]) == 0
    assert decoy.read_bytes() == before
    with pytest.raises(SystemExit) as raised:
        main([])
    assert raised.value.code == 2
    source = (Path(__file__).resolve().parents[1] / "app" / "migrate_credits_to_msat.py").read_text(encoding="utf-8")
    assert "config.DB_PATH" not in source
    assert "required=True" in source
