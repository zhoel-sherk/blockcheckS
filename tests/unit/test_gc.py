"""Retention / bs gc dry-run plan."""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

import pytest

from blockchecks.engine.gc import apply_gc, collect_gc, prune_db_results, prune_nfqws2_debug_logs


@pytest.mark.unit
def test_prune_nfqws2_keeps_newest(tmp_path: Path, monkeypatch) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    for i in range(5):
        p = logs / f"nfqws2_run_{i}.log"
        p.write_text("x")
        p.touch()
    # oldest first names 0..4; prune keep=2
    deleted = prune_nfqws2_debug_logs(logs, keep=2)
    remain = sorted(p.name for p in logs.glob("nfqws2_*.log"))
    assert len(remain) == 2
    assert len(deleted) == 3
    assert "week_cov" not in "".join(remain)


@pytest.mark.unit
def test_prune_skips_week_cov_name(tmp_path: Path) -> None:
    logs = tmp_path / "logs"
    logs.mkdir()
    week = logs / "nfqws2_week_cov_old.log"
    week.write_text("x")
    os.utime(week, (1, 1))
    newest = logs / "nfqws2_new.log"
    newest.write_text("y")
    prune_nfqws2_debug_logs(logs, keep=1)
    assert week.exists()
    assert newest.exists()


@pytest.mark.unit
def test_collect_gc_and_dry_run(tmp_path: Path, monkeypatch) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    old = cache / "bs_voice_cache_old_20200101.json"
    old.write_text("{}")
    dl = cache / "zapret2-dl"
    dl.mkdir()
    (dl / "zapret2-v1.tar.gz").write_bytes(b"aa")
    (dl / "zapret2-v2.tar.gz").write_bytes(b"bb")
    os.utime(dl / "zapret2-v1.tar.gz", (1, 1))
    os.utime(dl / "zapret2-v2.tar.gz", (2, 2))
    export = tmp_path / "export"
    harvest = export / "harvest" / "harvest_old"
    harvest.mkdir(parents=True)
    (harvest / "batch.txt").write_text("x")
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "run_summary_20200101.json").write_text("{}")
    (logs / "week_cov_export.conf").write_text("keep")

    monkeypatch.setattr("blockchecks.engine.gc.CACHE_DIR", cache)
    monkeypatch.setattr("blockchecks.engine.gc.DEFAULT_OUT_DIR", export)
    monkeypatch.setattr("blockchecks.engine.gc.RUNTIME_LOGS_DIR", logs)
    monkeypatch.setattr("blockchecks.engine.gc.DATA_DIR", tmp_path / "data")

    plan = collect_gc(max_age_days=0, nfqws2_keep=50, roots=[logs, export, cache])
    reasons = {i.reason for i in plan.deletes}
    assert "voice_cache_old" in reasons
    assert "run_summary_age" in reasons
    assert "harvest_dir_age" in reasons
    apply_gc(plan, dry_run=True)
    assert old.exists()
    apply_gc(plan, dry_run=False)
    assert not old.exists()
    assert not harvest.exists()


@pytest.mark.unit
def test_collect_gc_tmp_shm_wal(tmp_path: Path, monkeypatch) -> None:
  logs = tmp_path / "logs"
  logs.mkdir()
  (logs / "events_live.1234.jsonl.old").write_text("x")
  state = tmp_path / "state"
  state.mkdir()
  (state / "state.db-wal").write_text("wal")
  (state / "state.db-shm").write_text("shm")
  os.utime(state / "state.db-wal", (1, 1))
  os.utime(state / "state.db-shm", (1, 1))

  tmp_dir = tmp_path / "tmp"
  tmp_dir.mkdir()
  (tmp_dir / "bs_nfq_abc.conf").write_text("c")
  (tmp_dir / "bs_hostlist_abc.txt").write_text("h")
  os.utime(tmp_dir / "bs_nfq_abc.conf", (1, 1))
  os.utime(tmp_dir / "bs_hostlist_abc.txt", (1, 1))

  shm = tmp_path / "shm" / "blockchecks" / "bs-p-0001-ns0"
  staging = shm / ".staging.42"
  staging.mkdir(parents=True)
  (staging / "strategy.id").write_text("1")
  os.utime(staging, (1, 1))

  monkeypatch.setattr("blockchecks.engine.gc._TMP_DIR", tmp_dir)
  monkeypatch.setattr("blockchecks.engine.gc._SHM_BLOCKCHECKS", tmp_path / "shm" / "blockchecks")
  monkeypatch.setattr("blockchecks.engine.gc.RUNTIME_LOGS_DIR", logs)
  monkeypatch.setattr("blockchecks.engine.gc.STATE_DIR", state)
  monkeypatch.setattr("blockchecks.engine.gc.DATA_DIR", tmp_path / "data")
  monkeypatch.setattr("blockchecks.engine.gc.CACHE_DIR", tmp_path / "cache")
  monkeypatch.setattr("blockchecks.engine.gc._has_live_run_lock", lambda: False)

  plan = collect_gc(max_age_days=0, roots=[logs])
  reasons = {i.reason for i in plan.deletes}
  assert "events_live_old" in reasons
  assert "sqlite_wal" in reasons
  assert "sqlite_shm" in reasons
  assert "tmp_nfqws2_artifact" in reasons
  assert "shm_staging_age" in reasons


@pytest.mark.unit
def test_collect_gc_skips_shm_when_live_run(tmp_path: Path, monkeypatch) -> None:
  shm = tmp_path / "shm" / "blockchecks" / "orphan"
  staging = shm / ".staging.1"
  staging.mkdir(parents=True)
  (staging / "x").write_text("y")
  os.utime(staging, (1, 1))

  monkeypatch.setattr("blockchecks.engine.gc._SHM_BLOCKCHECKS", tmp_path / "shm" / "blockchecks")
  monkeypatch.setattr("blockchecks.engine.gc._has_live_run_lock", lambda: True)

  plan = collect_gc(max_age_days=0, roots=[])
  assert not any(i.reason == "shm_staging_age" for i in plan.deletes)


def _seed_results_db(path: Path) -> None:
    now_ms = int(time.time() * 1000)
    old_ms = now_ms - 10 * 86400 * 1000
    with sqlite3.connect(str(path)) as con:
        con.executescript(
            """
            CREATE TABLE strategies (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                proto TEXT NOT NULL DEFAULT 'tcp',
                config_path TEXT NOT NULL,
                first_seen TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE tcp_results (
                id INTEGER PRIMARY KEY,
                strategy_id INTEGER,
                domain TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT '',
                epoch_ms INTEGER
            );
            CREATE TABLE udp_results (
                id INTEGER PRIMARY KEY,
                strategy_id INTEGER,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                timestamp TEXT NOT NULL DEFAULT '',
                epoch_ms INTEGER
            );
            """
        )
        con.executemany(
            "INSERT INTO strategies (id, name, proto, config_path) VALUES (?,?,?,?)",
            [
                (1, "keep_recent", "tcp", "a.conf"),
                (2, "old_only", "tcp", "b.conf"),
                (3, "already_orphan", "tcp", "c.conf"),
            ],
        )
        con.execute(
            "INSERT INTO tcp_results (strategy_id, domain, status, timestamp, epoch_ms) "
            "VALUES (1,'a.com','PASS','2026-08-26T00:00:00',?)",
            (now_ms,),
        )
        con.execute(
            "INSERT INTO tcp_results (strategy_id, domain, status, timestamp, epoch_ms) "
            "VALUES (2,'b.com','FAIL','2020-01-01T00:00:00',?)",
            (old_ms,),
        )
        con.execute(
            "INSERT INTO tcp_results (strategy_id, domain, status, timestamp, epoch_ms) "
            "VALUES (2,'b.com','FAIL','2020-01-02T00:00:00', NULL)",
        )
        con.execute(
            "INSERT INTO udp_results (strategy_id, target, status, timestamp, epoch_ms) "
            "VALUES (2,'voice:50000','FAIL','2020-01-01T00:00:00',?)",
            (old_ms,),
        )


@pytest.mark.unit
def test_prune_db_dry_run_counts_does_not_delete(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    _seed_results_db(db)
    stats = prune_db_results(db, max_age_days=7, dry_run=True, live_run=False)
    assert stats.tcp_rows == 2
    assert stats.udp_rows == 1
    assert stats.skipped_lock is False
    with sqlite3.connect(str(db)) as con:
        assert con.execute("SELECT COUNT(*) FROM tcp_results").fetchone()[0] == 3
        assert con.execute("SELECT COUNT(*) FROM udp_results").fetchone()[0] == 1


@pytest.mark.unit
def test_prune_db_apply_deletes_aged_keeps_recent(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    _seed_results_db(db)
    stats = prune_db_results(db, max_age_days=7, dry_run=False, live_run=False)
    assert stats.tcp_rows == 2
    assert stats.udp_rows == 1
    with sqlite3.connect(str(db)) as con:
        tcp = con.execute("SELECT strategy_id FROM tcp_results").fetchall()
        assert tcp == [(1,)]
        assert con.execute("SELECT COUNT(*) FROM udp_results").fetchone()[0] == 0
        names = {r[0] for r in con.execute("SELECT name FROM strategies")}
        assert names == {"keep_recent", "old_only", "already_orphan"}


@pytest.mark.unit
def test_prune_db_orphan_strategies(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    _seed_results_db(db)
    stats = prune_db_results(
        db,
        max_age_days=7,
        dry_run=False,
        orphan_strategies=True,
        live_run=False,
    )
    assert stats.orphan_strategies == 2
    with sqlite3.connect(str(db)) as con:
        names = [r[0] for r in con.execute("SELECT name FROM strategies ORDER BY id")]
        assert names == ["keep_recent"]


@pytest.mark.unit
def test_prune_db_skips_delete_when_run_lock_held(tmp_path: Path) -> None:
    db = tmp_path / "state.db"
    _seed_results_db(db)
    stats = prune_db_results(
        db,
        max_age_days=7,
        dry_run=False,
        orphan_strategies=True,
        live_run=True,
    )
    assert stats.skipped_lock is True
    assert stats.tcp_rows == 2
    with sqlite3.connect(str(db)) as con:
        assert con.execute("SELECT COUNT(*) FROM tcp_results").fetchone()[0] == 3
        assert con.execute("SELECT COUNT(*) FROM strategies").fetchone()[0] == 3


@pytest.mark.unit
def test_cmd_gc_db_days_dry_run(tmp_path: Path, monkeypatch, capsys) -> None:
    import argparse

    from blockchecks.cli.commands.gc import cmd_gc

    db = tmp_path / "state.db"
    _seed_results_db(db)
    monkeypatch.setattr("blockchecks.engine.gc.CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr("blockchecks.engine.gc.DEFAULT_OUT_DIR", tmp_path / "export")
    monkeypatch.setattr("blockchecks.engine.gc.RUNTIME_LOGS_DIR", tmp_path / "logs")
    monkeypatch.setattr("blockchecks.engine.gc.DATA_DIR", tmp_path / "data")
    (tmp_path / "cache").mkdir()
    (tmp_path / "export").mkdir()
    (tmp_path / "logs").mkdir()
    ns = argparse.Namespace(
        apply=False,
        max_age_days=14,
        nfqws2_keep=50,
        db_days=7,
        orphan_strategies=False,
        db=str(db),
    )
    assert cmd_gc(ns) == 0
    assert "re-run with --apply to delete" in capsys.readouterr().out
    with sqlite3.connect(str(db)) as con:
        assert con.execute("SELECT COUNT(*) FROM tcp_results").fetchone()[0] == 3


@pytest.mark.unit
def test_gc_cli_parses_db_days() -> None:
    from blockchecks.cli.cliapp import build_command_registry, parse_cli_subcommand

    build_command_registry({})
    sub = parse_cli_subcommand(
        ["gc", "--db-days", "14", "--orphan-strategies", "--db", "/tmp/gc-test.db"]
    )
    assert sub.db_days == 14.0
    assert sub.orphan_strategies is True
    assert sub.db == "/tmp/gc-test.db"
    assert sub.apply is False
