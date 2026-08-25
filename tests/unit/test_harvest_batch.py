"""harvest_batch: выборка кандидатов из state.db (fixture-BD, read-only)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from blockchecks.harvest_batch import (
    SCHEMA,
    collect_harvest_candidates,
    render_batch_txt,
    write_confs,
)

pytestmark = pytest.mark.unit

SCHEMA_SQL = """
CREATE TABLE strategies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    proto TEXT DEFAULT 'tcp',
    config_path TEXT NOT NULL,
    first_seen TEXT,
    UNIQUE(name, proto)
);
CREATE TABLE tcp_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    strategy_id INTEGER REFERENCES strategies(id),
    domain TEXT, status TEXT, http_code INTEGER, latency_ms REAL,
    content_valid INTEGER, error TEXT, fail_phase TEXT, timestamp TEXT,
    bridge_applied INTEGER
);
CREATE TABLE quarantined (domain TEXT PRIMARY KEY, reason TEXT, failed INTEGER,
                          created TEXT);
"""


@pytest.fixture()
def db(tmp_path: Path) -> Path:
    path = tmp_path / "state.db"
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA_SQL)

    def strat(name: str, cfg: str) -> int:
        cur = conn.execute(
            "INSERT INTO strategies(name, proto, config_path) VALUES (?, 'tcp', ?)",
            (name, cfg),
        )
        conn.commit()
        return int(cur.lastrowid)  # type: ignore[arg-type]

    def res(
        sid: int,
        domain: str,
        status: str,
        ms: float,
        ts: str,
        *,
        bridge_applied: int | None = 1,
    ) -> None:
        conn.execute(
            "INSERT INTO tcp_results(strategy_id, domain, status, latency_ms,"
            " timestamp, bridge_applied)"
            " VALUES (?,?,?,?,?,?)",
            (sid, domain, status, ms, ts, bridge_applied),
        )

    s1 = strat("fake_a", "fake:blob=stun:repeats=6")
    for dom, ms in [("a.com", 100.0), ("b.com", 120.0), ("c.com", 140.0)]:
        res(s1, dom, "FAIL", 900.0, "2026-08-25T00:00:00")  # старее и по id
        res(s1, dom, "PASS", ms, "2026-08-25T01:00:00")

    # THROTTLED не входит в дефолтную выборку (только PASS)
    s2 = strat("fake_b", "fake:blob=google:repeats=5")
    res(s2, "a.com", "THROTTLED", 200.0, "2026-08-25T01:00:00")
    res(s2, "b.com", "THROTTLED", 210.0, "2026-08-25T01:00:00")

    # PASS без bridge_applied — не кандидат
    s2b = strat("no_bridge", "fake:blob=google:repeats=7")
    res(s2b, "a.com", "PASS", 150.0, "2026-08-25T01:00:00", bridge_applied=0)
    res(s2b, "b.com", "PASS", 160.0, "2026-08-25T01:00:00", bridge_applied=None)

    # один домен — отфильтрован min_domains=2
    s3 = strat("solo", "fake:solo")
    res(s3, "a.com", "PASS", 50.0, "2026-08-25T01:00:00")

    # карантинный домен: по умолчанию не исключается; --exclude-quarantined — да
    conn.execute(
        "INSERT INTO quarantined VALUES ('dead.com', '0 PASS', 500, '2026-08-25')"
    )
    s4 = strat("fake_c", "fake:blob=max_ru:repeats=4")
    res(s4, "x.com", "PASS", 300.0, "2026-08-25T01:00:00")
    res(s4, "y.com", "PASS", 310.0, "2026-08-25T01:00:00")
    res(s4, "dead.com", "PASS", 320.0, "2026-08-25T01:00:00")

    # стратегия-путь .conf → разворачивается в ядро
    conf = tmp_path / "strat.conf"
    conf.write_text(
        "--filter-tcp=443\n--lua-desync=fake:blob=b4pda:repeats=3\n",
        encoding="utf-8",
    )
    s5 = strat("from_conf", f"{conf}")
    res(s5, "q1.com", "PASS", 80.0, "2026-08-25T01:00:00")
    res(s5, "q2.com", "PASS", 90.0, "2026-08-25T01:00:00")

    # неразрешимый .conf путь — skipped_unresolved
    s6 = strat("broken_conf", "/nonexistent/zzz.conf")
    res(s6, "z1.com", "PASS", 10.0, "2026-08-25T01:00:00")
    res(s6, "z2.com", "PASS", 10.0, "2026-08-25T01:00:00")

    conn.commit()
    conn.close()
    return path


def test_grouping_latest_wins_and_rank(db: Path) -> None:
    r = collect_harvest_candidates(db, top=10, min_domains=2)
    by_name = {c.strategy: c for c in r.candidates}
    assert "fake_a" not in by_name  # имя строки ≠ стратегия; ключ — config_path core
    core_a = [c for c in r.candidates if c.strategy == "fake:blob=stun:repeats=6"]
    assert core_a, "latest PASS должен победить более старый FAIL"
    ca = core_a[0]
    assert sorted(ca.domains) == ["a.com", "b.com", "c.com"]
    assert ca.avg_latency_ms == 120.0
    # ранжирование: покрытие ↓, при равном — латентность ↑
    covs = [-c.coverage for c in r.candidates]
    assert covs == sorted(covs)


def test_min_domains_and_quarantine(db: Path) -> None:
    r = collect_harvest_candidates(db, top=10, min_domains=2)
    names = [c.strategy for c in r.candidates]
    assert all("solo" not in n for n in names)
    assert "dead.com" in render_batch_txt(r)
    assert r.quarantined_excluded == []

    r_ex = collect_harvest_candidates(
        db, top=10, min_domains=2, exclude_quarantined=True
    )
    assert "dead.com" not in render_batch_txt(r_ex)
    assert r_ex.quarantined_excluded == ["dead.com"]


def test_throttled_excluded_by_default_and_status_filter(db: Path) -> None:
    r = collect_harvest_candidates(db, top=10, min_domains=2)
    assert all(c.strategy != "fake:blob=google:repeats=5" for c in r.candidates)
    assert all(c.strategy != "fake:blob=google:repeats=7" for c in r.candidates)
    r_throttled = collect_harvest_candidates(
        db, top=10, min_domains=2, statuses=("THROTTLED",)
    )
    assert any(c.strategy == "fake:blob=google:repeats=5" for c in r_throttled.candidates)


def test_conf_path_resolved_and_broken_counted(db: Path, caplog) -> None:
    import logging

    caplog.set_level(logging.WARNING, logger="blockchecks.harvest_batch")
    r = collect_harvest_candidates(db, top=10, min_domains=2)
    assert any(c.strategy == "fake:blob=b4pda:repeats=3" for c in r.candidates)
    assert r.skipped_unresolved == 1
    assert any("broken_conf" in rec.message for rec in caplog.records)


def test_render_batch_txt_format(db: Path) -> None:
    r = collect_harvest_candidates(db, top=10, min_domains=2)
    txt = render_batch_txt(r)
    line = next(ln for ln in txt.splitlines() if "stun" in ln)
    assert " | fake:blob=stun:repeats=6" in line
    assert "," in line.split(" | ")[0]


def test_manifest_structure(db: Path) -> None:
    from blockchecks.harvest_batch import build_manifest

    r = collect_harvest_candidates(db, top=10, min_domains=2)
    m = build_manifest(r, db_path=db, proto="tcp", top=10, min_domains=2)
    assert m["schema"] == SCHEMA == "blockchecks.harvest/v1"
    assert m["source_db"] == db.name
    payload = json.dumps(m)
    assert "candidates" in payload and "domains_meta" in payload


def test_write_confs_emits_bundle(db: Path, tmp_path: Path) -> None:
    r = collect_harvest_candidates(db, top=3, min_domains=2)
    dirs = write_confs(r, tmp_path / "confs")
    assert len(dirs) == len(r.candidates)
    for d in dirs:
        conf = Path(d) / "nfqws2.conf"
        assert conf.is_file(), d
        text = conf.read_text(encoding="utf-8")
        assert "--lua-desync=" in text

def test_digital_leading_blob_renamed(db: Path) -> None:
    """seqovl_pattern=4pda → b4pda (nfqws2 падает на цифре), а не drop."""
    conn = sqlite3.connect(db)
    cur = conn.execute(
        "INSERT INTO strategies(name, proto, config_path) VALUES ('dig','tcp',?)",
        ("multisplit:pos=host+1:seqovl_pattern=4pda:badsum:ip_ttl=127",),
    )
    sid = int(cur.lastrowid or 0)
    for dom in ("m1.com", "m2.com"):
        conn.execute(
            "INSERT INTO tcp_results(strategy_id,domain,status,latency_ms,timestamp,"
            " bridge_applied)"
            " VALUES (?,?,?,50.0,'2026-08-25T01:00:00',1)",
            (sid, dom, "PASS"),
        )
    conn.commit()
    conn.close()
    r = collect_harvest_candidates(db, top=10, min_domains=2)
    assert any(
        c.strategy.startswith("multisplit:") and "seqovl_pattern=b4pda" in c.strategy
        for c in r.candidates
    ), [c.strategy for c in r.candidates]

