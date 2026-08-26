"""SQLite DDL and migrations for the run-state store."""

from __future__ import annotations

import aiosqlite

INIT_SCRIPT = """
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL DEFAULT '',
    code_version TEXT NOT NULL DEFAULT '',
    args_hash TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL DEFAULT '',
    impersonate TEXT NOT NULL DEFAULT '',
    nfqws2_version TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS strategies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    proto TEXT NOT NULL DEFAULT 'tcp',
    config_path TEXT NOT NULL,
    first_seen TEXT NOT NULL DEFAULT '',
    UNIQUE(name, proto)
);
CREATE TABLE IF NOT EXISTS tcp_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES runs(id),
    strategy_id INTEGER REFERENCES strategies(id),
    domain TEXT NOT NULL,
    status TEXT NOT NULL,
    http_code INTEGER DEFAULT 0,
    latency_ms REAL DEFAULT 0,
    gateway_ws_ms REAL DEFAULT 0,
    content_valid INTEGER DEFAULT 0,
    read_rate_bps REAL DEFAULT 0,
    error TEXT DEFAULT '',
    fail_phase TEXT DEFAULT '',
    timestamp TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS udp_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES runs(id),
    strategy_id INTEGER REFERENCES strategies(id),
    target TEXT NOT NULL,
    status TEXT NOT NULL,
    latency_ms REAL DEFAULT 0,
    error TEXT DEFAULT '',
    timestamp TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS pair_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tcp_strategy TEXT NOT NULL,
    udp_strategy TEXT NOT NULL,
    domain TEXT NOT NULL,
    tcp_ok INTEGER DEFAULT 0,
    gateway_ok INTEGER DEFAULT 0,
    udp_ok INTEGER DEFAULT 0,
    tcp_ms REAL DEFAULT 0,
    gateway_ms REAL DEFAULT 0,
    udp_ms REAL DEFAULT 0,
    overall TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS checkpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tcp_idx INTEGER NOT NULL,
    udp_idx INTEGER NOT NULL,
    fingerprint TEXT NOT NULL DEFAULT '',
    tcp_label TEXT NOT NULL DEFAULT '',
    udp_label TEXT NOT NULL DEFAULT '',
    timestamp TEXT NOT NULL DEFAULT '',
    note TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_tcp_status ON tcp_results(status);
CREATE INDEX IF NOT EXISTS idx_tcp_strat_domain ON tcp_results(strategy_id, domain);
CREATE INDEX IF NOT EXISTS idx_tcp_strat_dom_id ON tcp_results(strategy_id, domain, id DESC);
CREATE INDEX IF NOT EXISTS idx_tcp_domain ON tcp_results(domain, strategy_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_udp_status ON udp_results(status);
CREATE INDEX IF NOT EXISTS idx_udp_strat ON udp_results(strategy_id);
CREATE INDEX IF NOT EXISTS idx_pair_overall ON pair_results(overall);
CREATE INDEX IF NOT EXISTS idx_pair_domain ON pair_results(domain);
CREATE VIEW IF NOT EXISTS v_working_tcp AS
SELECT s.name AS strategy, t.domain, t.http_code, t.latency_ms,
       t.content_valid, t.timestamp, t.status
FROM tcp_results t
JOIN strategies s ON t.strategy_id = s.id
WHERE t.status IN ('PASS', 'THROTTLED')
ORDER BY t.domain, t.latency_ms;
CREATE VIEW IF NOT EXISTS v_coverage AS
SELECT s.name AS strategy, s.proto,
       COUNT(DISTINCT t.domain) AS domains_passed,
       ROUND(AVG(t.latency_ms), 1) AS avg_latency_ms
FROM tcp_results t
JOIN strategies s ON t.strategy_id = s.id
WHERE t.status IN ('PASS', 'THROTTLED')
  AND t.id = (
    SELECT t2.id FROM tcp_results t2
    WHERE t2.strategy_id = t.strategy_id AND t2.domain = t.domain
    ORDER BY t2.id DESC LIMIT 1
  )
GROUP BY s.name, s.proto
HAVING domains_passed > 0
ORDER BY domains_passed DESC;
CREATE VIEW IF NOT EXISTS v_latest_run AS
SELECT domain, COUNT(*) AS total,
       SUM(CASE WHEN status IN ('PASS','THROTTLED') THEN 1 ELSE 0 END) AS passed,
       MAX(timestamp) AS last_test
FROM tcp_results t
WHERE t.id = (
  SELECT t2.id FROM tcp_results t2
  WHERE t2.strategy_id = t.strategy_id AND t2.domain = t.domain
  ORDER BY t2.id DESC LIMIT 1
)
GROUP BY domain
ORDER BY last_test DESC;

CREATE TABLE IF NOT EXISTS dns_audit_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    udp_ips TEXT NOT NULL DEFAULT '',
    doh_ips TEXT NOT NULL DEFAULT '',
    verdict TEXT NOT NULL DEFAULT '',
    doh_server TEXT DEFAULT '',
    timestamp TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS quarantined (
    domain TEXT PRIMARY KEY,
    reason TEXT NOT NULL DEFAULT '',
    failed INTEGER NOT NULL DEFAULT 0,
    created TEXT NOT NULL DEFAULT ''
);
"""


async def apply_schema(db: aiosqlite.Connection) -> None:
    await db.execute("PRAGMA busy_timeout = 5000")
    await db.executescript(INIT_SCRIPT)
    await db.commit()
    cols = await db.execute("PRAGMA table_info(tcp_results)")
    col_names = {row[1] for row in await cols.fetchall()}
    if "read_rate_bps" not in col_names:
        await db.execute("ALTER TABLE tcp_results ADD COLUMN read_rate_bps REAL DEFAULT 0")
        await db.commit()
    for col, typedef in (
        ("resolved_ip", "TEXT DEFAULT ''"),
        ("dns_verdict", "TEXT DEFAULT ''"),
        ("doh_server", "TEXT DEFAULT ''"),
        ("bridge_batch_id", "INTEGER DEFAULT 0"),
        ("bridge_gen", "INTEGER DEFAULT 0"),
        ("fail_phase", "TEXT DEFAULT ''"),
        # NULL = unknown (classic backend / legacy rows); 1 = APPLIED seen,
        # 0 = PASS without APPLIED (suspicious lua-bridge result).
        ("bridge_applied", "INTEGER"),
        # SNI/хост, которым реально зондиовали (ggc-пул; пусто = домен как есть)
        ("probe_host", "TEXT DEFAULT ''"),
    ):
        if col not in col_names:
            await db.execute(f"ALTER TABLE tcp_results ADD COLUMN {col} {typedef}")
    await db.commit()
    await db.execute("PRAGMA journal_mode=WAL")
    await db.execute("PRAGMA synchronous=NORMAL")
    await db.execute("PRAGMA mmap_size=268435456")
    await db.execute("PRAGMA cache_size=-64000")
    await db.execute("PRAGMA temp_store=MEMORY")
    await db.execute("PRAGMA busy_timeout=5000")
    await db.execute(
        """CREATE TABLE IF NOT EXISTS scan_weights (
            key TEXT PRIMARY KEY,
            weight REAL NOT NULL DEFAULT 1.0,
            updated_at TEXT NOT NULL DEFAULT ''
        )"""
    )
    await db.execute(
        """CREATE TABLE IF NOT EXISTS triage_snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL DEFAULT '',
            payload_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT ''
        )"""
    )
    await db.commit()
    # runs table + run_id on results (ST-1 migration for pre-1.3.9 DBs)
    await db.execute(
        """CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL DEFAULT '',
            code_version TEXT NOT NULL DEFAULT '',
            args_hash TEXT NOT NULL DEFAULT '',
            fingerprint TEXT NOT NULL DEFAULT '',
            impersonate TEXT NOT NULL DEFAULT '',
            nfqws2_version TEXT NOT NULL DEFAULT ''
        )"""
    )
    for col, typedef in (
        ("run_id", "INTEGER REFERENCES runs(id)"),
    ):
        if col not in col_names:
            await db.execute(f"ALTER TABLE tcp_results ADD COLUMN {col} {typedef}")
    udp_cols = await db.execute("PRAGMA table_info(udp_results)")
    udp_col_names = {row[1] for row in await udp_cols.fetchall()}
    if "run_id" not in udp_col_names:
        await db.execute("ALTER TABLE udp_results ADD COLUMN run_id INTEGER REFERENCES runs(id)")
    await db.commit()
    # Query indexes (IF NOT EXISTS)
    pair_cols = await db.execute("PRAGMA table_info(pair_results)")
    pair_col_names = {row[1] for row in await pair_cols.fetchall()}
    pair_strat_idx = (
        "CREATE INDEX IF NOT EXISTS idx_pair_strat_dom_id ON pair_results(tcp_strategy, udp_strategy, domain, id DESC);"
        if "tcp_strategy" in pair_col_names
        else ""
    )
    await db.executescript(
        f"""
        CREATE INDEX IF NOT EXISTS idx_tcp_strat_domain ON tcp_results(strategy_id, domain);
        CREATE INDEX IF NOT EXISTS idx_tcp_strat_dom_id ON tcp_results(strategy_id, domain, id DESC);
        CREATE INDEX IF NOT EXISTS idx_tcp_domain ON tcp_results(domain, strategy_id, id DESC);
        CREATE INDEX IF NOT EXISTS idx_tcp_run_dom_strat ON tcp_results(run_id, domain, strategy_id);
        {pair_strat_idx}
        CREATE INDEX IF NOT EXISTS idx_udp_strat ON udp_results(strategy_id);
        CREATE INDEX IF NOT EXISTS idx_pair_domain ON pair_results(domain);
        """
    )
    await db.commit()
    # Recreate views so THROTTLED ∈ working (IF NOT EXISTS keeps stale defs)
    await db.executescript(
        """
        DROP VIEW IF EXISTS v_working_tcp;
        DROP VIEW IF EXISTS v_coverage;
        DROP VIEW IF EXISTS v_latest_run;
        CREATE VIEW v_working_tcp AS
        SELECT s.name AS strategy, t.domain, t.http_code, t.latency_ms,
               t.content_valid, t.timestamp, t.status
        FROM tcp_results t
        JOIN strategies s ON t.strategy_id = s.id
        WHERE t.status IN ('PASS', 'THROTTLED')
        ORDER BY t.domain, t.latency_ms;
        CREATE VIEW v_coverage AS
        SELECT s.name AS strategy, s.proto,
               COUNT(DISTINCT t.domain) AS domains_passed,
               ROUND(AVG(t.latency_ms), 1) AS avg_latency_ms
        FROM tcp_results t
        JOIN strategies s ON t.strategy_id = s.id
        WHERE t.status IN ('PASS', 'THROTTLED')
          AND t.id = (
            SELECT t2.id FROM tcp_results t2
            WHERE t2.strategy_id = t.strategy_id AND t2.domain = t.domain
            ORDER BY t2.id DESC LIMIT 1
          )
        GROUP BY s.name, s.proto
        HAVING domains_passed > 0
        ORDER BY domains_passed DESC;
        CREATE VIEW v_latest_run AS
        SELECT domain, COUNT(*) AS total,
               SUM(CASE WHEN status IN ('PASS','THROTTLED') THEN 1 ELSE 0 END) AS passed,
               MAX(timestamp) AS last_test
        FROM tcp_results t
        WHERE t.id = (
          SELECT t2.id FROM tcp_results t2
          WHERE t2.strategy_id = t.strategy_id AND t2.domain = t.domain
          ORDER BY t2.id DESC LIMIT 1
        )
        GROUP BY domain
        ORDER BY last_test DESC;
        """
    )
    await db.commit()
