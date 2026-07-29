"""State DB — aiosqlite-powered persistent results log."""

import hashlib
import time
from dataclasses import dataclass
from typing import Optional

import aiosqlite


@dataclass
class Checkpoint:
    tcp_idx: int
    udp_idx: int
    timestamp: str
    note: str
    fingerprint: str
    tcp_label: str
    udp_label: str


def matrix_fingerprint(tcp_strategies: list[str], udp_strategies: list[str],
                       scan_level: str = "", max_count: int = 0) -> str:
    """Stable hash of the strategy matrix for --resume drift detection."""
    parts = (
        sorted(tcp_strategies)
        + ["|"]
        + sorted(udp_strategies)
        + [f"level={scan_level}", f"max={max_count}"]
    )
    raw = "\n".join(parts).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


class StateDB:
    def __init__(self, db_path: str = "state.db"):
        self.db_path = db_path

    async def init(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript("""
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
                    strategy_id INTEGER REFERENCES strategies(id),
                    domain TEXT NOT NULL,
                    status TEXT NOT NULL,
                    http_code INTEGER DEFAULT 0,
                    latency_ms REAL DEFAULT 0,
                    gateway_ws_ms REAL DEFAULT 0,
                    content_valid INTEGER DEFAULT 0,
                    read_rate_bps REAL DEFAULT 0,
                    error TEXT DEFAULT '',
                    timestamp TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS udp_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
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
                CREATE INDEX IF NOT EXISTS idx_udp_status ON udp_results(status);
                CREATE INDEX IF NOT EXISTS idx_pair_overall ON pair_results(overall);
                CREATE VIEW IF NOT EXISTS v_working_tcp AS
                SELECT s.name AS strategy, t.domain, t.http_code, t.latency_ms,
                       t.content_valid, t.timestamp
                FROM tcp_results t
                JOIN strategies s ON t.strategy_id = s.id
                WHERE t.status = 'PASS'
                ORDER BY t.domain, t.latency_ms;
                CREATE VIEW IF NOT EXISTS v_coverage AS
                SELECT s.name AS strategy, s.proto,
                       COUNT(DISTINCT t.domain) AS domains_passed,
                       ROUND(AVG(t.latency_ms), 1) AS avg_latency_ms
                FROM tcp_results t
                JOIN strategies s ON t.strategy_id = s.id
                WHERE t.status = 'PASS'
                GROUP BY s.name, s.proto
                HAVING domains_passed > 0
                ORDER BY domains_passed DESC;
                CREATE VIEW IF NOT EXISTS v_latest_run AS
                SELECT domain, COUNT(*) AS total,
                       SUM(CASE WHEN status='PASS' THEN 1 ELSE 0 END) AS passed,
                       MAX(timestamp) AS last_test
                FROM tcp_results
                GROUP BY domain
                ORDER BY last_test DESC;
            """)
            await db.commit()
            # Migrate older DBs created before read_rate_bps existed
            cols = await db.execute("PRAGMA table_info(tcp_results)")
            col_names = {row[1] for row in await cols.fetchall()}
            if "read_rate_bps" not in col_names:
                await db.execute(
                    "ALTER TABLE tcp_results ADD COLUMN read_rate_bps REAL DEFAULT 0"
                )
                await db.commit()
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute("PRAGMA busy_timeout=5000")

    async def ensure_strategy(self, name: str, proto: str,
                               config_path: str,
                               db: aiosqlite.Connection = None) -> int:
        """Insert or get strategy ID. Reuses open `db` when provided."""
        async def _body(conn):
            row = await conn.execute(
                "SELECT id FROM strategies WHERE name=? AND proto=?",
                (name, proto),
            )
            existing = await row.fetchone()
            if existing:
                return existing[0]
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            cur = await conn.execute(
                "INSERT INTO strategies(name,proto,config_path,first_seen) "
                "VALUES(?,?,?,?)",
                (name, proto, config_path, ts),
            )
            await conn.commit()
            return cur.lastrowid

        if db is not None:
            return await _body(db)
        async with aiosqlite.connect(self.db_path) as conn:
            return await _body(conn)

    async def log_tcp(self, strategy: str, domain: str,
                       status: str, latency_ms: float,
                       http_code: int = 0, gateway_ms: float = 0,
                       content_valid: bool = True,
                       error: str = "",
                       read_rate_bps: float = 0.0) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            sid = await self.ensure_strategy(strategy, "tcp", strategy, db=db)
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                """INSERT INTO tcp_results
                   (strategy_id,domain,status,http_code,latency_ms,
                    gateway_ws_ms,content_valid,error,timestamp,read_rate_bps)
                   VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (sid, domain, status, http_code, latency_ms,
                 gateway_ms, int(content_valid), error, ts,
                 float(read_rate_bps or 0.0)),
            )
            await db.commit()

    async def log_udp(self, strategy: str, target: str,
                       status: str, latency_ms: float = 0,
                       error: str = "") -> None:
        async with aiosqlite.connect(self.db_path) as db:
            sid = await self.ensure_strategy(strategy, "udp", strategy, db=db)
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                """INSERT INTO udp_results
                   (strategy_id,target,status,latency_ms,error,timestamp)
                   VALUES(?,?,?,?,?,?)""",
                (sid, target, status, latency_ms, error, ts),
            )
            await db.commit()

    async def log_pair(self, tcp: str, udp: str, domain: str,
                        tcp_ok: bool, gateway_ok: bool, udp_ok: bool,
                        tcp_ms: float, gateway_ms: float, udp_ms: float,
                        overall: str) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                """INSERT INTO pair_results
                   (tcp_strategy,udp_strategy,domain,
                    tcp_ok,gateway_ok,udp_ok,
                    tcp_ms,gateway_ms,udp_ms,overall,timestamp)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (tcp, udp, domain,
                 int(tcp_ok), int(gateway_ok), int(udp_ok),
                 tcp_ms, gateway_ms, udp_ms, overall, ts),
            )
            await db.commit()

    async def save_checkpoint(self, tcp_idx: int, udp_idx: int,
                                note: str = "", fingerprint: str = "",
                                tcp_label: str = "", udp_label: str = "") -> None:
        async with aiosqlite.connect(self.db_path) as db:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                "INSERT INTO checkpoints(tcp_idx,udp_idx,fingerprint,"
                "tcp_label,udp_label,timestamp,note) VALUES(?,?,?,?,?,?,?)",
                (tcp_idx, udp_idx, fingerprint, tcp_label, udp_label, ts, note),
            )
            await db.commit()

    async def latest_checkpoint(self) -> Optional[Checkpoint]:
        """Return latest Checkpoint or None."""
        async with aiosqlite.connect(self.db_path) as db:
            row = await db.execute(
                "SELECT tcp_idx,udp_idx,timestamp,note,fingerprint,"
                "tcp_label,udp_label FROM checkpoints ORDER BY id DESC LIMIT 1"
            )
            r = await row.fetchone()
            if not r:
                return None
            return Checkpoint(
                tcp_idx=r[0], udp_idx=r[1], timestamp=r[2], note=r[3],
                fingerprint=r[4], tcp_label=r[5], udp_label=r[6],
            )

    async def get_working_tcp(self, domain: str) -> list[str]:
        """Names whose *latest* result for domain is PASS."""
        async with aiosqlite.connect(self.db_path) as db:
            rows = await db.execute(
                """SELECT s.name FROM strategies s
                   JOIN tcp_results t ON t.strategy_id = s.id
                   WHERE t.domain=? AND t.id = (
                       SELECT t2.id FROM tcp_results t2
                       WHERE t2.strategy_id = s.id AND t2.domain=?
                       ORDER BY t2.id DESC LIMIT 1
                   ) AND t.status='PASS'""",
                (domain, domain),
            )
            return [r[0] for r in await rows.fetchall()]

    async def get_passing_pairs(self, domain: str) -> list[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            rows = await db.execute(
                """SELECT tcp_strategy,udp_strategy,tcp_ms,gateway_ms,udp_ms
                   FROM pair_results WHERE domain=? AND overall='PASS'""",
                (domain,),
            )
            cols = ["tcp", "udp", "tcp_ms", "gateway_ms", "udp_ms"]
            return [dict(zip(cols, r)) for r in await rows.fetchall()]
