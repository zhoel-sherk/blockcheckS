"""State DB — aiosqlite-powered persistent results log."""

import hashlib
import time
from dataclasses import dataclass

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


def matrix_fingerprint(
    tcp_strategies: list[str], udp_strategies: list[str], scan_level: str = "", max_count: int = 0
) -> str:
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
                await db.execute("ALTER TABLE tcp_results ADD COLUMN read_rate_bps REAL DEFAULT 0")
                await db.commit()
            for col, typedef in (
                ("resolved_ip", "TEXT DEFAULT ''"),
                ("dns_verdict", "TEXT DEFAULT ''"),
                ("doh_server", "TEXT DEFAULT ''"),
            ):
                if col not in col_names:
                    await db.execute(f"ALTER TABLE tcp_results ADD COLUMN {col} {typedef}")
            await db.commit()
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute("PRAGMA busy_timeout=5000")

    async def ensure_strategy(
        self, name: str, proto: str, config_path: str, db: aiosqlite.Connection = None
    ) -> int:
        """Insert or get strategy ID. Reuses open `db` when provided."""

        async def _body(conn):
            row = await conn.execute(
                "SELECT id FROM strategies WHERE name=? AND proto=?",
                (name, proto),
            )
            existing = await row.fetchone()
            if existing:
                if config_path:
                    await conn.execute(
                        "UPDATE strategies SET config_path=? WHERE id=?",
                        (config_path, existing[0]),
                    )
                    await conn.commit()
                return existing[0]
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            cur = await conn.execute(
                "INSERT INTO strategies(name,proto,config_path,first_seen) VALUES(?,?,?,?)",
                (name, proto, config_path, ts),
            )
            await conn.commit()
            return cur.lastrowid

        if db is not None:
            return await _body(db)
        async with aiosqlite.connect(self.db_path) as conn:
            return await _body(conn)

    async def log_tcp(
        self,
        strategy: str,
        domain: str,
        status: str,
        latency_ms: float,
        http_code: int = 0,
        gateway_ms: float = 0,
        content_valid: bool = True,
        error: str = "",
        read_rate_bps: float = 0.0,
        config_path: str = "",
        resolved_ip: str = "",
        dns_verdict: str = "",
        doh_server: str = "",
        proto: str = "tcp",
    ) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            sid = await self.ensure_strategy(strategy, proto, config_path or strategy, db=db)
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                """INSERT INTO tcp_results
                   (strategy_id,domain,status,http_code,latency_ms,
                    gateway_ws_ms,content_valid,error,timestamp,read_rate_bps,
                    resolved_ip,dns_verdict,doh_server)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    sid,
                    domain,
                    status,
                    http_code,
                    latency_ms,
                    gateway_ms,
                    int(content_valid),
                    error,
                    ts,
                    float(read_rate_bps or 0.0),
                    resolved_ip or "",
                    dns_verdict or "",
                    doh_server or "",
                ),
            )
            await db.commit()

    async def log_udp(
        self,
        strategy: str,
        target: str,
        status: str,
        latency_ms: float = 0,
        error: str = "",
        config_path: str = "",
    ) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            sid = await self.ensure_strategy(strategy, "udp", config_path or strategy, db=db)
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                """INSERT INTO udp_results
                   (strategy_id,target,status,latency_ms,error,timestamp)
                   VALUES(?,?,?,?,?,?)""",
                (sid, target, status, latency_ms, error, ts),
            )
            await db.commit()

    async def log_pair(
        self,
        tcp: str,
        udp: str,
        domain: str,
        tcp_ok: bool,
        gateway_ok: bool,
        udp_ok: bool,
        tcp_ms: float,
        gateway_ms: float,
        udp_ms: float,
        overall: str,
    ) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                """INSERT INTO pair_results
                   (tcp_strategy,udp_strategy,domain,
                    tcp_ok,gateway_ok,udp_ok,
                    tcp_ms,gateway_ms,udp_ms,overall,timestamp)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    tcp,
                    udp,
                    domain,
                    int(tcp_ok),
                    int(gateway_ok),
                    int(udp_ok),
                    tcp_ms,
                    gateway_ms,
                    udp_ms,
                    overall,
                    ts,
                ),
            )
            await db.commit()

    async def save_checkpoint(
        self,
        tcp_idx: int,
        udp_idx: int,
        note: str = "",
        fingerprint: str = "",
        tcp_label: str = "",
        udp_label: str = "",
    ) -> None:
        async with aiosqlite.connect(self.db_path) as db:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                "INSERT INTO checkpoints(tcp_idx,udp_idx,fingerprint,"
                "tcp_label,udp_label,timestamp,note) VALUES(?,?,?,?,?,?,?)",
                (tcp_idx, udp_idx, fingerprint, tcp_label, udp_label, ts, note),
            )
            await db.commit()

    async def latest_checkpoint(self) -> Checkpoint | None:
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
                tcp_idx=r[0],
                udp_idx=r[1],
                timestamp=r[2],
                note=r[3],
                fingerprint=r[4],
                tcp_label=r[5],
                udp_label=r[6],
            )

    async def get_working_tcp(self, domain: str) -> list[str]:
        """Names whose *latest* result for domain is PASS (proto=tcp)."""
        return await self.get_working_proto(domain, "tcp")

    async def get_working_quic(self, domain: str) -> list[str]:
        """Names whose latest QUIC result for domain is PASS."""
        return await self.get_working_proto(domain, "quic")

    async def get_working_proto(self, domain: str, proto: str) -> list[str]:
        async with aiosqlite.connect(self.db_path) as db:
            rows = await db.execute(
                """SELECT s.name FROM strategies s
                   JOIN tcp_results t ON t.strategy_id = s.id
                   WHERE s.proto=? AND t.domain=? AND t.id = (
                       SELECT t2.id FROM tcp_results t2
                       WHERE t2.strategy_id = s.id AND t2.domain=?
                       ORDER BY t2.id DESC LIMIT 1
                   ) AND t.status='PASS'""",
                (proto, domain, domain),
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

    async def has_tcp_result(self, strategy: str, domain: str, proto: str = "tcp") -> bool:
        """True if any tcp_results row exists for strategy×domain (resume skip)."""
        async with aiosqlite.connect(self.db_path) as db:
            row = await db.execute(
                """SELECT 1 FROM tcp_results t
                   JOIN strategies s ON t.strategy_id = s.id
                   WHERE s.name=? AND s.proto=? AND t.domain=?
                   LIMIT 1""",
                (strategy, proto, domain),
            )
            return await row.fetchone() is not None

    async def get_best_tcp(self, domain: str, *, limit: int = 5) -> list[dict]:
        """Latest PASS per strategy for domain, ordered by latency_ms ASC."""
        async with aiosqlite.connect(self.db_path) as db:
            rows = await db.execute(
                """SELECT s.name, t.latency_ms, t.http_code, t.timestamp
                   FROM strategies s
                   JOIN tcp_results t ON t.strategy_id = s.id
                   WHERE s.proto='tcp' AND t.domain=? AND t.status='PASS'
                     AND t.id = (
                       SELECT t2.id FROM tcp_results t2
                       WHERE t2.strategy_id = s.id AND t2.domain=?
                       ORDER BY t2.id DESC LIMIT 1
                     )
                   ORDER BY t.latency_ms ASC
                   LIMIT ?""",
                (domain, domain, limit),
            )
            cols = ["strategy", "latency_ms", "http_code", "timestamp"]
            return [dict(zip(cols, r)) for r in await rows.fetchall()]

    async def get_best_quic(self, domain: str, *, limit: int = 5) -> list[dict]:
        """Latest PASS per QUIC strategy for domain, ordered by latency_ms ASC."""
        async with aiosqlite.connect(self.db_path) as db:
            rows = await db.execute(
                """SELECT s.name, t.latency_ms, t.http_code, t.timestamp
                   FROM strategies s
                   JOIN tcp_results t ON t.strategy_id = s.id
                   WHERE s.proto='quic' AND t.domain=? AND t.status='PASS'
                     AND t.id = (
                       SELECT t2.id FROM tcp_results t2
                       WHERE t2.strategy_id = s.id AND t2.domain=?
                       ORDER BY t2.id DESC LIMIT 1
                     )
                   ORDER BY t.latency_ms ASC
                   LIMIT ?""",
                (domain, domain, limit),
            )
            cols = ["strategy", "latency_ms", "http_code", "timestamp"]
            return [dict(zip(cols, r)) for r in await rows.fetchall()]

    async def get_best_udp(self, *, limit: int = 5) -> list[dict]:
        """Latest PASS UDP strategies, ordered by latency."""
        async with aiosqlite.connect(self.db_path) as db:
            rows = await db.execute(
                """SELECT s.name, t.target, t.latency_ms, t.timestamp
                   FROM strategies s
                   JOIN udp_results t ON t.strategy_id = s.id
                   WHERE s.proto='udp' AND t.status='PASS'
                     AND t.id = (
                       SELECT t2.id FROM udp_results t2
                       WHERE t2.strategy_id = s.id
                       ORDER BY t2.id DESC LIMIT 1
                     )
                   ORDER BY t.latency_ms ASC
                   LIMIT ?""",
                (limit,),
            )
            cols = ["strategy", "target", "latency_ms", "timestamp"]
            return [dict(zip(cols, r)) for r in await rows.fetchall()]

    async def get_best_pairs(self, domain: str, *, limit: int = 10) -> list[dict]:
        """PASS pairs for domain, best by tcp_ms+udp_ms."""
        async with aiosqlite.connect(self.db_path) as db:
            rows = await db.execute(
                """SELECT tcp_strategy, udp_strategy, tcp_ms, udp_ms, overall
                   FROM pair_results
                   WHERE domain=? AND overall='PASS'
                   ORDER BY (tcp_ms + udp_ms) ASC
                   LIMIT ?""",
                (domain, limit),
            )
            cols = ["tcp", "udp", "tcp_ms", "udp_ms", "overall"]
            return [dict(zip(cols, r)) for r in await rows.fetchall()]

    async def coverage_score(self, strategy: str) -> dict:
        """PASS domain count + avg latency for a TCP strategy (latest per domain)."""
        async with aiosqlite.connect(self.db_path) as db:
            rows = await db.execute(
                """SELECT t.domain, t.latency_ms FROM strategies s
                   JOIN tcp_results t ON t.strategy_id = s.id
                   WHERE s.name=? AND s.proto='tcp' AND t.status='PASS'
                     AND t.id = (
                       SELECT t2.id FROM tcp_results t2
                       WHERE t2.strategy_id = s.id AND t2.domain = t.domain
                       ORDER BY t2.id DESC LIMIT 1
                     )""",
                (strategy,),
            )
            data = await rows.fetchall()
            if not data:
                return {
                    "strategy": strategy,
                    "domains_passed": 0,
                    "avg_latency_ms": 0.0,
                    "domains": [],
                }
            domains = [r[0] for r in data]
            avg = sum(r[1] for r in data) / len(data)
            return {
                "strategy": strategy,
                "domains_passed": len(domains),
                "avg_latency_ms": round(avg, 1),
                "domains": domains,
            }

    async def get_best_by_coverage(self, *, limit: int = 5) -> list[dict]:
        """TCP strategies ranked by domains_passed DESC, then avg latency ASC."""
        async with aiosqlite.connect(self.db_path) as db:
            # Distinct strategy names that have at least one PASS
            rows = await db.execute(
                """SELECT DISTINCT s.name FROM strategies s
                   JOIN tcp_results t ON t.strategy_id = s.id
                   WHERE s.proto='tcp' AND t.status='PASS'"""
            )
            names = [r[0] for r in await rows.fetchall()]

        scored = []
        for name in names:
            sc = await self.coverage_score(name)
            if sc["domains_passed"] > 0:
                scored.append(sc)
        scored.sort(key=lambda x: (-x["domains_passed"], x["avg_latency_ms"]))
        return scored[:limit]

    async def get_common_tcp(self, domains: list[str], *, limit: int = 5) -> list[dict]:
        """TCP strategies whose latest result is PASS on every domain (BC2-7)."""
        if len(domains) < 2:
            return []
        common: set[str] | None = None
        for domain in domains:
            working = set(await self.get_working_tcp(domain))
            common = working if common is None else common & working
        if not common:
            return []
        scored: list[dict] = []
        for name in common:
            total_ms = 0.0
            found = 0
            for domain in domains:
                for row in await self.get_best_tcp(domain, limit=200):
                    if row["strategy"] == name:
                        total_ms += row["latency_ms"]
                        found += 1
                        break
            if found == len(domains):
                scored.append(
                    {
                        "strategy": name,
                        "avg_latency_ms": round(total_ms / found, 1),
                        "domains_passed": len(domains),
                    }
                )
        scored.sort(key=lambda x: x["avg_latency_ms"])
        return scored[:limit]

    async def get_strategy_config(self, name: str, proto: str = "tcp") -> str | None:
        """Return stored config_path/strategy string for name."""
        async with aiosqlite.connect(self.db_path) as db:
            row = await db.execute(
                "SELECT config_path FROM strategies WHERE name=? AND proto=?",
                (name, proto),
            )
            r = await row.fetchone()
            return r[0] if r else None
