"""SQLite DAO for the run-state store."""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from pathlib import Path

import aiosqlite

from blockchecks.engine.paths import reclaim_sudo_ownership
from blockchecks.engine.store.models import Checkpoint
from blockchecks.engine.store.schema import apply_schema


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


def fingerprint_mismatch(checkpoint_fp: str | None, current_fp: str) -> bool:
    """True when a saved checkpoint fingerprint disagrees with the current matrix."""
    return bool(checkpoint_fp and checkpoint_fp != current_fp)


_WORKING_STATUSES = "('PASS','THROTTLED')"


class SqliteRunStore:
    """Closed DAO for blockcheckS run state (SQLite backend)."""

    def __init__(self, db_path: str | Path, batch_size: int = 0):
        self._path = Path(db_path).expanduser().resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        reclaim_sudo_ownership(self._path.parent)
        if self._path.exists():
            reclaim_sudo_ownership(self._path)
        self.batch_size = max(0, int(batch_size or 0))
        self._tcp_pending: list[dict] = []
        self._udp_pending: list[dict] = []
        self._flush_lock = asyncio.Lock()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def db_path(self) -> str:
        """Deprecated alias for export tools; prefer ``path``."""
        return str(self._path)

    async def init(self) -> None:
        async with aiosqlite.connect(self._path) as db:
            await apply_schema(db)
        reclaim_sudo_ownership(self._path)

    async def close(self) -> None:
        await self.flush()
        reclaim_sudo_ownership(self._path)

    @staticmethod
    async def _apply_pragmas(db: aiosqlite.Connection) -> None:
        # WAL: writers don't block readers; parallel worker flushes no longer
        # race into "database is locked" (seen at end of long runs). busy_timeout
        # stays as backstop for WAL checkpoint contention.
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("PRAGMA busy_timeout = 30000")
        await db.execute("PRAGMA synchronous = NORMAL")
        await db.execute("PRAGMA mmap_size = 268435456")
        await db.execute("PRAGMA cache_size = -64000")
        await db.execute("PRAGMA temp_store = MEMORY")

    async def ensure_strategy(
        self, name: str, proto: str, config_path: str, db: aiosqlite.Connection = None
    ) -> int:
        """Insert or get strategy ID. Reuses open `db` when provided."""

        async def _body(conn, commit: bool):
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
                    if commit:
                        await conn.commit()
                return existing[0]
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            cur = await conn.execute(
                "INSERT INTO strategies(name,proto,config_path,first_seen) VALUES(?,?,?,?)",
                (name, proto, config_path, ts),
            )
            if commit:
                await conn.commit()
            return cur.lastrowid

        if db is not None:
            return await _body(db, commit=False)
        async with aiosqlite.connect(self._path) as conn:
            await SqliteRunStore._apply_pragmas(conn)
            return await _body(conn, commit=True)

    async def flush(self) -> None:
        """Flush buffered log_tcp/log_udp rows (B8 batch mode).

        Drains pending rows and commits under ``_flush_lock`` for the entire
        write transaction so parallel flushes never race on BEGIN IMMEDIATE.
        On failure rows are re-queued before the lock is released.
        """
        # Drain atomically: snapshot current buffered rows and clear them in the
        # same synchronous block, so parallel writers appending after this point
        # are not erased when the commit completes.
        async with self._flush_lock:
            tcp_batch = list(self._tcp_pending)
            udp_batch = list(self._udp_pending)
            if not tcp_batch and not udp_batch:
                return
            self._tcp_pending.clear()
            self._udp_pending.clear()

            # Hold the lock for the whole write transaction so parallel flushes
            # never contend on BEGIN IMMEDIATE / redundant locked retries.
            last_err: Exception | None = None
            try:
                for attempt in range(5):
                    try:
                        async with aiosqlite.connect(self._path) as db:
                            await SqliteRunStore._apply_pragmas(db)
                            await db.execute("BEGIN IMMEDIATE")
                            try:
                                ts = time.strftime("%Y-%m-%dT%H:%M:%S")
                                for entry in tcp_batch:
                                    sid = await self.ensure_strategy(
                                        entry["strategy"],
                                        entry["proto"],
                                        entry["config_path"],
                                        db=db,
                                    )
                                    await db.execute(
                                        """INSERT INTO tcp_results
                                           (strategy_id,domain,status,http_code,latency_ms,
                                            gateway_ws_ms,content_valid,error,timestamp,read_rate_bps,
                                            resolved_ip,dns_verdict,doh_server,fail_phase)
                                           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                                        (
                                            sid,
                                            entry["domain"],
                                            entry["status"],
                                            entry["http_code"],
                                            entry["latency_ms"],
                                            entry["gateway_ms"],
                                            entry["content_valid"],
                                            entry["error"],
                                            ts,
                                            entry["read_rate_bps"],
                                            entry["resolved_ip"],
                                            entry["dns_verdict"],
                                            entry["doh_server"],
                                            entry.get("fail_phase", ""),
                                        ),
                                    )
                                for entry in udp_batch:
                                    sid = await self.ensure_strategy(
                                        entry["strategy"],
                                        "udp",
                                        entry["config_path"],
                                        db=db,
                                    )
                                    await db.execute(
                                        """INSERT INTO udp_results
                                           (strategy_id,target,status,latency_ms,error,timestamp)
                                           VALUES(?,?,?,?,?,?)""",
                                        (
                                            sid,
                                            entry["target"],
                                            entry["status"],
                                            entry["latency_ms"],
                                            entry["error"],
                                            ts,
                                        ),
                                    )
                                await db.commit()
                            except Exception:
                                await db.rollback()
                                raise
                        last_err = None
                        break
                    except aiosqlite.OperationalError as e:
                        if "locked" not in str(e).lower() or attempt >= 4:
                            raise
                        last_err = e
                        await asyncio.sleep(0.5 * (attempt + 1))
            except Exception:
                self._tcp_pending[:0] = tcp_batch
                self._udp_pending[:0] = udp_batch
                raise
            if last_err is not None:
                self._tcp_pending[:0] = tcp_batch
                self._udp_pending[:0] = udp_batch
                raise last_err
        reclaim_sudo_ownership(self._path)

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
        fail_phase: str = "",
    ) -> None:
        if self.batch_size > 0:
            self._tcp_pending.append(
                {
                    "strategy": strategy,
                    "proto": proto,
                    "config_path": config_path or strategy,
                    "domain": domain,
                    "status": status,
                    "http_code": http_code,
                    "latency_ms": latency_ms,
                    "gateway_ms": gateway_ms,
                    "content_valid": int(content_valid),
                    "error": error,
                    "read_rate_bps": float(read_rate_bps or 0.0),
                    "resolved_ip": resolved_ip or "",
                    "dns_verdict": dns_verdict or "",
                    "doh_server": doh_server or "",
                    "fail_phase": fail_phase or "",
                }
            )
            if len(self._tcp_pending) >= self.batch_size:
                await self.flush()
            return
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            sid = await self.ensure_strategy(strategy, proto, config_path or strategy, db=db)
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                """INSERT INTO tcp_results
                   (strategy_id,domain,status,http_code,latency_ms,
                    gateway_ws_ms,content_valid,error,timestamp,read_rate_bps,
                    resolved_ip,dns_verdict,doh_server,fail_phase)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
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
                    fail_phase or "",
                ),
            )
            await db.commit()
        reclaim_sudo_ownership(self._path)

    async def log_udp(
        self,
        strategy: str,
        target: str,
        status: str,
        latency_ms: float = 0,
        error: str = "",
        config_path: str = "",
    ) -> None:
        if self.batch_size > 0:
            self._udp_pending.append(
                {
                    "strategy": strategy,
                    "config_path": config_path or strategy,
                    "target": target,
                    "status": status,
                    "latency_ms": latency_ms,
                    "error": error,
                }
            )
            if len(self._udp_pending) >= self.batch_size:
                await self.flush()
            return
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            sid = await self.ensure_strategy(strategy, "udp", config_path or strategy, db=db)
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                """INSERT INTO udp_results
                   (strategy_id,target,status,latency_ms,error,timestamp)
                   VALUES(?,?,?,?,?,?)""",
                (sid, target, status, latency_ms, error, ts),
            )
            await db.commit()
        reclaim_sudo_ownership(self._path)

    async def write_dns_audit_log(
        self,
        domain: str,
        udp_ips: str,
        doh_ips: str,
        verdict: str,
        doh_server: str = "",
        timestamp: str = "",
    ) -> None:
        ts = timestamp or time.strftime("%Y-%m-%dT%H:%M:%S")
        async with aiosqlite.connect(self._path) as db:
            await db.execute(
                """INSERT INTO dns_audit_results
                   (domain, udp_ips, doh_ips, verdict, doh_server, timestamp)
                   VALUES (?,?,?,?,?,?)""",
                (domain, udp_ips, doh_ips, verdict, doh_server, ts),
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
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
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
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                "INSERT INTO checkpoints(tcp_idx,udp_idx,fingerprint,"
                "tcp_label,udp_label,timestamp,note) VALUES(?,?,?,?,?,?,?)",
                (tcp_idx, udp_idx, fingerprint, tcp_label, udp_label, ts, note),
            )
            await db.commit()

    async def latest_checkpoint(self) -> Checkpoint | None:
        """Return latest Checkpoint or None."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
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

    async def domain_pass_stats(
        self,
        domain: str,
        *,
        protos: tuple[str, ...] = ("tcp",),
    ) -> dict[str, int]:
        """Count latest-row results per strategy for domain (given protos)."""
        if not protos:
            return {"total": 0, "passed": 0}
        placeholders = ",".join("?" * len(protos))
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            row = await db.execute(
                f"""SELECT COUNT(*),
                           SUM(CASE WHEN t.status IN {_WORKING_STATUSES} THEN 1 ELSE 0 END)
                    FROM tcp_results t
                    JOIN strategies s ON t.strategy_id = s.id
                    WHERE t.domain=? AND s.proto IN ({placeholders})
                      AND t.id = (
                        SELECT t2.id FROM tcp_results t2
                        WHERE t2.strategy_id = t.strategy_id AND t2.domain = t.domain
                        ORDER BY t2.id DESC LIMIT 1
                      )""",
                (domain, *protos),
            )
            r = await row.fetchone()
            return {"total": int(r[0] or 0), "passed": int(r[1] or 0)}

    async def count_tcp_passes(self, domain: str | None = None) -> int:
        """Count latest-row PASS/THROTTLED for tcp proto (optionally per domain)."""
        if domain:
            stats = await self.domain_pass_stats(domain, protos=("tcp",))
            return int(stats.get("passed", 0))
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            row = await (
                await db.execute(
                    f"""SELECT COUNT(*) FROM tcp_results t
                       JOIN strategies s ON t.strategy_id=s.id
                       WHERE t.status IN {_WORKING_STATUSES} AND s.proto='tcp'
                         AND t.id = (
                           SELECT t2.id FROM tcp_results t2
                           WHERE t2.strategy_id = t.strategy_id AND t2.domain = t.domain
                           ORDER BY t2.id DESC LIMIT 1
                         )"""
                )
            ).fetchone()
        return int(row[0] or 0)

    async def get_working_tcp(self, domain: str) -> list[str]:
        """Names whose *latest* result for domain is PASS or THROTTLED (proto=tcp)."""
        return await self.get_working_proto(domain, "tcp")

    async def get_working_quic(self, domain: str) -> list[str]:
        """Names whose latest QUIC result for domain is PASS or THROTTLED."""
        return await self.get_working_proto(domain, "quic")

    async def get_working_proto(self, domain: str, proto: str) -> list[str]:
        details = await self.get_working_proto_details(domain, proto)
        return [d["name"] for d in details]

    async def get_working_tcp_details(self, domain: str) -> list[dict]:
        """Latest PASS/THROTTLED TCP rows for domain: name, status, latency_ms."""
        return await self.get_working_proto_details(domain, "tcp")

    async def get_working_proto_details(self, domain: str, proto: str) -> list[dict]:
        await self.flush()
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute(
                f"""SELECT s.name, t.status, t.latency_ms FROM strategies s
                   JOIN tcp_results t ON t.strategy_id = s.id
                   WHERE s.proto=? AND t.domain=? AND t.id = (
                       SELECT t2.id FROM tcp_results t2
                       WHERE t2.strategy_id = s.id AND t2.domain=?
                       ORDER BY t2.id DESC LIMIT 1
                   ) AND t.status IN {_WORKING_STATUSES}""",
                (proto, domain, domain),
            )
            cols = ["name", "status", "latency_ms"]
            return [dict(zip(cols, r)) for r in await rows.fetchall()]

    async def get_completed_pair_keys(self, domain: str) -> set[tuple[str, str]]:
        """All (tcp, udp) pairs already logged for domain (any overall) — resume skip."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute(
                "SELECT DISTINCT tcp_strategy, udp_strategy FROM pair_results WHERE domain=?",
                (domain,),
            )
            return {(r[0], r[1]) for r in await rows.fetchall()}

    async def has_tcp_result(self, strategy: str, domain: str, proto: str = "tcp") -> bool:
        """True if any tcp_results row exists for strategy×domain (resume skip)."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            row = await db.execute(
                """SELECT 1 FROM tcp_results t
                   JOIN strategies s ON t.strategy_id = s.id
                   WHERE s.name=? AND s.proto=? AND t.domain=?
                   LIMIT 1""",
                (strategy, proto, domain),
            )
            return await row.fetchone() is not None

    async def get_completed_tcp_keys(self, proto: str = "tcp") -> set[tuple[str, str]]:
        """All (strategy_name, domain) pairs already in tcp_results — bulk resume skip."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute(
                """SELECT DISTINCT s.name, t.domain
                   FROM tcp_results t
                   JOIN strategies s ON t.strategy_id = s.id
                   WHERE s.proto=?""",
                (proto,),
            )
            return {(r[0], r[1]) for r in await rows.fetchall()}

    async def get_best_tcp(self, domain: str, *, limit: int = 5) -> list[dict]:
        """Latest PASS/THROTTLED per strategy for domain, ordered by latency_ms ASC."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute(
                f"""SELECT s.name, t.latency_ms, t.http_code, t.timestamp
                   FROM strategies s
                   JOIN tcp_results t ON t.strategy_id = s.id
                   WHERE s.proto='tcp' AND t.domain=? AND t.status IN {_WORKING_STATUSES}
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
        """Latest PASS/THROTTLED per QUIC strategy for domain, ordered by latency_ms ASC."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute(
                f"""SELECT s.name, t.latency_ms, t.http_code, t.timestamp
                   FROM strategies s
                   JOIN tcp_results t ON t.strategy_id = s.id
                   WHERE s.proto='quic' AND t.domain=? AND t.status IN {_WORKING_STATUSES}
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
        """Latest PASS/THROTTLED UDP strategies, ordered by latency."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute(
                f"""SELECT s.name, t.target, t.latency_ms, t.timestamp
                   FROM strategies s
                   JOIN udp_results t ON t.strategy_id = s.id
                   WHERE s.proto='udp' AND t.status IN {_WORKING_STATUSES}
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
        """Latest PASS/THROTTLED pair per (tcp,udp,domain), best by tcp_ms+udp_ms."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute(
                f"""SELECT tcp_strategy, udp_strategy, tcp_ms, udp_ms, overall
                   FROM pair_results p
                   WHERE domain=? AND overall IN {_WORKING_STATUSES}
                     AND id = (
                       SELECT p2.id FROM pair_results p2
                       WHERE p2.tcp_strategy = p.tcp_strategy
                         AND p2.udp_strategy = p.udp_strategy
                         AND p2.domain = p.domain
                       ORDER BY p2.id DESC LIMIT 1
                     )
                   ORDER BY (tcp_ms + udp_ms) ASC
                   LIMIT ?""",
                (domain, limit),
            )
            cols = ["tcp", "udp", "tcp_ms", "udp_ms", "overall"]
            return [dict(zip(cols, r)) for r in await rows.fetchall()]

    async def coverage_score(self, strategy: str) -> dict:
        """PASS domain count + avg latency for a TCP strategy (latest per domain)."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute(
                f"""SELECT t.domain, t.latency_ms FROM strategies s
                   JOIN tcp_results t ON t.strategy_id = s.id
                   WHERE s.name=? AND s.proto='tcp' AND t.status IN {_WORKING_STATUSES}
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
        await self.flush()
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute(
                f"""SELECT s.name,
                           COUNT(DISTINCT t.domain) AS domains_passed,
                           ROUND(AVG(t.latency_ms), 1) AS avg_latency_ms
                    FROM tcp_results t
                    JOIN strategies s ON t.strategy_id = s.id
                    WHERE s.proto='tcp' AND t.status IN {_WORKING_STATUSES}
                      AND t.id = (
                        SELECT t2.id FROM tcp_results t2
                        WHERE t2.strategy_id = t.strategy_id AND t2.domain = t.domain
                        ORDER BY t2.id DESC LIMIT 1
                      )
                    GROUP BY s.name
                    HAVING domains_passed > 0
                    ORDER BY domains_passed DESC, avg_latency_ms ASC
                    LIMIT ?""",
                (limit,),
            )
            return [
                {
                    "strategy": r[0],
                    "domains_passed": int(r[1]),
                    "avg_latency_ms": float(r[2]),
                    "domains": [],
                }
                for r in await rows.fetchall()
            ]

    async def get_common_tcp(self, domains: list[str], *, limit: int = 5) -> list[dict]:
        """TCP strategies whose latest result is PASS on every domain."""
        if len(domains) < 2:
            return []
        placeholders = ",".join("?" * len(domains))
        need = len(domains)
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute(
                f"""SELECT s.name,
                           COUNT(DISTINCT t.domain) AS domains_passed,
                           ROUND(AVG(t.latency_ms), 1) AS avg_latency_ms
                    FROM tcp_results t
                    JOIN strategies s ON t.strategy_id = s.id
                    WHERE s.proto='tcp' AND t.domain IN ({placeholders})
                      AND t.status IN {_WORKING_STATUSES}
                      AND t.id = (
                        SELECT t2.id FROM tcp_results t2
                        WHERE t2.strategy_id = t.strategy_id AND t2.domain = t.domain
                        ORDER BY t2.id DESC LIMIT 1
                      )
                    GROUP BY s.name
                    HAVING domains_passed = ?
                    ORDER BY avg_latency_ms ASC
                    LIMIT ?""",
                (*domains, need, limit),
            )
            return [
                {
                    "strategy": r[0],
                    "domains_passed": int(r[1]),
                    "avg_latency_ms": float(r[2]),
                }
                for r in await rows.fetchall()
            ]

    async def get_strategy_config(self, name: str, proto: str = "tcp") -> str | None:
        """Return stored config_path/strategy string for name."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            row = await db.execute(
                "SELECT config_path FROM strategies WHERE name=? AND proto=?",
                (name, proto),
            )
            r = await row.fetchone()
            return r[0] if r else None

    async def load_scan_weights(self) -> list[tuple[str, float]]:
        """Load AQ4 weight rows (key, weight)."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute("SELECT key, weight FROM scan_weights ORDER BY key")
            return [(r[0], float(r[1])) for r in await rows.fetchall()]

    async def save_scan_weights(self, rows: list[tuple[str, float]]) -> None:
        """Persist AQ4 weight rows (upsert)."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            for key, weight in rows:
                await db.execute(
                    """INSERT INTO scan_weights(key, weight, updated_at) VALUES(?,?,?)
                       ON CONFLICT(key) DO UPDATE SET weight=excluded.weight,
                       updated_at=excluded.updated_at""",
                    (key, float(weight), ts),
                )
            await db.commit()

    async def save_triage_snapshot(self, domain: str, payload: dict) -> None:
        """Persist a JSON triage snapshot for this run."""
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            await db.execute(
                """INSERT INTO triage_snapshots(domain, payload_json, created_at)
                   VALUES(?,?,?)""",
                (domain or "", json.dumps(payload, ensure_ascii=False), ts),
            )
            await db.commit()
        reclaim_sudo_ownership(self._path)
