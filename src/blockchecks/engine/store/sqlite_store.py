"""SQLite DAO for the run-state store."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any

import aiosqlite

from blockchecks import __version__
from blockchecks.engine.paths import reclaim_sudo_ownership
from blockchecks.engine.store.models import Checkpoint
from blockchecks.engine.store.schema import apply_schema

log = logging.getLogger(__name__)

_TCP_INSERT_SQL = """INSERT INTO tcp_results
   (run_id,strategy_id,domain,status,http_code,latency_ms,
    gateway_ws_ms,content_valid,error,timestamp,read_rate_bps,
    resolved_ip,dns_verdict,doh_server,fail_phase,
    bridge_applied,bridge_batch_id,bridge_gen,probe_host,
    epoch_ms,settle_ms,content_len)
   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"""

_UDP_INSERT_SQL = """INSERT INTO udp_results
   (run_id,strategy_id,target,status,latency_ms,error,timestamp,epoch_ms)
   VALUES(?,?,?,?,?,?,?,?)"""

_ENSURE_STRATEGY_SQL = """INSERT INTO strategies(name, proto, config_path, first_seen)
   VALUES(?,?,?,?)
   ON CONFLICT(name, proto) DO UPDATE SET
     config_path=CASE
       WHEN excluded.config_path != '' THEN excluded.config_path
       ELSE strategies.config_path
     END"""

_SELECT_STRATEGY_ID_SQL = "SELECT id FROM strategies WHERE name=? AND proto=?"


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


def campaign_args_hash(args: Any) -> str:
    """Stable hash of campaign CLI args (domains/preset/scan knobs)."""
    parts: list[str] = []
    for key in (
        "domain",
        "domains",
        "domains_file",
        "preset",
        "scan_level",
        "max",
        "parallel",
        "protocol",
        "db",
    ):
        val = getattr(args, key, None)
        if val is None or val == "" or val == []:
            continue
        parts.append(f"{key}={val}")
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def _probe_nfqws2_version() -> str:
    try:
        from blockchecks.engine.config import get_nfqws2_bin

        bin_path = get_nfqws2_bin()
        if not bin_path:
            return ""
        proc = subprocess.run(
            [bin_path, "--version"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        text = (proc.stdout or proc.stderr or "").strip()
        return text[:200]
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("nfqws2 --version probe failed: %s", exc)
        return ""


def _resolve_impersonate() -> str:
    """Same env pin as curl_probe.impersonate_target, without importing checkers (store_leaf)."""
    return (os.environ.get("BLOCKCHECKS_IMPERSONATE") or "").strip() or "chrome124"


_WORKING_STATUSES = "('PASS','THROTTLED')"
_DEFAULT_FLUSH_INTERVAL_SEC = 15.0
_WAL_CHECKPOINT_EVERY = 5
_WAL_CHECKPOINT_ELAPSED_SEC = 60.0


class SqliteRunStore:
    """Closed DAO for blockcheckS run state (SQLite backend)."""

    def __init__(
        self,
        db_path: str | Path,
        batch_size: int = 0,
        flush_interval_sec: float = _DEFAULT_FLUSH_INTERVAL_SEC,
        *,
        resume: bool = False,
    ):
        self._path = Path(db_path).expanduser().resolve()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        reclaim_sudo_ownership(self._path.parent)
        if self._path.exists():
            reclaim_sudo_ownership(self._path)
        self.batch_size = max(0, int(batch_size or 0))
        self._flush_interval = max(10.0, min(30.0, float(flush_interval_sec)))
        self._resume = bool(resume)
        self._run_id: int | None = None
        self._tcp_pending: list[dict] = []
        self._udp_pending: list[dict] = []
        self._flush_lock = asyncio.Lock()
        self._write_lock = asyncio.Lock()
        self._conn_lock = asyncio.Lock()
        self._conn: aiosqlite.Connection | None = None
        self._flush_count = 0
        self._last_checkpoint_mono: float | None = None
        self._pending_since: float | None = None
        self._flush_timer_task: asyncio.Task[None] | None = None

    @property
    def path(self) -> Path:
        return self._path

    @property
    def db_path(self) -> str:
        """Deprecated alias for export tools; prefer ``path``."""
        return str(self._path)

    @property
    def run_id(self) -> int | None:
        return self._run_id

    async def init(self) -> None:
        async with self._write_lock:
            db = await self._writer()
            await apply_schema(db)
        reclaim_sudo_ownership(self._path)
        log.debug(
            "reclaim_sudo_ownership: init/close only (skipped per-write hot path)"
        )

    async def _writer(self) -> aiosqlite.Connection:
        """Lazy-open the long-lived writer connection (ST-2)."""
        if self._conn is not None:
            return self._conn
        async with self._conn_lock:
            if self._conn is not None:
                return self._conn
            try:
                conn = await aiosqlite.connect(self._path)
            except Exception as exc:
                log.error("sqlite writer connect failed path=%s: %s", self._path, exc)
                raise
            await SqliteRunStore._apply_pragmas(conn)
            self._conn = conn
            return conn

    async def _close_writer(self) -> None:
        if self._conn is None:
            return
        await self._conn.close()
        self._conn = None

    async def compact(self) -> None:
        """Passive WAL checkpoint + incremental vacuum pages (ST-7)."""
        async with self._write_lock:
            if self._conn is None:
                return
            db = self._conn
            try:
                await db.execute("PRAGMA wal_checkpoint(PASSIVE)")
            except Exception as exc:
                log.warning("wal_checkpoint(PASSIVE) failed: %s", exc)
            try:
                await db.execute("PRAGMA incremental_vacuum(64)")
            except Exception as exc:
                log.warning("incremental_vacuum failed: %s", exc)

    async def _maybe_wal_checkpoint(self) -> None:
        self._flush_count += 1
        now = time.monotonic()
        elapsed = (
            self._last_checkpoint_mono is not None
            and now - self._last_checkpoint_mono >= _WAL_CHECKPOINT_ELAPSED_SEC
        )
        if self._flush_count % _WAL_CHECKPOINT_EVERY != 0 and not elapsed:
            return
        if self._conn is None:
            return
        try:
            await self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            self._last_checkpoint_mono = now
        except Exception as exc:
            log.warning("wal_checkpoint(PASSIVE) failed: %s", exc)

    async def begin_run(
        self,
        *,
        resume: bool | None = None,
        fingerprint: str = "",
        args_hash: str = "",
        code_version: str | None = None,
        impersonate: str | None = None,
        nfqws2_version: str | None = None,
    ) -> int:
        """Start or reuse a campaign run row.

        Resume rule: when ``resume`` is true, reuse the latest ``runs`` row whose
        ``fingerprint`` matches the current campaign; otherwise insert a new run.
        """
        use_resume = self._resume if resume is None else bool(resume)
        fp = fingerprint or ""
        ah = args_hash or ""
        cv = code_version if code_version is not None else __version__
        imp = impersonate if impersonate is not None else _resolve_impersonate()
        nfv = nfqws2_version if nfqws2_version is not None else _probe_nfqws2_version()
        async with self._write_lock:
            db = await self._writer()
            run_id = await self._begin_run_on_db(
                db,
                use_resume=use_resume,
                fp=fp,
                ah=ah,
                cv=cv,
                imp=imp,
                nfv=nfv,
            )
        log.info("started run_id=%s fingerprint=%s resume=%s", run_id, fp, use_resume)
        return run_id

    async def _begin_run_on_db(
        self,
        db: aiosqlite.Connection,
        *,
        use_resume: bool,
        fp: str,
        ah: str,
        cv: str,
        imp: str,
        nfv: str,
    ) -> int:
        if use_resume and fp:
            row = await db.execute(
                "SELECT id FROM runs WHERE fingerprint=? ORDER BY id DESC LIMIT 1",
                (fp,),
            )
            found = await row.fetchone()
            if found:
                self._run_id = int(found[0])
                log.info(
                    "resume: reusing run_id=%s fingerprint=%s",
                    self._run_id,
                    fp,
                )
                return self._run_id
        ts = time.strftime("%Y-%m-%dT%H:%M:%S")
        cur = await db.execute(
            """INSERT INTO runs
               (started_at, code_version, args_hash, fingerprint,
                impersonate, nfqws2_version)
               VALUES(?,?,?,?,?,?)""",
            (ts, cv, ah, fp, imp, nfv),
        )
        await db.commit()
        self._run_id = int(cur.lastrowid)
        return self._run_id

    async def _ensure_run_id_on_db(self, db: aiosqlite.Connection) -> int:
        if self._run_id is not None:
            return self._run_id
        return await self._begin_run_on_db(
            db,
            use_resume=False,
            fp="",
            ah="",
            cv=__version__,
            imp=_resolve_impersonate(),
            nfv=_probe_nfqws2_version(),
        )

    def _tcp_row_values(self, run_id: int, sid: int, entry: dict) -> tuple:
        return (
            run_id,
            sid,
            entry["domain"],
            entry["status"],
            entry["http_code"],
            entry["latency_ms"],
            entry["gateway_ms"],
            entry["content_valid"],
            entry["error"],
            entry.get("timestamp") or self._row_timestamp(),
            entry["read_rate_bps"],
            entry["resolved_ip"],
            entry["dns_verdict"],
            entry["doh_server"],
            entry.get("fail_phase") or "",
            None if entry.get("bridge_applied") is None else int(entry["bridge_applied"]),
            entry.get("bridge_batch_id") or 0,
            entry.get("bridge_gen") or 0,
            entry.get("probe_host") or "",
            entry.get("epoch_ms"),
            entry.get("settle_ms"),
            entry.get("content_len"),
        )

    async def close(self) -> None:
        if self._flush_timer_task is not None:
            self._flush_timer_task.cancel()
            try:
                await self._flush_timer_task
            except asyncio.CancelledError:
                pass
            self._flush_timer_task = None
        await self.flush()
        await self.compact()
        async with self._write_lock:
            await self._close_writer()
        reclaim_sudo_ownership(self._path)

    def _row_timestamp(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%S")

    def _mark_pending(self) -> None:
        if self._pending_since is None:
            self._pending_since = time.monotonic()
        self._ensure_flush_timer()

    def _clear_pending_clock(self) -> None:
        self._pending_since = None

    def _ensure_flush_timer(self) -> None:
        if self.batch_size <= 0 or self._flush_timer_task is not None:
            return
        self._flush_timer_task = asyncio.create_task(self._flush_timer_loop())

    async def _flush_timer_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(self._flush_interval)
                if self._tcp_pending or self._udp_pending:
                    await self.flush()
        except asyncio.CancelledError:
            raise

    async def _ensure_strategy_cached(
        self,
        cache: dict[tuple[str, str], int],
        name: str,
        proto: str,
        config_path: str,
        db: aiosqlite.Connection,
    ) -> int:
        key = (name, proto)
        sid = cache.get(key)
        if sid is not None:
            return sid
        sid = await self.ensure_strategy(name, proto, config_path, db=db)
        cache[key] = sid
        return sid

    async def _maybe_flush_by_age(self) -> None:
        if self._pending_since is None:
            return
        if time.monotonic() - self._pending_since >= self._flush_interval:
            await self.flush()

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
        self,
        name: str,
        proto: str,
        config_path: str,
        db: aiosqlite.Connection | None = None,
    ) -> int:
        """Insert or get strategy ID. Reuses open `db` when provided."""

        async def _body(conn, commit: bool) -> int:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await conn.execute(
                _ENSURE_STRATEGY_SQL,
                (name, proto, config_path, ts),
            )
            row = await conn.execute(_SELECT_STRATEGY_ID_SQL, (name, proto))
            found = await row.fetchone()
            if found is None:
                raise RuntimeError(f"strategy upsert vanished: {name!r} {proto!r}")
            if commit:
                await conn.commit()
            return int(found[0])

        if db is not None:
            return await _body(db, commit=False)
        async with self._write_lock:
            conn = await self._writer()
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
                        async with self._write_lock:
                            db = await self._writer()
                            run_id = await self._ensure_run_id_on_db(db)
                            await db.execute("BEGIN IMMEDIATE")
                            try:
                                strategy_cache: dict[tuple[str, str], int] = {}
                                tcp_rows: list[tuple] = []
                                for entry in tcp_batch:
                                    sid = await self._ensure_strategy_cached(
                                        strategy_cache,
                                        entry["strategy"],
                                        entry["proto"],
                                        entry["config_path"],
                                        db,
                                    )
                                    tcp_rows.append(self._tcp_row_values(run_id, sid, entry))
                                if tcp_rows:
                                    await db.executemany(_TCP_INSERT_SQL, tcp_rows)
                                udp_rows: list[tuple] = []
                                for entry in udp_batch:
                                    sid = await self._ensure_strategy_cached(
                                        strategy_cache,
                                        entry["strategy"],
                                        "udp",
                                        entry["config_path"],
                                        db,
                                    )
                                    udp_rows.append(
                                        (
                                            run_id,
                                            sid,
                                            entry["target"],
                                            entry["status"],
                                            entry["latency_ms"],
                                            entry["error"],
                                            entry.get("timestamp") or self._row_timestamp(),
                                            entry.get("epoch_ms"),
                                        )
                                    )
                                if udp_rows:
                                    await db.executemany(_UDP_INSERT_SQL, udp_rows)
                                await db.commit()
                            except Exception:
                                await db.rollback()
                                raise
                        await self._maybe_wal_checkpoint()
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
            self._clear_pending_clock()

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
        bridge_applied: bool | None = None,
        bridge_batch_id: int = 0,
        bridge_gen: int = 0,
        probe_host: str = "",
        settle_ms: float | None = None,
        content_len: int | None = None,
    ) -> None:
        epoch_ms = int(time.time() * 1000)
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
                    "timestamp": self._row_timestamp(),
                    "read_rate_bps": float(read_rate_bps or 0.0),
                    "resolved_ip": resolved_ip or "",
                    "dns_verdict": dns_verdict or "",
                    "doh_server": doh_server or "",
                    "fail_phase": fail_phase or "",
                    "bridge_applied": bridge_applied,
                    "probe_host": probe_host or "",
                    "bridge_batch_id": int(bridge_batch_id or 0),
                    "bridge_gen": int(bridge_gen or 0),
                    "epoch_ms": epoch_ms,
                    "settle_ms": settle_ms,
                    "content_len": content_len,
                }
            )
            self._mark_pending()
            if len(self._tcp_pending) >= self.batch_size:
                await self.flush()
            else:
                await self._maybe_flush_by_age()
            return
        async with self._write_lock:
            db = await self._writer()
            run_id = await self._ensure_run_id_on_db(db)
            sid = await self.ensure_strategy(strategy, proto, config_path or strategy, db=db)
            ts = self._row_timestamp()
            await db.execute(
                _TCP_INSERT_SQL,
                (
                    run_id,
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
                    None if bridge_applied is None else int(bridge_applied),
                    int(bridge_batch_id or 0),
                    int(bridge_gen or 0),
                    probe_host or "",
                    epoch_ms,
                    settle_ms,
                    content_len,
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
        epoch_ms = int(time.time() * 1000)
        if self.batch_size > 0:
            self._udp_pending.append(
                {
                    "strategy": strategy,
                    "config_path": config_path or strategy,
                    "target": target,
                    "status": status,
                    "latency_ms": latency_ms,
                    "error": error,
                    "timestamp": self._row_timestamp(),
                    "epoch_ms": epoch_ms,
                }
            )
            self._mark_pending()
            if len(self._udp_pending) >= self.batch_size:
                await self.flush()
            else:
                await self._maybe_flush_by_age()
            return
        async with self._write_lock:
            db = await self._writer()
            run_id = await self._ensure_run_id_on_db(db)
            sid = await self.ensure_strategy(strategy, "udp", config_path or strategy, db=db)
            ts = self._row_timestamp()
            await db.execute(
                _UDP_INSERT_SQL,
                (run_id, sid, target, status, latency_ms, error, ts, epoch_ms),
            )
            await db.commit()

    async def quarantine_domain(
        self, domain: str, *, reason: str = "", failed: int = 0
    ) -> None:
        """Persist one quarantined domain (rare event — write immediately)."""
        async with self._write_lock:
            db = await self._writer()
            await db.execute(
                """INSERT INTO quarantined (domain, reason, failed, created)
                   VALUES(?,?,?,?)
                   ON CONFLICT(domain) DO UPDATE SET
                     reason=excluded.reason, failed=excluded.failed""",
                (
                    domain,
                    reason or "",
                    int(failed or 0),
                    time.strftime("%Y-%m-%dT%H:%M:%S"),
                ),
            )
            await db.commit()

    async def get_quarantined(self) -> list[dict]:
        """All quarantined domains recorded for this campaign DB."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            cur = await db.execute(
                "SELECT domain, reason, failed, created FROM quarantined ORDER BY created"
            )
            rows = await cur.fetchall()
        return [
            {"domain": r[0], "reason": r[1], "failed": r[2], "created": r[3]}
            for r in rows
        ]

    async def domain_pass_rows(self) -> list[tuple[str, int, int]]:
        """Bulk (domain, total_attempts, total_passed) for quarantine seeding.

        ``total_passed`` counts rows whose status is PASS or THROTTLED (working
        probes), matching latest-row working semantics elsewhere in the store.
        """
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            cur = await db.execute(
                f"SELECT domain, COUNT(*), "
                f"SUM(CASE WHEN status IN {_WORKING_STATUSES} THEN 1 ELSE 0 END) "
                f"FROM tcp_results GROUP BY domain"
            )
            rows = await cur.fetchall()
        return [(r[0], int(r[1] or 0), int(r[2] or 0)) for r in rows]

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
        async with self._write_lock:
            db = await self._writer()
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
        async with self._write_lock:
            db = await self._writer()
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
        async with self._write_lock:
            db = await self._writer()
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
        """True if any tcp_results row exists for strategy×domain in the current run."""
        async with self._write_lock:
            db = await self._writer()
            run_id = await self._ensure_run_id_on_db(db)
            row = await db.execute(
                """SELECT 1 FROM tcp_results t
                   JOIN strategies s ON t.strategy_id = s.id
                   WHERE s.name=? AND s.proto=? AND t.domain=? AND t.run_id=?
                   LIMIT 1""",
                (strategy, proto, domain, run_id),
            )
            return await row.fetchone() is not None

    async def get_completed_tcp_keys(self, proto: str = "tcp") -> set[tuple[str, str]]:
        """(strategy_name, domain) pairs whose *latest* row is working — resume skip.

        Only latest-row PASS/THROTTLED in the **current run** count as completed.
        FAIL, SKIPPED, and other non-working statuses are excluded.
        """
        if self._run_id is None:
            return set()
        run_id = self._run_id
        async with self._write_lock:
            db = await self._writer()
            rows = await db.execute(
                f"""SELECT s.name, t.domain
                   FROM tcp_results t
                   JOIN strategies s ON t.strategy_id = s.id
                   WHERE s.proto=? AND t.run_id=?
                     AND t.id = (
                       SELECT t2.id FROM tcp_results t2
                       WHERE t2.strategy_id = t.strategy_id AND t2.domain = t.domain
                         AND t2.run_id = ?
                       ORDER BY t2.id DESC LIMIT 1
                     )
                     AND t.status IN {_WORKING_STATUSES}""",
                (proto, run_id, run_id),
            )
            return {(r[0], r[1]) for r in await rows.fetchall()}

    async def _count_infra_fail_rows(
        self,
        db: aiosqlite.Connection,
        strategy: str,
        domain: str,
        proto: str,
        run_id: int,
    ) -> int:
        from blockchecks.engine.fail_phase import is_infra_fail_phase

        rows = await db.execute(
            """SELECT t.fail_phase, t.error
               FROM tcp_results t
               JOIN strategies s ON t.strategy_id = s.id
               WHERE s.name=? AND s.proto=? AND t.domain=? AND t.run_id=?
                 AND t.status='FAIL'""",
            (strategy, proto, domain, run_id),
        )
        count = 0
        for fail_phase, error in await rows.fetchall():
            if is_infra_fail_phase(fail_phase or "", error=error or ""):
                count += 1
        return count

    async def get_resume_skip_tcp_keys(
        self, proto: str = "tcp", *, reprobe_failed: int = 0
    ) -> set[tuple[str, str]]:
        """Keys to skip on ``--resume``: WORKING plus optional DPI/exhausted infra FAIL.

        When ``reprobe_failed`` is 0, only latest-row PASS/THROTTLED are skipped
        (same as ``get_completed_tcp_keys``).  When N>0, latest-row DPI-shaped
        FAIL is skipped, and infra FAIL is skipped only after N infra FAIL rows.
        """
        from blockchecks.engine.fail_phase import is_infra_fail_phase

        working = await self.get_completed_tcp_keys(proto)
        if reprobe_failed <= 0:
            return working
        if self._run_id is None:
            return working

        run_id = self._run_id
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute(
                """SELECT s.name, t.domain, t.fail_phase, t.error
                   FROM tcp_results t
                   JOIN strategies s ON t.strategy_id = s.id
                   WHERE s.proto=? AND t.run_id=?
                     AND t.id = (
                       SELECT t2.id FROM tcp_results t2
                       WHERE t2.strategy_id = t.strategy_id AND t2.domain = t.domain
                         AND t2.run_id = ?
                       ORDER BY t2.id DESC LIMIT 1
                     )
                     AND t.status = 'FAIL'""",
                (proto, run_id, run_id),
            )
            latest_fails = await rows.fetchall()

            skip_fail: set[tuple[str, str]] = set()
            reprobe_keys: list[tuple[str, str]] = []
            for name, domain, fail_phase, error in latest_fails:
                key = (name, domain)
                if key in working:
                    continue
                err = error or ""
                phase = fail_phase or ""
                if is_infra_fail_phase(phase, error=err):
                    infra_count = await self._count_infra_fail_rows(
                        db, name, domain, proto, run_id
                    )
                    if infra_count < reprobe_failed:
                        reprobe_keys.append(key)
                        continue
                else:
                    if not phase and any(
                        m in err for m in ("dev/shm", "ns pool exhausted", "stopped before probe")
                    ):
                        log.debug(
                            "resume reprobe: infra FAIL via error fallback %s×%s",
                            name,
                            domain,
                        )
                    else:
                        log.debug(
                            "resume reprobe: DPI-shaped FAIL skip %s×%s fail_phase=%r",
                            name,
                            domain,
                            phase,
                        )
                skip_fail.add(key)

        if reprobe_keys:
            log.info(
                "resume: re-queuing %d infra-fail pairs (reprobe_failed=%d, count < %d)",
                len(reprobe_keys),
                reprobe_failed,
                reprobe_failed,
            )
        return working | skip_fail

    async def get_best_tcp(self, domain: str, *, limit: int = 5) -> list[dict]:
        """Latest PASS/THROTTLED per strategy for domain, ordered by latency_ms ASC."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute(
                f"""SELECT s.name, t.latency_ms, t.http_code, t.timestamp, t.probe_host
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
            cols = ["strategy", "latency_ms", "http_code", "timestamp", "probe_host"]
            return [dict(zip(cols, r)) for r in await rows.fetchall()]

    async def get_best_quic(self, domain: str, *, limit: int = 5) -> list[dict]:
        """Latest PASS/THROTTLED per QUIC strategy for domain, ordered by latency_ms ASC."""
        async with aiosqlite.connect(self._path) as db:
            await SqliteRunStore._apply_pragmas(db)
            rows = await db.execute(
                f"""SELECT s.name, t.latency_ms, t.http_code, t.timestamp, t.probe_host
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
            cols = ["strategy", "latency_ms", "http_code", "timestamp", "probe_host"]
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
        async with self._write_lock:
            db = await self._writer()
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
        async with self._write_lock:
            db = await self._writer()
            await db.execute(
                """INSERT INTO triage_snapshots(domain, payload_json, created_at)
                   VALUES(?,?,?)""",
                (domain or "", json.dumps(payload, ensure_ascii=False), ts),
            )
            await db.commit()
