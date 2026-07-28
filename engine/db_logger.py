"""State DB — aiosqlite-powered persistent results log.

Tables:
  strategies    — registry of TCP/UDP strategy config paths
  tcp_results   — HTTP/TLS test results per strategy+domain
  udp_results   — STUN probe results per strategy+target
  pair_results  — aggregated TCP×UDP pair outcomes
  checkpoints   — (tcp_idx, udp_idx, timestamp) for --resume

Usage:
  db = StateDB("state.db")
  await db.init()
  await db.log_tcp_result(strategy, domain, status, latency, http_code, gateway_ms)
  tcp_idx, udp_idx = await db.latest_checkpoint()
  await db.save_checkpoint(tcp_idx, udp_idx)
"""

import os
import time
import aiosqlite
from typing import Optional
from pathlib import Path


class StateDB:
    def __init__(self, db_path: str = "state.db"):
        self.db_path = db_path

    async def init(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript("""
                CREATE TABLE IF NOT EXISTS strategies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    proto TEXT NOT NULL DEFAULT 'tcp',  -- 'tcp' or 'udp'
                    config_path TEXT NOT NULL,
                    first_seen TEXT NOT NULL DEFAULT '',
                    UNIQUE(name, proto)
                );
                CREATE TABLE IF NOT EXISTS tcp_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    strategy_id INTEGER REFERENCES strategies(id),
                    domain TEXT NOT NULL,
                    status TEXT NOT NULL,       -- PASS, FAIL, SKIP
                    http_code INTEGER DEFAULT 0,
                    latency_ms REAL DEFAULT 0,
                    gateway_ws_ms REAL DEFAULT 0,
                    content_valid INTEGER DEFAULT 0,
                    error TEXT DEFAULT '',
                    timestamp TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS udp_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    strategy_id INTEGER REFERENCES strategies(id),
                    target TEXT NOT NULL,        -- ip:port
                    status TEXT NOT NULL,        -- PASS, FAIL, SKIP
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
                    overall TEXT NOT NULL,       -- PASS, PARTIAL, FAIL
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
            """)
            await db.commit()
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute("PRAGMA busy_timeout=5000")

    # ── Strategy registry ──────────────────────────

    async def ensure_strategy(self, name: str, proto: str,
                               config_path: str) -> int:
        """Insert or get strategy ID."""
        async with aiosqlite.connect(self.db_path) as db:
            row = await db.execute(
                "SELECT id FROM strategies WHERE name=? AND proto=?", (name, proto)
            )
            existing = await row.fetchone()
            if existing:
                return existing[0]
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            cur = await db.execute(
                "INSERT INTO strategies(name,proto,config_path,first_seen) VALUES(?,?,?,?)",
                (name, proto, config_path, ts)
            )
            await db.commit()
            return cur.lastrowid

    # ── Results logging ────────────────────────────

    async def log_tcp(self, strategy: str, domain: str,
                       status: str, latency_ms: float,
                       http_code: int = 0, gateway_ms: float = 0,
                       content_valid: bool = True,
                       error: str = "") -> None:
        async with aiosqlite.connect(self.db_path) as db:
            sid = await self.ensure_strategy(strategy, "tcp", strategy)
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                """INSERT INTO tcp_results
                   (strategy_id,domain,status,http_code,latency_ms,
                    gateway_ws_ms,content_valid,error,timestamp)
                   VALUES(?,?,?,?,?,?,?,?,?)""",
                (sid, domain, status, http_code, latency_ms,
                 gateway_ms, int(content_valid), error, ts)
            )
            await db.commit()

    async def log_udp(self, strategy: str, target: str,
                       status: str, latency_ms: float = 0,
                       error: str = "") -> None:
        async with aiosqlite.connect(self.db_path) as db:
            sid = await self.ensure_strategy(strategy, "udp", strategy)
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                """INSERT INTO udp_results
                   (strategy_id,target,status,latency_ms,error,timestamp)
                   VALUES(?,?,?,?,?,?)""",
                (sid, target, status, latency_ms, error, ts)
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
                 tcp_ms, gateway_ms, udp_ms, overall, ts)
            )
            await db.commit()

    # ── Checkpoints ────────────────────────────────

    async def save_checkpoint(self, tcp_idx: int, udp_idx: int,
                                note: str = "", fingerprint: str = "",
                                tcp_label: str = "", udp_label: str = "") -> None:
        async with aiosqlite.connect(self.db_path) as db:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S")
            await db.execute(
                "INSERT INTO checkpoints(tcp_idx,udp_idx,fingerprint,tcp_label,udp_label,timestamp,note) VALUES(?,?,?,?,?,?,?)",
                (tcp_idx, udp_idx, fingerprint, tcp_label, udp_label, ts, note)
            )
            await db.commit()

    async def latest_checkpoint(self) -> Optional[tuple[int, int, str, str, str, str]]:
        """Return (tcp_idx, udp_idx, timestamp, note) or None."""
        async with aiosqlite.connect(self.db_path) as db:
            row = await db.execute(
                "SELECT tcp_idx,udp_idx,timestamp,note,fingerprint,tcp_label FROM checkpoints ORDER BY id DESC LIMIT 1"
            )
            r = await row.fetchone()
            return r if r else None

    # ── Query helpers ──────────────────────────────

    async def get_working_tcp(self, domain: str) -> list[str]:
        """Get names of TCP strategies that passed for this domain."""
        async with aiosqlite.connect(self.db_path) as db:
            rows = await db.execute(
                """SELECT DISTINCT s.name FROM tcp_results t
                   JOIN strategies s ON t.strategy_id = s.id
                   WHERE t.domain=? AND t.status='PASS'""",
                (domain,)
            )
            return [r[0] for r in await rows.fetchall()]

    async def get_passing_pairs(self, domain: str) -> list[dict]:
        """Get all pairs where overall='PASS'."""
        async with aiosqlite.connect(self.db_path) as db:
            rows = await db.execute(
                """SELECT tcp_strategy,udp_strategy,tcp_ms,gateway_ms,udp_ms
                   FROM pair_results WHERE domain=? AND overall='PASS'""",
                (domain,)
            )
            cols = ["tcp", "udp", "tcp_ms", "gateway_ms", "udp_ms"]
            return [dict(zip(cols, r)) for r in await rows.fetchall()]
