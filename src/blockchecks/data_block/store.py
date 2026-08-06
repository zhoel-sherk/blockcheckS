"""ProviderStore — SQLite dns.db / strategies.db + hosts + best_config in data_block.

All writes go to ``data_block/providers/<provider>/`` (a git submodule).
Nothing is committed/pushed automatically; call ``ProviderStore.sync_commit()``
with ``push=True`` only when the ``--data-block-sync`` flag is set.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import aiosqlite

from blockchecks.engine.paths import reclaim_sudo_ownership

# Records older than this are re-validated via DoH instead of trusted from cache.
DATA_BLOCK_DNS_TTL = float(os.environ.get("BLOCKCHECKS_DATA_BLOCK_DNS_TTL", str(7 * 86400)))

_DNS_SCHEMA = """
CREATE TABLE IF NOT EXISTS dns_records (
    domain TEXT PRIMARY KEY,
    ips TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'doh',
    checked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dns_tampered (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    udp_ips TEXT DEFAULT '',
    doh_ips TEXT DEFAULT '',
    verdict TEXT DEFAULT '',
    checked_at TEXT NOT NULL
);
"""

_STRATEGIES_SCHEMA = """
CREATE TABLE IF NOT EXISTS pass_strategies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    strategy TEXT NOT NULL,
    domain TEXT NOT NULL,
    protocol TEXT DEFAULT 'tcp',
    latency_ms REAL DEFAULT 0,
    http_code INTEGER DEFAULT 0,
    approved INTEGER DEFAULT 0,
    checked_at TEXT NOT NULL,
    UNIQUE(strategy, domain)
);
"""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def _ts_to_epoch(ts: str) -> float:
    try:
        return time.mktime(time.strptime(ts, "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, OverflowError):
        return 0.0


class ProviderStore:
    """Read/write per-provider DNS cache and pass-strategy store."""

    def __init__(self, provider_dir: str | Path):
        self._dir = Path(provider_dir).expanduser().resolve()
        self._dir.mkdir(parents=True, exist_ok=True)
        reclaim_sudo_ownership(self._dir)
        self._ensure_md()

    @property
    def dns_db(self) -> Path:
        return self._dir / "dns.db"

    @property
    def strategies_db(self) -> Path:
        return self._dir / "strategies.db"

    @property
    def best_config(self) -> Path:
        return self._dir / "best_config.conf"

    @property
    def hosts_file(self) -> Path:
        return self._dir / "hosts"

    @property
    def provider_dir(self) -> Path:
        return self._dir

    def _ensure_md(self) -> None:
        """Create a stub ``<provider>.md`` when missing (user-filled notes)."""
        md = self._dir / f"{self._dir.name}.md"
        if md.exists():
            return
        try:
            md.write_text(
                f"# {self._dir.name}\n\n"
                "Провайдер-специфичные заметки: блоки, юзер-инфо, решения.\n\n"
                "## Блокировки\n\n"
                "## Проверенные стратегии\n\n"
                "## Примечания\n",
                encoding="utf-8",
            )
            reclaim_sudo_ownership(md)
        except OSError:
            pass

    # ── dns.db ────────────────────────────────────────────

    async def _init_dns(self) -> aiosqlite.Connection:
        db = await aiosqlite.connect(self.dns_db)
        await db.executescript(_DNS_SCHEMA)
        await db.commit()
        return db

    async def save_dns_records(
        self, records: dict[str, list[str]], *, source: str = "doh"
    ) -> None:
        """Upsert verified DoH IPs into dns_records."""
        if not records:
            return
        db = await self._init_dns()
        try:
            ts = _now()
            for domain, ips in records.items():
                if not domain or not ips:
                    continue
                await db.execute(
                    """INSERT INTO dns_records (domain, ips, source, checked_at)
                       VALUES (?,?,?,?)
                       ON CONFLICT(domain) DO UPDATE SET
                         ips=excluded.ips,
                         source=excluded.source,
                         checked_at=excluded.checked_at""",
                    (domain, ", ".join(dict.fromkeys(ips)), source, ts),
                )
            await db.commit()
        finally:
            await db.close()

    async def save_dns_tampered(self, rows: list[dict]) -> None:
        """Append tampered audit rows into dns_tampered."""
        if not rows:
            return
        db = await self._init_dns()
        try:
            ts = _now()
            for r in rows:
                await db.execute(
                    """INSERT INTO dns_tampered (domain, udp_ips, doh_ips, verdict, checked_at)
                       VALUES (?,?,?,?,?)""",
                    (
                        r.get("domain", ""),
                        r.get("udp_ips", ""),
                        r.get("doh_ips", ""),
                        r.get("verdict", ""),
                        r.get("checked_at") or ts,
                    ),
                )
            await db.commit()
        finally:
            await db.close()

    async def load_dns_records(self) -> dict[str, tuple[list[str], str]]:
        """Return fresh (within DATA_BLOCK_DNS_TTL) records: domain -> (ips, checked_at)."""
        if not self.dns_db.is_file():
            return {}
        db = await aiosqlite.connect(self.dns_db)
        try:
            cur = await db.execute(
                "SELECT domain, ips, checked_at FROM dns_records"
            )
            rows = await cur.fetchall()
        finally:
            await db.close()
        cutoff = time.time() - DATA_BLOCK_DNS_TTL
        out: dict[str, tuple[list[str], str]] = {}
        for domain, ips, checked_at in rows:
            if _ts_to_epoch(checked_at) < cutoff:
                continue
            parsed = [ip.strip() for ip in str(ips).split(",") if ip.strip()]
            if parsed:
                out[domain] = (parsed, checked_at)
        return out

    def load_dns_records_sync(self) -> dict[str, tuple[list[str], str]]:
        """Sync variant of load_dns_records (sqlite3 stdlib) for sync callers.

        Same TTL cutoff as the async version.  Uses stdlib sqlite3 so it works
        from a sync context (e.g. DnsRunCache.resolve) without an event loop.
        """
        import sqlite3

        if not self.dns_db.is_file():
            return {}
        cutoff = time.time() - DATA_BLOCK_DNS_TTL
        out: dict[str, tuple[list[str], str]] = {}
        try:
            con = sqlite3.connect(self.dns_db, timeout=5.0)
            try:
                for domain, ips, checked_at in con.execute(
                    "SELECT domain, ips, checked_at FROM dns_records"
                ):
                    if _ts_to_epoch(checked_at) < cutoff:
                        continue
                    parsed = [ip.strip() for ip in str(ips).split(",") if ip.strip()]
                    if parsed:
                        out[domain] = (parsed, checked_at)
            finally:
                con.close()
        except sqlite3.Error:
            return {}
        return out

    # ── strategies.db ─────────────────────────────────────

    async def _init_strategies(self) -> aiosqlite.Connection:
        db = await aiosqlite.connect(self.strategies_db)
        await db.executescript(_STRATEGIES_SCHEMA)
        await db.commit()
        return db

    async def upsert_pass_strategy(
        self,
        strategy: str,
        domain: str,
        *,
        protocol: str = "tcp",
        latency_ms: float = 0.0,
        http_code: int = 0,
        approved: bool = False,
    ) -> None:
        db = await self._init_strategies()
        try:
            await db.execute(
                """INSERT INTO pass_strategies
                       (strategy, domain, protocol, latency_ms, http_code, approved, checked_at)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT(strategy, domain) DO UPDATE SET
                     protocol=excluded.protocol,
                     latency_ms=excluded.latency_ms,
                     http_code=excluded.http_code,
                     approved=excluded.approved,
                     checked_at=excluded.checked_at""",
                (strategy, domain, protocol, latency_ms, http_code, int(approved), _now()),
            )
            await db.commit()
        finally:
            await db.close()

    async def pass_strategies(self, *, approved_only: bool = False) -> list[dict]:
        if not self.strategies_db.is_file():
            return []
        db = await aiosqlite.connect(self.strategies_db)
        try:
            q = "SELECT strategy, domain, protocol, latency_ms, http_code, approved, checked_at FROM pass_strategies"
            if approved_only:
                q += " WHERE approved = 1"
            cur = await db.execute(q)
            rows = await cur.fetchall()
        finally:
            await db.close()
        keys = ("strategy", "domain", "protocol", "latency_ms", "http_code", "approved", "checked_at")
        return [dict(zip(keys, row, strict=False)) for row in rows]

    # ── hosts file (Windows anti-hijack) ──────────────────

    def write_hosts(self, records: dict[str, list[str] | tuple[list[str], str]]) -> Path:
        """Regenerate the anti-hijack hosts file (first IP per domain).

        Accepts either ``domain -> [ips]`` or ``domain -> (ips, checked_at)``.
        """
        lines = [
            "# Generated by blockcheckS — verified DoH records (anti-hijack).",
            "# Copy to C:\\Windows\\System32\\drivers\\etc\\hosts on Windows.",
        ]
        for domain, value in sorted(records.items()):
            ips = value[0] if isinstance(value, tuple) else value
            if ips:
                lines.append(f"{ips[0]}\t{domain}")
        self.hosts_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        reclaim_sudo_ownership(self.hosts_file)
        return self.hosts_file

    # ── best_config.conf ──────────────────────────────────

    def write_best_config(self, content: str) -> Path:
        """Write the best nfqws2 config; skip when content is unchanged."""
        if self.best_config.is_file() and self.best_config.read_text(encoding="utf-8") == content:
            return self.best_config
        self.best_config.write_text(content, encoding="utf-8")
        reclaim_sudo_ownership(self.best_config)
        return self.best_config

    # ── sync (opt-in) ─────────────────────────────────────

    def sync_commit(self, *, push: bool = False) -> bool:
        """Commit data_block changes locally; push only if requested."""
        repo = self._dir.parents[1]  # .../data_block
        if not (repo / ".git").exists():
            return False
        for cmd in (
            ["git", "add", "-A"],
            ["git", "commit", "-m", f"sync: update provider data ({_now()})"],
        ):
            r = subprocess.run(
                cmd, cwd=repo, capture_output=True, text=True, timeout=30
            )
            if r.returncode != 0 and "nothing to commit" not in r.stdout + r.stderr:
                print(f"  [data_block] git {cmd[1]} failed: {r.stderr[:200]}")
                return False
        if push:
            r = subprocess.run(
                ["git", "push"], cwd=repo, capture_output=True, text=True, timeout=60
            )
            if r.returncode != 0:
                print(
                    f"  WARNING: data_block push failed (creds?): {r.stderr[:200]}"
                )
                return False
        return True


def write_hosts_file(
    provider_dir: str | Path, records: dict[str, list[str] | tuple[list[str], str]]
) -> Path:
    return ProviderStore(provider_dir).write_hosts(records)


def write_best_config(provider_dir: str | Path, content: str) -> Path:
    return ProviderStore(provider_dir).write_best_config(content)
