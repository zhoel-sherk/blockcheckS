"""SQLite dns.db / strategies.db plus hosts, best_config.conf, and triage.toml for one provider."""

from __future__ import annotations

import logging
import os
import subprocess
import time
from pathlib import Path

import aiosqlite

from blockchecks.engine.paths import reclaim_sudo_ownership

log = logging.getLogger(__name__)


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
                "Provider notes: blocks, user info, working strategies.\n\n"
                "## Blocks\n\n"
                "## Working strategies\n\n"
                "## Notes\n",
                encoding="utf-8",
            )
            reclaim_sudo_ownership(md)
        except OSError:
            pass

    # dns.db

    async def _init_dns(self) -> aiosqlite.Connection:
        db = await aiosqlite.connect(self.dns_db)
        await db.executescript(_DNS_SCHEMA)
        await db.commit()
        return db

    async def save_dns_records(self, records: dict[str, list[str]], *, source: str = "doh") -> None:
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
            cur = await db.execute("SELECT domain, ips, checked_at FROM dns_records")
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

    # strategies.db

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
        keys = (
            "strategy",
            "domain",
            "protocol",
            "latency_ms",
            "http_code",
            "approved",
            "checked_at",
        )
        return [dict(zip(keys, row, strict=False)) for row in rows]

    # hosts file (Windows anti-hijack)

    def write_hosts(self, records: dict[str, list[str] | tuple[list[str], str]]) -> Path:
        """Regenerate the anti-hijack hosts file (first IP per domain).

        Accepts either ``domain -> [ips]`` or ``domain -> (ips, checked_at)``.

        Existing pinned/verified entries not present in ``records`` are kept
        (merge with the current hosts file), so a run that audits only a few
        domains does not wipe unrelated pinned hosts entries.
        """
        from blockchecks.checkers.ip_pin import merge_pins, parse_pins

        try:
            existing = parse_pins(self.hosts_file.read_text(encoding="utf-8"))
        except OSError:
            existing = {}

        new_records: dict[str, str] = {}
        for domain, value in records.items():
            ips = value[0] if isinstance(value, tuple) else value
            if ips:
                new_records[domain] = ips[0]

        merged = merge_pins(existing, new_records)
        lines = [
            "# Generated by blockcheckS — verified DoH records (anti-hijack).",
            "# Copy to C:\\Windows\\System32\\drivers\\etc\\hosts on Windows.",
            "# Auto-refreshed by blockcheckS IP pinning; hand-editable.",
        ]
        for domain in sorted(merged):
            lines.append(f"{merged[domain]}\t{domain}")
        self.hosts_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        reclaim_sudo_ownership(self.hosts_file)
        return self.hosts_file

    # best_config.conf

    def write_best_config(self, content: str) -> Path:
        """Write the best nfqws2 config; skip when content is unchanged."""
        if self.best_config.is_file() and self.best_config.read_text(encoding="utf-8") == content:
            return self.best_config
        self.best_config.write_text(content, encoding="utf-8")
        reclaim_sudo_ownership(self.best_config)
        return self.best_config

    # triage.toml

    @property
    def triage_file(self) -> Path:
        return self._dir / "triage.toml"

    def save_triage(self, profile, *, primary_domain: str = "") -> Path:
        """Write ISP triage prior next to best_config.conf."""
        text = _dump_triage_toml(profile, primary_domain=primary_domain)
        self.triage_file.write_text(text, encoding="utf-8")
        reclaim_sudo_ownership(self.triage_file)
        return self.triage_file

    def load_triage(self):
        """Load ``triage.toml`` if present; ``None`` when missing/invalid."""
        path = self.triage_file
        if not path.is_file():
            return None
        try:
            import tomllib

            raw = tomllib.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning("%s", f"  WARNING: triage.toml unreadable ({exc})")
            return None
        from blockchecks.engine.triage import TriageProfile

        return TriageProfile.from_dict(_flatten_triage_toml(raw))

    # sync (opt-in)

    def sync_commit(self, *, push: bool = False) -> bool:
        """Commit data_block changes locally; push only if requested.

        When running as root via sudo, git is re-invoked as the original user
        (``sudo -u $SUDO_USER``) so its credentials (gh helper) are available —
        otherwise ``git push`` fails with "could not read Username".
        """
        repo = self._dir.parents[1]  # .../data_block
        if not (repo / ".git").exists():
            return False
        prefix: list[str] = []
        if os.geteuid() == 0:
            sudo_user = os.environ.get("SUDO_USER", "").strip()
            if sudo_user:
                prefix = ["sudo", "-u", sudo_user]
        for cmd in (
            ["git", "add", "-A"],
            ["git", "commit", "-m", f"sync: update provider data ({_now()})"],
        ):
            r = subprocess.run(prefix + cmd, cwd=repo, capture_output=True, text=True, timeout=30)
            if r.returncode != 0 and "nothing to commit" not in r.stdout + r.stderr:
                log.info("%s", f"  [data_block] git {cmd[1]} failed: {r.stderr[:200]}")
                return False
        if push:
            r = subprocess.run(
                prefix + ["git", "push"], cwd=repo, capture_output=True, text=True, timeout=60
            )
            if r.returncode != 0:
                log.warning("%s", f"  WARNING: data_block push failed (creds?): {r.stderr[:200]}")
                return False
        return True


def _toml_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _toml_list(values: list[str]) -> str:
    return "[" + ", ".join(_toml_str(v) for v in values) + "]"


def _toml_bool(value: bool) -> str:
    return "true" if value else "false"


def _flag_lines(d: dict) -> list[str]:
    extra = [
        *(
            [f"ech_blocked = {_toml_bool(bool(d.get('ech_blocked')))}"]
            if d.get("ech_blocked") is not None
            else []
        ),
        *(
            [f"http_blocked = {_toml_bool(bool(d.get('http_blocked')))}"]
            if d.get("http_blocked") is not None
            else []
        ),
    ]
    return [
        f"silent_drop_after_sni = {_toml_bool(bool(d.get('silent_drop_after_sni')))}",
        f"rst_at_sni = {_toml_bool(bool(d.get('rst_at_sni')))}",
        f"voice_ok = {_toml_bool(bool(d.get('voice_ok')))}",
        f"udp_blocked = {_toml_bool(bool(d.get('udp_blocked')))}",
        f"dns_hijacked = {_toml_bool(bool(d.get('dns_hijacked')))}",
        f"dns_sinkhole = {_toml_bool(bool(d.get('dns_sinkhole')))}",
        *extra,
    ]


def _hop_lines(d: dict) -> list[str]:
    return [
        f"{key} = {int(d[key])}"
        for key in ("server_hops", "dpi_hops", "autottl_delta")
        if d.get(key) is not None
    ]


def _dump_triage_toml(profile, *, primary_domain: str = "") -> str:
    d = profile.to_dict()
    from blockchecks.engine.triage import cluster_domain_reports, clustered_primary_domain

    reports = getattr(profile, "domain_reports", None) or d.get("domain_reports") or {}
    clusters = cluster_domain_reports(reports)
    top = clustered_primary_domain(reports, fallback=primary_domain)
    notes = ["send:repeats=6 → SSL 35 on L4-checksum-normalizing DPI"]
    hops = _hop_lines(d)
    cluster_block = _cluster_toml_lines(clusters)
    return "\n".join(
        [
            "version = 1",
            f"updated_at = {_toml_str(_now())}",
            f"primary_domain = {_toml_str(top or '')}",
            "",
            "[flags]",
            *_flag_lines(d),
            "",
            "[hops]",
            *(hops or ["# hops unknown"]),
            "",
            "[viable]",
            f"foolings = {_toml_list(list(d.get('viable_foolings') or []))}",
            f"blobs = {_toml_list(list(d.get('viable_blobs') or []))}",
            f"split_mode = {_toml_str(str(d.get('split_mode') or ''))}",
            *(
                [f"hosts = {_toml_list(list(d.get('viable_hosts') or []))}"]
                if d.get("viable_hosts")
                else []
            ),
            "",
            "[dead]",
            f"foolings = {_toml_list(list(d.get('dead_foolings') or []))}",
            f"notes = {_toml_list(notes)}",
            *_dpi_diag_lines(d),
            *cluster_block,
            "",
        ]
    )


def _dpi_diag_lines(d: dict) -> list[str]:
    diag = d.get("dpi_diag") or {}
    if not diag:
        return []
    return [
        "",
        "[dpi_diag]",
        f"sni_whitelist = {_toml_list(list(diag.get('sni_whitelist') or []))}",
        f"dns_as_mismatch = {_toml_list(list(diag.get('dns_as_mismatch') or []))}",
        f"cgnat_sinkhole = {_toml_list(list(diag.get('cgnat_sinkhole') or []))}",
    ]


def _cluster_toml_lines(clusters: list[dict]) -> list[str]:
    if len(clusters) < 2:
        return []
    return [line for cluster in clusters for line in _one_cluster_lines(cluster)]


def _one_cluster_lines(cluster: dict) -> list[str]:
    keys = (
        "phase",
        "l3",
        "stall",
        "rst_at_sni",
        "silent_drop",
        "quic_drop",
        "ip_blocked",
        "prolog_ok",
    )

    def _line(key: str) -> str:
        val = cluster[key]
        if isinstance(val, bool):
            return f"{key} = {_toml_bool(val)}"
        return f"{key} = {_toml_str(str(val))}"

    extras = [_line(key) for key in keys if key in cluster and cluster[key] is not None]
    return [
        "",
        "[[cluster]]",
        f"primary_domain = {_toml_str(cluster.get('primary_domain') or '')}",
        *extras,
    ]


def _flatten_triage_toml(raw: dict) -> dict:
    flags = dict(raw.get("flags") or {})
    hops = dict(raw.get("hops") or {})
    viable = dict(raw.get("viable") or {})
    dead = dict(raw.get("dead") or {})
    return {
        **flags,
        **hops,
        "viable_foolings": list(viable.get("foolings") or []),
        "viable_blobs": list(viable.get("blobs") or []),
        "split_mode": str(viable.get("split_mode") or ""),
        "dead_foolings": list(dead.get("foolings") or []),
        "viable_hosts": list(viable.get("hosts") or []),
        "dpi_diag": dict(raw.get("dpi_diag") or {}),
    }


def write_hosts_file(
    provider_dir: str | Path, records: dict[str, list[str] | tuple[list[str], str]]
) -> Path:
    return ProviderStore(provider_dir).write_hosts(records)


def write_best_config(provider_dir: str | Path, content: str) -> Path:
    return ProviderStore(provider_dir).write_best_config(content)
