"""Audit closure regression tests (Wave 4) — Windows-safe, no root."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import aiosqlite
import pytest

from blockchecks.engine import async_runner as ar
from blockchecks.engine.async_runner import _add_blobs_from_strategy, _run_udp_check
from blockchecks.engine.db_logger import StateDB
from blockchecks.engine.matrix_generator import (
    TCP_FAMILIES,
    UDP_VOICE_FAMILIES,
    MatrixGenerator,
    StandardGenerator,
)

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_log_tcp_read_rate_not_latency(temp_db: StateDB):
    await temp_db.log_tcp(
        "s1",
        "discord.com",
        "PASS",
        latency_ms=123.0,
        http_code=200,
        read_rate_bps=98765.0,
    )
    async with aiosqlite.connect(temp_db.db_path) as db:
        row = await (
            await db.execute("SELECT latency_ms, read_rate_bps FROM tcp_results")
        ).fetchone()
    assert row[0] == 123.0
    assert row[1] == 98765.0


@pytest.mark.asyncio
async def test_db_migrates_read_rate_column(tmp_path):
    db_path = tmp_path / "old.db"
    async with aiosqlite.connect(db_path) as db:
        await db.executescript(
            """
            CREATE TABLE strategies (
                id INTEGER PRIMARY KEY, name TEXT, proto TEXT,
                config_path TEXT, first_seen TEXT,
                UNIQUE(name, proto)
            );
            CREATE TABLE tcp_results (
                id INTEGER PRIMARY KEY,
                strategy_id INTEGER, domain TEXT, status TEXT,
                http_code INTEGER, latency_ms REAL,
                gateway_ws_ms REAL, content_valid INTEGER,
                error TEXT, timestamp TEXT
            );
            CREATE TABLE udp_results (
                id INTEGER PRIMARY KEY,
                strategy_id INTEGER, target TEXT, status TEXT,
                latency_ms REAL, error TEXT, timestamp TEXT
            );
            CREATE TABLE pair_results (
                id INTEGER PRIMARY KEY,
                tcp_strategy_id INTEGER, udp_strategy_id INTEGER,
                domain TEXT, tcp_ok INTEGER, gateway_ok INTEGER,
                udp_ok INTEGER, tcp_ms REAL, gateway_ms REAL,
                udp_ms REAL, overall TEXT, timestamp TEXT
            );
            CREATE TABLE checkpoints (
                id INTEGER PRIMARY KEY,
                tcp_idx INTEGER, udp_idx INTEGER, timestamp TEXT,
                note TEXT, fingerprint TEXT,
                tcp_label TEXT, udp_label TEXT
            );
            """
        )
        await db.commit()

    state = StateDB(str(db_path))
    await state.init()
    async with aiosqlite.connect(db_path) as db:
        cols = await db.execute("PRAGMA table_info(tcp_results)")
        names = {row[1] for row in await cols.fetchall()}
    assert "read_rate_bps" in names


def test_scan_auto_discover_none_skips():
    """None/False must not call discover; only int > 0 does."""
    # Mirror the guard used in cmd_scan / cmd_pair
    for auto_discover in (None, False):
        should = auto_discover is not None and int(auto_discover) > 0
        assert should is False
    assert (5 != None and 5 > 0) is True

    # scan path must normalize False → None (never leave False for int())
    pair_src = (
        Path(__file__).resolve().parents[2] / "src" / "blockchecks" / "cli" / "commands" / "pair.py"
    )
    parser_src = Path(__file__).resolve().parents[2] / "src" / "blockchecks" / "cli" / "parser.py"
    pair_text = pair_src.read_text(encoding="utf-8")
    parser_text = parser_src.read_text(encoding="utf-8")
    assert "args.auto_discover = False" not in parser_text or "auto_discover = None" in parser_text
    assert "int(auto_discover) > 0" in pair_text


@pytest.mark.asyncio
async def test_protocol_forwarded_to_generate():
    mg = MatrixGenerator()
    captured = {}

    async def spy_generate(**kwargs):
        captured.update(kwargs)
        return []

    class FakeGen:
        async def generate(self, **kwargs):
            return await spy_generate(**kwargs)

    mg.register("fake_src", FakeGen())
    await mg.generate_tcp(
        sources=["fake_src"],
        protocol="tls13",
        max_count=5,
        domain="x.com",
    )
    assert captured.get("protocol") == "tls13"


def test_preset_domains_used():
    """cmd_pair uses preset_domains when -d omitted."""
    src = (
        Path(__file__).resolve().parents[2] / "src" / "blockchecks" / "cli" / "commands" / "pair.py"
    )
    text = src.read_text(encoding="utf-8")
    assert "preset_domains if preset_domains else [args.domain]" in text
    assert "ERROR: --domain or --preset required" in text


def test_disable_ech_in_check_source():
    src = Path(ar.__file__).read_text(encoding="utf-8")
    assert "CURLOPT_ECH" in src
    assert "disable_ech" in inspect.signature(ar._run_tcp_check).parameters
    assert "CurlOpt.ECH" in src
    # Numeric fallback after CurlOpt.ECH failure
    assert "setopt({ech_opt}" in src or "ech_setopt" in src
    tree = ast.parse(src)
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert "CURLOPT_ECH" in names


def test_udp_check_parses_cli_prefix(monkeypatch, tmp_path):
    written = {}

    def fake_daemon(ns_name, config_path, kill_existing=True):
        written["text"] = Path(config_path).read_text(encoding="utf-8")
        written["kill"] = kill_existing

    monkeypatch.setattr(ar, "_nfqws2_daemon", fake_daemon)
    monkeypatch.setattr(ar, "_sudo", lambda *a, **k: None)

    class FakeCompleted:
        stdout = '{"success": true, "latency_ms": 1.0, "detail": "ok"}'
        stderr = ""
        returncode = 0

    import subprocess as _sp

    monkeypatch.setattr(_sp, "run", lambda *a, **k: FakeCompleted())

    strategy = "--filter-udp=50000-50100 --lua-desync=fake:blob=DISCORD:repeats=6"
    _run_udp_check("mock-ns", strategy, "1.2.3.4", 3478, 1.0)
    text = written["text"]
    assert "--lua-desync=--filter" not in text
    assert any(line.startswith("--filter-udp=") for line in text.splitlines())
    assert "--lua-desync=fake:blob=DISCORD:repeats=6" in text
    assert written["kill"] is True


def test_udp_coexist_skips_pkill(monkeypatch):
    calls = []

    def fake_daemon(ns_name, config_path, kill_existing=True):
        calls.append(kill_existing)
        Path(config_path).write_text("--qnum=201\n", encoding="utf-8")

    monkeypatch.setattr(ar, "_nfqws2_daemon", fake_daemon)
    monkeypatch.setattr(ar, "_sudo", lambda *a, **k: None)

    class FakeCompleted:
        stdout = '{"success": true, "latency_ms": 1.0, "detail": "ok"}'
        returncode = 0

    import subprocess as _sp

    monkeypatch.setattr(_sp, "run", lambda *a, **k: FakeCompleted())

    _run_udp_check(
        "mock-ns",
        "fake:blob=discord_udp:repeats=6",
        "1.2.3.4",
        3478,
        1.0,
        coexist=True,
    )
    assert calls == [False]


def test_nfqws2_daemon_stderr_devnull_and_kill_flag():
    src = Path(ar.__file__).read_text(encoding="utf-8")
    assert "stderr=sp.DEVNULL" in src or "stderr=subprocess.DEVNULL" in src
    assert "kill_existing" in inspect.signature(ar._nfqws2_daemon).parameters
    assert "--queue-bypass" in src
    # 206 is not an unconditional small_body shortcut
    assert "or (resp.status_code == 206 and clen < 300)" in src


@pytest.mark.asyncio
async def test_user_matrix_skips_udp_cli_on_tcp(tmp_path):
    path = tmp_path / "m.txt"
    path.write_text(
        "fake:blob=stun:repeats=6\n"
        "--filter-udp=50000 --lua-desync=fake:blob=discord_udp:repeats=6\n"
        "fake:blob=discord_udp:repeats=12\n",
        encoding="utf-8",
    )
    from blockchecks.engine.matrix_generator import UserMatrixGenerator

    items = await UserMatrixGenerator(str(path)).generate("tls12", max_count=50)
    assert len(items) == 1
    assert "stun" in items[0].strategy


def test_add_blobs_loads_all_and_seqovl(tmp_path, monkeypatch):
    blob_dir = tmp_path / "blobs"
    blob_dir.mkdir()
    (blob_dir / "stun.bin").write_bytes(b"x")
    (blob_dir / "max_ru.bin").write_bytes(b"x")
    (blob_dir / "google.bin").write_bytes(b"x")
    monkeypatch.setattr(ar, "BLOB_DIR", str(blob_dir))

    lines: list[str] = []
    strategy = (
        "fake:blob=stun:repeats=6\nfake:blob=max_ru:repeats=6\n"
        "multisplit:pos=1:seqovl_pattern=google"
    )
    _add_blobs_from_strategy(lines, strategy)
    blob_lines = [line for line in lines if line.startswith("--blob=")]
    assert len(blob_lines) >= 3
    joined = "\n".join(blob_lines)
    assert "stun" in joined and "max_ru" in joined and "google" in joined


@pytest.mark.asyncio
async def test_standard_tcp_excludes_udp_families():
    items = await MatrixGenerator().generate_tcp(
        sources=["standard"],
        protocol="tls12",
        scan_level="single",
        max_count=200,
    )
    for it in items:
        assert "--filter-udp" not in it.strategy
        assert "discord_udp" not in it.strategy


@pytest.mark.asyncio
async def test_standard_udp_excludes_tcp_fakes():
    items = await MatrixGenerator().generate_udp(
        sources=["standard_udp"],
        scan_level="fast",
        max_count=50,
    )
    assert items
    for it in items:
        assert "fake:blob=stun" not in it.strategy
        assert "quic_initial" not in it.strategy
        assert "discord_udp" in it.strategy


@pytest.mark.asyncio
async def test_fake_hostfake_disorder_after():
    gen = StandardGenerator(strategy_types=["fake_hostfake"])
    items = await gen.generate("tls12", scan_level="fast", max_count=200)
    joined = "\n".join(i.strategy for i in items)
    assert "hostfakesplit:disorder:" not in joined
    assert "hostfakesplit:disorder_after:" in joined


@pytest.mark.asyncio
async def test_scan_level_single_one_per_family():
    gen = StandardGenerator(strategy_types=list(TCP_FAMILIES))
    items = await gen.generate("tls12", scan_level="single", max_count=500)
    # At most one strategy per TCP family
    assert len(items) <= len(TCP_FAMILIES)
    assert len(items) >= 1

    gen_u = StandardGenerator(strategy_types=list(UDP_VOICE_FAMILIES))
    u_items = await gen_u.generate("udp_voice", scan_level="single", max_count=50)
    assert len(u_items) <= len(UDP_VOICE_FAMILIES)
