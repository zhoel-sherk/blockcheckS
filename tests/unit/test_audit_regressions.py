"""Regression tests that do not need root: ECH setopt, paths, and store contracts."""

from __future__ import annotations

import inspect
from pathlib import Path

import aiosqlite
import pytest

from blockchecks.engine import async_runner as ar
from blockchecks.engine.async_runner import _add_blobs_from_strategy, _run_udp_check
from blockchecks.engine.matrix_generator import (
    TCP_FAMILIES,
    UDP_VOICE_FAMILIES,
    MatrixGenerator,
    StandardGenerator,
)
from blockchecks.engine.store import SqliteRunStore, open_run_store

pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_log_tcp_read_rate_not_latency(temp_db: SqliteRunStore):
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

    state = open_run_store(db_path)
    await state.init()
    async with aiosqlite.connect(db_path) as db:
        cols = await db.execute("PRAGMA table_info(tcp_results)")
        names = {row[1] for row in await cols.fetchall()}
    assert "read_rate_bps" in names


def test_scan_auto_discover_none_skips():
    """None/False/0 must not enable discovery; only positive int does."""
    from blockchecks.checkers.voice_dns import positive_discover_count

    assert positive_discover_count(None) is None
    assert positive_discover_count(False) is None
    assert positive_discover_count(0) is None
    assert positive_discover_count("0") is None
    assert positive_discover_count(5) == 5
    assert positive_discover_count("3") == 3

    phases = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "blockchecks"
        / "cli"
        / "commands"
        / "pair_phases.py"
    )
    phases_text = phases.read_text(encoding="utf-8")
    assert "positive_discover_count" in phases_text


@pytest.mark.asyncio
async def test_auto_discover_gates_discover_multiple_calls():
    """Only positive auto_discover count invokes discovery (pair/udp gate)."""
    from blockchecks.checkers.voice_dns import positive_discover_count

    calls: list[int] = []

    async def fake_discover(count, use_dns=True):
        calls.append(count)
        return [{"ip": "1.2.3.4", "port": 50000, "hostname": "x"}]

    for auto_discover in (None, False, 0, 2):
        count = positive_discover_count(auto_discover)
        if count is not None:
            await fake_discover(count, use_dns=True)

    assert calls == [2]


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
    root = Path(__file__).resolve().parents[2] / "src" / "blockchecks" / "cli" / "commands"
    text = (root / "pair.py").read_text(encoding="utf-8") + (root / "pair_phases.py").read_text(
        encoding="utf-8"
    )
    assert "preset_domains if preset_domains else [args.domain]" in text
    assert "ERROR: --domain or --preset required" in text


def test_disable_ech_in_curl_probe_source():
    """GV-3: ECH off via Session.curl.setopt, never options= kwarg."""
    probe = (
        Path(__file__).resolve().parents[2] / "src" / "blockchecks" / "checkers" / "curl_probe.py"
    )
    src = probe.read_text(encoding="utf-8")
    assert "CURLOPT_ECH" in src
    assert "CurlOpt.ECH" in src
    assert "_apply_ech_off" in src
    assert 'kwargs["options"]' not in src
    from blockchecks.engine import in_ns_workers as insw

    runner = Path(insw.__file__).read_text(encoding="utf-8")
    assert "_curl_probe_worker" in runner
    assert '["-c", check_code]' not in runner


def test_udp_check_parses_cli_prefix(monkeypatch, tmp_path):
    from blockchecks.engine import in_ns_workers as insw

    written = {}

    def fake_daemon(ns_name, config_path, kill_existing=True, **_kw):
        written["text"] = Path(config_path).read_text(encoding="utf-8")
        written["kill"] = kill_existing

    monkeypatch.setattr(insw, "_nfqws2_daemon", fake_daemon)
    monkeypatch.setattr(insw, "_sudo", lambda *a, **k: None)

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
    from blockchecks.engine import in_ns_workers as insw

    calls = []

    def fake_daemon(ns_name, config_path, kill_existing=True, **_kw):
        calls.append(kill_existing)
        Path(config_path).write_text("--qnum=201\n", encoding="utf-8")

    monkeypatch.setattr(insw, "_nfqws2_daemon", fake_daemon)
    monkeypatch.setattr(insw, "_sudo", lambda *a, **k: None)

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
    import blockchecks.service.nfqws2 as nfq
    from blockchecks.engine import in_ns_workers as insw

    src = Path(nfq.__file__).read_text(encoding="utf-8")
    # zapret2#300: bind-ошибки печатаются в stdout nfqws2 — захват обязателен,
    # DEVNULL допустим только как fallback при недоступном файле лога.
    assert "open_out_capture(" in src
    assert "stderr=subprocess.STDOUT if out_fh is not None" in src
    assert "kill_existing" in inspect.signature(nfq.start_daemon).parameters
    assert "min_procs" in inspect.signature(nfq.start_daemon).parameters
    assert "kill_existing" in inspect.signature(ar._nfqws2_daemon).parameters
    worker_src = Path(insw.__file__).read_text(encoding="utf-8")
    assert "--queue-bypass" in worker_src
    probe = (
        Path(__file__).resolve().parents[2] / "src" / "blockchecks" / "checkers" / "curl_probe.py"
    ).read_text(encoding="utf-8")
    # 206 is not an unconditional small_body shortcut (googlevideo ~17KB Range)
    assert "resp.status_code == 206 and clen < 300" in probe


def test_nfqws2_daemon_unlinks_temp_conf(tmp_path, monkeypatch):
    """C1: daemon mkstemp copy must not leak in /tmp after settle."""
    import blockchecks.service.nfqws2 as nfq

    src = tmp_path / "src.conf"
    src.write_text("--filter-tcp=443\n", encoding="utf-8")
    seen: list[str] = []

    def fake_popen(cmd, **kwargs):
        for part in cmd:
            if isinstance(part, str) and part.startswith("@") and "bs_nfq_" in part:
                seen.append(part[1:])

    monkeypatch.setattr(nfq.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(nfq.subprocess, "run", lambda *a, **k: None)
    monkeypatch.setattr(nfq, "wait_nfqws2_ready", lambda *a, **k: 0.01)
    monkeypatch.setattr(nfq, "inject_debug_and_daemon", lambda *a, **k: None)

    nfq.start_daemon("mock-ns", str(src), kill_existing=False)
    assert seen, "expected @bs_nfq_* path in Popen cmd"
    assert not Path(seen[0]).exists(), f"leaked temp conf: {seen[0]}"


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
        assert it.protocol == "udp_voice"
        assert "hostfakesplit" not in it.strategy
        assert "discord_udp" in it.strategy or "blob=stun" in it.strategy


@pytest.mark.asyncio
async def test_fake_hostfake_disorder_after():
    gen = StandardGenerator(strategy_types=["fake_hostfake"])
    items = await gen.generate("tls12", scan_level="fast", max_count=200)
    joined = "\n".join(i.strategy for i in items)
    assert "hostfakesplit:disorder:" not in joined
    assert "hostfakesplit:disorder_after:" in joined


@pytest.mark.asyncio
async def test_fake_multisplit_family_m1():
    gen = StandardGenerator(strategy_types=["fake_multisplit"])
    items = await gen.generate("tls12", scan_level="fast", max_count=50)
    assert items
    assert len({i.label for i in items}) == len(items)
    for sample in items:
        assert "fake:blob=" in sample.strategy
        assert "multisplit:" in sample.strategy
        assert "seqovl_pattern=" in sample.strategy
        fake_blob = sample.strategy.split("fake:blob=")[1].split(":")[0]
        pattern_blob = sample.strategy.split("seqovl_pattern=")[1].split(":")[0]
        assert fake_blob != pattern_blob


@pytest.mark.asyncio
async def test_fake_multisplit_hostfake_m2():
    gen = StandardGenerator(strategy_types=["fake_multisplit_hostfake"])
    items = await gen.generate("tls12", scan_level="single", max_count=10)
    assert items
    strat = items[0].strategy
    assert "fake:blob=" in strat
    assert "multisplit:" in strat
    assert "hostfakesplit:host=" in strat


@pytest.mark.asyncio
async def test_multidisorder_m3():
    gen = StandardGenerator(strategy_types=["multidisorder"])
    items = await gen.generate("tls12", scan_level="single", max_count=10)
    assert items
    assert "multidisorder:" in items[0].strategy


@pytest.mark.asyncio
async def test_fakedsplit_m3():
    gen = StandardGenerator(strategy_types=["fakedsplit"])
    items = await gen.generate("tls12", scan_level="single", max_count=10)
    assert items
    assert "fakedsplit:" in items[0].strategy
    assert "pattern=" in items[0].strategy


@pytest.mark.asyncio
async def test_quic_gv_family_gv5():
    gen = StandardGenerator(strategy_types=["quic_gv"])
    items = await gen.generate("quic", scan_level="single", max_count=10)
    assert items
    assert items[0].protocol == "quic"
    assert "quic_gv_kyber" in items[0].strategy or "quic_google" in items[0].strategy


@pytest.mark.asyncio
async def test_faked_tcp_generator_m9_real_fakedsplit():
    from blockchecks.engine.generators.standard import FakedTcpGenerator

    gen = FakedTcpGenerator()
    items = await gen.generate("tls12", scan_level="single", max_count=5)
    assert items
    assert "fakedsplit:" in items[0].strategy or "fakeddisorder:" in items[0].strategy
    assert "multisplit:" not in items[0].strategy
    assert "pattern=" in items[0].strategy


@pytest.mark.asyncio
async def test_fake_split_combo_m9():
    from blockchecks.engine.generators.standard import FakeSplitComboGenerator

    gen = FakeSplitComboGenerator()
    items = await gen.generate("tls12", scan_level="single", max_count=5)
    assert items
    assert "fakedsplit:" in items[0].strategy
    assert "fake:blob=" in items[0].strategy


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


@pytest.mark.asyncio
async def test_multi_fake_m5_reverse_and_repeat_pairs():
    gen = StandardGenerator(strategy_types=["multi_fake"])
    items = await gen.generate("tls12", scan_level="fast", max_count=500)
    strategies = {i.strategy for i in items}
    assert any(
        "fake:blob=max_ru:repeats=6" in s and "fake:blob=stun:repeats=6" in s for s in strategies
    )
    assert any(
        "fake:blob=stun:repeats=6" in s and "fake:blob=max_ru:repeats=3" in s for s in strategies
    )
    labels = [i.label for i in items]
    assert len(labels) == len(set(labels)) or len(items) == len({i.strategy for i in items})


@pytest.mark.asyncio
async def test_triple_fake_m5():
    gen = StandardGenerator(strategy_types=["triple_fake"])
    items = await gen.generate("tls12", scan_level="single", max_count=10)
    assert items
    assert items[0].strategy.count("fake:blob=") == 3


@pytest.mark.asyncio
async def test_tcp_ipfrag_family():
    gen = StandardGenerator(strategy_types=["tcp_ipfrag"])
    items = await gen.generate("tls12", scan_level="single", max_count=10)
    assert items
    assert "ipfrag_pos_tcp=" in items[0].strategy


@pytest.mark.asyncio
async def test_http_tls_dual_m6():
    gen = StandardGenerator(strategy_types=["http_tls_dual"])
    items = await gen.generate("http", scan_level="single", max_count=10)
    assert items
    assert items[0].protocol == "http"
    assert "fake_default_http" in items[0].strategy


@pytest.mark.asyncio
async def test_udp_multiblob_m7():
    gen = StandardGenerator(strategy_types=["udp_multiblob"])
    items = await gen.generate("udp_voice", scan_level="single", max_count=10)
    assert items
    assert items[0].protocol == "udp_voice"
    assert items[0].strategy.count("fake:blob=") == 2
    assert "discord" in items[0].strategy.lower()
    assert "--filter-udp=" not in items[0].strategy


@pytest.mark.asyncio
async def test_db_batch_flush(temp_db: SqliteRunStore):
    temp_db.batch_size = 3
    for i in range(5):
        await temp_db.log_tcp(f"s{i}", "discord.com", "PASS", float(i), 200)
    await temp_db.flush()
    stats = await temp_db.domain_pass_stats("discord.com")
    assert stats["passed"] == 5
