"""Unit tests for nfconf — strategy export to nfqws2 conf files."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from blockchecks.nfconf import collect_export_strategies, export_configs, main

pytestmark = pytest.mark.unit


def _store():
    s = MagicMock()
    s.flush = AsyncMock()
    s.close = AsyncMock()
    s.get_common_tcp = AsyncMock(return_value=[])
    s.get_best_by_coverage = AsyncMock(return_value=[])
    s.get_best_tcp = AsyncMock(return_value=[])
    s.get_working_tcp = AsyncMock(return_value=[])
    s.get_strategy_config = AsyncMock(return_value=None)
    s.get_best_pairs = AsyncMock(return_value=[])
    s.get_best_udp = AsyncMock(return_value=[])
    s.get_best_quic = AsyncMock(return_value=[])
    return s


# ── collect_export_strategies ─────────────────────────────────────────


def test_collect_common_tcp():
    db = _store()
    db.get_common_tcp = AsyncMock(return_value=[{"strategy": "fake:a"}])
    db.get_strategy_config = AsyncMock(return_value="fake:a:strategy=1")
    tcp, udp, quic = asyncio.run(
        collect_export_strategies(db, domain="d.com", limit=3, domains=["a.com", "b.com"])
    )
    assert tcp == ["fake:a:strategy=1"]
    db.get_best_tcp.assert_not_called()


def test_collect_common_only_empty_intersection_no_fallback():
    db = _store()
    db.get_best_by_coverage = AsyncMock(return_value=[{"strategy": "fake:b"}])
    db.get_strategy_config = AsyncMock(return_value=None)
    tcp, _, _ = asyncio.run(
        collect_export_strategies(db, domain="d.com", limit=3, domains=["a.com", "b.com"])
    )
    assert tcp == []
    db.get_best_by_coverage.assert_not_called()
    db.get_best_tcp.assert_not_called()


def test_collect_coverage_fallback_when_not_common_only():
    db = _store()
    db.get_best_by_coverage = AsyncMock(return_value=[{"strategy": "fake:b"}])
    db.get_strategy_config = AsyncMock(return_value=None)
    tcp, _, _ = asyncio.run(
        collect_export_strategies(
            db,
            domain="d.com",
            limit=3,
            domains=["a.com", "b.com"],
            common_only=False,
        )
    )
    assert tcp == ["fake:b"]
    db.get_common_tcp.assert_not_called()


def test_collect_skips_label_when_config_missing():
    db = _store()
    db.get_best_by_coverage = AsyncMock(return_value=[{"strategy": "std_fake_stun_r6"}])
    db.get_strategy_config = AsyncMock(return_value=None)
    tcp, _, _ = asyncio.run(
        collect_export_strategies(
            db,
            domain="d.com",
            limit=3,
            domains=["a.com", "b.com"],
            common_only=False,
        )
    )
    assert tcp == []


def test_collect_working_fallback():
    db = _store()
    db.get_working_tcp = AsyncMock(return_value=["fake:c"])
    tcp, _, _ = asyncio.run(collect_export_strategies(db, domain="d.com", limit=3, domains=None))
    assert tcp == ["fake:c"]


def test_collect_udp_from_pairs():
    db = _store()
    db.get_best_pairs = AsyncMock(return_value=[{"udp": "fake:udp1"}])
    udp_strats = asyncio.run(collect_export_strategies(db, domain="d.com", limit=3))
    assert "fake:udp1" in udp_strats[1]


def test_collect_udp_empty_without_stock_fallback():
    db = _store()
    _, udp, _ = asyncio.run(collect_export_strategies(db, domain="d.com", limit=3))
    assert udp == []


def test_collect_udp_stock_fallback_when_allowed():
    db = _store()
    _, udp, _ = asyncio.run(
        collect_export_strategies(db, domain="d.com", limit=3, allow_stock_fallback=True)
    )
    assert udp == ["fake:blob=discord_udp:repeats=6"]


def test_collect_quic_empty_without_stock_fallback():
    db = _store()
    _, _, quic = asyncio.run(collect_export_strategies(db, domain="d.com", limit=3))
    assert quic == []


def test_collect_quic_stock_fallback_when_allowed():
    db = _store()
    _, _, quic = asyncio.run(
        collect_export_strategies(db, domain="d.com", limit=3, allow_stock_fallback=True)
    )
    assert quic == ["fake:blob=quic_initial:repeats=11"]


# ── export_configs ────────────────────────────────────────────────────


def test_export_configs_writes_files(tmp_path, monkeypatch):
    out = str(tmp_path / "out")
    store = _store()
    store.get_best_tcp = AsyncMock(return_value=[{"strategy": "fake:blob=stun:repeats=6"}])
    store.get_best_quic = AsyncMock(return_value=[{"strategy": "fake:quic"}])
    monkeypatch.setattr("blockchecks.nfconf.DEFAULT_DOMAINS_FILE", str(tmp_path / "no-domains.txt"))
    res = asyncio.run(
        export_configs(
            store=store,
            domain="d.com",
            limit=2,
            out_dir=out,
            timestamp="20260811_000000",
            domains_file=str(tmp_path / "no-domains.txt"),
        )
    )
    assert res["keenetic"].endswith("nfqws2_20260811_000000.conf")
    import os

    assert os.path.exists(res["keenetic"])
    assert os.path.exists(res["raw"])
    assert os.path.exists(res["user_list"])


def test_export_configs_opens_store_by_path(tmp_path, monkeypatch):
    out = str(tmp_path / "out")
    db = _store()
    db.init = AsyncMock()
    with patch("blockchecks.nfconf.open_run_store", return_value=db) as open_store:
        asyncio.run(
            export_configs(
                db_path="x.db",
                domain="d.com",
                limit=1,
                out_dir=out,
                domains_file=str(tmp_path / "no-domains.txt"),
            )
        )
    open_store.assert_called_once_with("x.db")
    db.init.assert_awaited_once()
    db.close.assert_awaited_once()


def test_export_configs_uses_domain_file_domains(tmp_path):
    doms = tmp_path / "domains.txt"
    doms.write_text("a.com\nb.com\n")
    out = tmp_path / "out"
    store = _store()
    store.get_best_tcp = AsyncMock(return_value=[{"strategy": "fake:a"}])
    store.get_working_tcp = AsyncMock(return_value=[])
    with patch("blockchecks.nfconf.build_raw_conf") as raw:
        raw.return_value = "raw"
        asyncio.run(
            export_configs(
                store=store,
                domain="d.com",
                limit=1,
                out_dir=str(out),
                domains_file=str(doms),
            )
        )
    # build_raw_conf received domains list from file
    assert raw.call_args.kwargs["domains"] == ["a.com", "b.com"]


def test_main_returns_zero(tmp_path, monkeypatch):
    monkeypatch.setattr("sys.argv", ["nfconf", "--limit", "1"])
    with patch(
        "blockchecks.nfconf.export_configs",
        new=AsyncMock(
            return_value={
                "keenetic": "k",
                "raw": "r",
                "user_list": "u",
                "tcp": ["a"],
                "udp": ["b"],
                "quic": ["c"],
            }
        ),
    ):
        rc = main(["--limit", "1"])
    assert rc == 0


def test_main_returns_nonzero_when_udp_quic_empty():
    with patch(
        "blockchecks.nfconf.export_configs",
        new=AsyncMock(
            return_value={
                "keenetic": "k",
                "raw": "r",
                "user_list": "u",
                "tcp": ["a"],
                "udp": [],
                "quic": [],
            }
        ),
    ):
        rc = main(["--limit", "1"])
    assert rc == 1


def test_main_prints_keenetic_path_before_stock_fail(capsys):
    with patch(
        "blockchecks.nfconf.export_configs",
        new=AsyncMock(
            return_value={
                "keenetic": "/tmp/out/nfqws2_keenetic.conf",
                "raw": "r",
                "user_list": "u",
                "tcp": ["a"],
                "udp": [],
                "quic": [],
            }
        ),
    ):
        rc = main(["--limit", "1"])
    assert rc == 1
    assert "keenetic: /tmp/out/nfqws2_keenetic.conf" in capsys.readouterr().out


def test_main_allows_empty_udp_quic_with_stock_flag():
    with patch(
        "blockchecks.nfconf.export_configs",
        new=AsyncMock(
            return_value={
                "keenetic": "k",
                "raw": "r",
                "user_list": "u",
                "tcp": ["a"],
                "udp": ["fake:blob=discord_udp:repeats=6"],
                "quic": ["fake:blob=quic_initial:repeats=11"],
            }
        ),
    ):
        rc = main(["--limit", "1", "--allow-stock-fallback"])
    assert rc == 0


# ── ipset export (data_block DNS cache, provider-agnostic) ─────────────


def _fake_provider_dir(tmp_path, provider, records):
    """Write data_block/providers/<provider>/dns.db with one domain per record."""
    import sqlite3
    import time

    now_str = time.strftime("%Y-%m-%dT%H:%M:%S")
    prov = tmp_path / "providers" / provider
    prov.mkdir(parents=True)
    con = sqlite3.connect(str(prov / "dns.db"))
    con.execute("CREATE TABLE dns_records (domain TEXT PRIMARY KEY, ips TEXT, checked_at TEXT)")
    for dom, ips in records.items():
        con.execute(
            "INSERT INTO dns_records (domain, ips, checked_at) VALUES (?,?,?)",
            (dom, ",".join(ips), now_str),
        )
    con.commit()
    con.close()
    return tmp_path / "providers"


def test_collect_domain_ips_uses_all_providers(tmp_path, monkeypatch):
    _fake_provider_dir(tmp_path, "p1", {"youtube.com": ["1.2.3.4"]})
    _fake_provider_dir(tmp_path, "p2", {"youtube.com": ["5.6.7.8"], "discord.com": ["9.9.9.9"]})
    monkeypatch.setattr(
        "blockchecks.data_block.provider.iter_provider_dirs",
        lambda allow_detect=True: sorted((tmp_path / "providers").iterdir()),
    )
    monkeypatch.setattr("blockchecks.nfconf._find_ip2net", lambda: None)
    from blockchecks.nfconf import collect_domain_ips

    ips = collect_domain_ips(["youtube.com", "discord.com"])
    # first provider that has youtube.com wins (p1), p2 discord adds 9.9.9.9
    assert "1.2.3.4" in ips
    assert "9.9.9.9" in ips
    assert "5.6.7.8" not in ips  # youtube.com already covered by p1


def test_collect_domain_ips_missing_db_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "blockchecks.data_block.provider.iter_provider_dirs", lambda allow_detect=True: []
    )
    from blockchecks.nfconf import collect_domain_ips

    assert collect_domain_ips(["a.com"]) == []


def test_resolve_ipset_for_export_inline(tmp_path, monkeypatch):
    monkeypatch.setattr("blockchecks.nfconf._find_ip2net", lambda: None)
    monkeypatch.setattr(
        "blockchecks.nfconf.collect_domain_ips",
        lambda domains, use_all_providers=True: ["1.1.1.1", "2.2.2.2"],
    )
    from blockchecks.nfconf import resolve_ipset_for_export

    ips, ipset_file = resolve_ipset_for_export(["a.com"], out_dir=str(tmp_path))
    assert ips == ["1.1.1.1", "2.2.2.2"]
    assert ipset_file is None


def test_resolve_ipset_for_export_file_over_limit(tmp_path, monkeypatch):
    monkeypatch.setattr("blockchecks.nfconf._find_ip2net", lambda: None)
    many = [f"10.0.{i}.1" for i in range(100)]
    monkeypatch.setattr(
        "blockchecks.nfconf.collect_domain_ips", lambda domains, use_all_providers=True: many
    )
    from blockchecks.nfconf import resolve_ipset_for_export

    ips, ipset_file = resolve_ipset_for_export(["a.com"], out_dir=str(tmp_path))
    assert ips is None
    assert ipset_file is not None
    assert Path(ipset_file).exists()
    assert len(Path(ipset_file).read_text().splitlines()) == 100


def test_maybe_aggregate_ips_without_ip2net(monkeypatch):
    monkeypatch.setattr("blockchecks.nfconf._find_ip2net", lambda: None)
    from blockchecks.nfconf import maybe_aggregate_ips

    assert maybe_aggregate_ips(["1.1.1.1", "1.1.1.1", "2.2.2.2"]) == ["1.1.1.1", "2.2.2.2"]


def test_export_configs_passes_ipset_to_builders(tmp_path, monkeypatch):
    out = tmp_path / "out"
    store = _store()
    store.get_best_tcp = AsyncMock(return_value=[{"strategy": "fake:a"}])
    store.get_working_tcp = AsyncMock(return_value=[])
    monkeypatch.setattr(
        "blockchecks.nfconf.resolve_ipset_for_export",
        lambda domains, out_dir, use_all_providers=True: (["1.2.3.4"], None),
    )
    with (
        patch("blockchecks.nfconf.build_keenetic_conf") as kc,
        patch("blockchecks.nfconf.build_raw_conf") as raw,
    ):
        kc.return_value = "k"
        raw.return_value = "r"
        asyncio.run(
            export_configs(store=store, domain="d.com", limit=1, out_dir=str(out), use_ipset=True)
        )
    assert kc.call_args.kwargs["ipset_ips"] == ["1.2.3.4"]
    assert raw.call_args.kwargs["ipset_ips"] == ["1.2.3.4"]


def test_manager_bind_retry_on_eperm(tmp_path, monkeypatch):
    """Nfqws2Manager._launch: EPERM-бут → ретрай; живой бут со 2-й попытки."""
    import blockchecks.service.nfqws2 as nfq
    import blockchecks.service.nfqws2_launcher as launcher_mod

    attempts = {"n": 0}
    logs = []

    class FakeProc:
        def __init__(self):
            self.pid = 4242

        def poll(self):
            attempts["n"] += 1
            # 1-я попытка мертва (EPERM), последующие живы
            return 1 if attempts["n"] == 1 else None

    def fake_capture(tag):
        path = tmp_path / f"out_{len(logs)+1}.log"
        text = (
            "nfq_create_queue(): Operation not permitted\n"
            if len(logs) == 0
            else "setting copy_packet mode\n"
        )
        path.write_text(text, encoding="utf-8")
        logs.append(path)
        fh = open(path, "rb")  # noqa: SIM115
        return fh, path

    monkeypatch.setattr(launcher_mod.subprocess, "Popen", lambda *a, **k: FakeProc())
    monkeypatch.setattr(launcher_mod, "wait_nfqws2_ready", lambda *a, **k: 0.0)
    monkeypatch.setattr(launcher_mod.time, "sleep", lambda s: None)
    monkeypatch.setattr(launcher_mod, "open_out_capture", fake_capture)
    monkeypatch.setattr(launcher_mod, "_reclaim_debug_log", lambda p: None)

    mgr = nfq.Nfqws2Manager(ns_name="ns-r")
    conf = tmp_path / "m.conf"
    conf.write_text("--qnum=200\n", encoding="utf-8")
    mgr.start_config(str(conf))
    assert attempts["n"] >= 2, "ретрай после EPERM не произошёл"
    assert mgr._proc is not None
    assert mgr.last_out_log == logs[-1]


def test_manager_non_bind_error_raises_immediately(tmp_path, monkeypatch):
    """Иная причина старта (без маркера очереди) — без ретраев, сразу raise."""
    import pytest as _pytest

    import blockchecks.service.nfqws2 as nfq
    import blockchecks.service.nfqws2_launcher as launcher_mod

    calls = {"n": 0}

    class FakeProc:
        pid = 1

        def poll(self):
            calls["n"] += 1
            return 1

    monkeypatch.setattr(launcher_mod.subprocess, "Popen", lambda *a, **k: FakeProc())
    monkeypatch.setattr(launcher_mod, "wait_nfqws2_ready", lambda *a, **k: 0.0)
    # out-файл без маркера nfq_create_queue
    monkeypatch.setattr(
        launcher_mod,
        "open_out_capture",
        lambda tag: _open_empty(tmp_path),
    )

    def _open_empty(root):
        f = root / "out.log"
        f.write_text("some other failure\n", encoding="utf-8")
        fh = open(f, "rb")  # noqa: SIM115
        return fh, f

    mgr = nfq.Nfqws2Manager(ns_name="ns-r")
    with _pytest.raises(RuntimeError, match="failed to start"):
        mgr._launch(f"@{tmp_path / 'x.conf'}")
    assert calls["n"] == 1


def test_default_isp_interface_from_env(monkeypatch):
    from blockchecks.nfconf import _default_isp_interface

    monkeypatch.delenv("BLOCKCHECKS_ISP_IFACE", raising=False)
    monkeypatch.delenv("ISP_INTERFACE", raising=False)
    assert _default_isp_interface() == ""
    monkeypatch.setenv("BLOCKCHECKS_ISP_IFACE", "wlp4s0")
    assert _default_isp_interface() == "wlp4s0"
    monkeypatch.delenv("BLOCKCHECKS_ISP_IFACE", raising=False)
    monkeypatch.setenv("ISP_INTERFACE", "eth0")
    assert _default_isp_interface() == "eth0"
