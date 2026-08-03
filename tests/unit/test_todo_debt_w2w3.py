"""Unit tests for V2-1 multi-EP, P5-1 provider seed, Phase 7 ipfrag."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from blockchecks.checkers.voice_dns import pair_log_domain, resolve_voice_targets
from blockchecks.engine.generators.standard import StandardGenerator
from blockchecks.provider_import import provider_summary_to_shortlist


@pytest.mark.unit
def test_resolve_voice_targets_prefers_multi_eps():
    targets = resolve_voice_targets(
        "9.9.9.9",
        50000,
        [
            {"ip": "1.1.1.1", "port": 50004},
            {"ip": "2.2.2.2", "port": 50005},
            {"ip": "1.1.1.1", "port": 50004},  # dup
        ],
    )
    assert targets == [("1.1.1.1", 50004), ("2.2.2.2", 50005)]


@pytest.mark.unit
def test_resolve_voice_targets_fallback_single():
    assert resolve_voice_targets("8.8.8.8", 50001, []) == [("8.8.8.8", 50001)]
    assert resolve_voice_targets("8.8.8.8", 50001, None) == [("8.8.8.8", 50001)]


@pytest.mark.unit
def test_pair_log_domain_multi():
    assert pair_log_domain("discord.com", "1.2.3.4", 50004, multi=True) == (
        "discord.com@1.2.3.4:50004"
    )
    assert pair_log_domain("discord.com", "1.2.3.4", 50004, multi=False) == "discord.com"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_pair_matrix_multi_ep_invokes_per_endpoint():
    from blockchecks.cli.commands.pair_phases import _run_pair_matrix_multi_ep
    from blockchecks.engine.async_runner import TcpTestResult
    from blockchecks.engine.matrix_generator import StrategyItem

    tcp_item = StrategyItem(label="tcp1", strategy="fake:repeats=6")
    udp_item = StrategyItem(label="udp1", strategy="fake:blob=discord_udp:repeats=6")
    tcp_r = TcpTestResult(item=tcp_item, domain="discord.com", success=True, latency_ms=10)

    runner = MagicMock()
    runner.test_pair_matrix = AsyncMock(return_value=["p"])

    pairs = await _run_pair_matrix_multi_ep(
        runner,
        [tcp_r],
        [udp_item],
        "discord.com",
        "9.9.9.9",
        50000,
        [{"ip": "1.1.1.1", "port": 50004}, {"ip": "2.2.2.2", "port": 50005}],
        udp_timeout=3.0,
        udp_bypass=False,
        resume_from=None,
        full_voice=False,
        fingerprint="fp",
    )
    assert pairs == ["p", "p"]
    assert runner.test_pair_matrix.await_count == 2
    calls = runner.test_pair_matrix.await_args_list
    assert calls[0].args[3:5] == ("1.1.1.1", 50004)
    assert calls[1].args[3:5] == ("2.2.2.2", 50005)
    assert calls[0].kwargs["pair_domain"] == "discord.com@1.1.1.1:50004"
    assert calls[1].kwargs["pair_domain"] == "discord.com@2.2.2.2:50005"


@pytest.mark.unit
@pytest.mark.asyncio
async def test_provider_seed_db(tmp_path: Path):
    from blockchecks.provider_import import provider_summary_to_shortlist
    from blockchecks.shortlist_import import seed_state_db

    summary = {
        "provider_id": "test-isp",
        "generated_at": "2026-01-01",
        "custom_strategies": {
            "tls12": ["fake:blob=stun:repeats=6:tcp_ts=-1000"],
            "quic": ["fake:blob=quic_initial:repeats=1"],
        },
        "shortlist": {"discord.com": {"tls12": "fake:blob=stun:repeats=6"}},
    }
    shortlist = provider_summary_to_shortlist(summary)
    assert shortlist["tcp"]
    db = tmp_path / "seed.db"
    n = await seed_state_db(shortlist, str(db))
    assert n >= 2
    assert db.is_file()


@pytest.mark.unit
def test_provider_summary_to_shortlist_shape():
    sl = provider_summary_to_shortlist(
        {
            "provider_id": "x",
            "custom_strategies": {"tls12": ["fake:repeats=6"], "udp_voice": ["fake:blob=discord_udp:repeats=6"]},
        }
    )
    assert sl["schema"] == "blockchecks.shortlist/v1"
    assert len(sl["tcp"]) == 1
    assert len(sl["udp"]) == 1


@pytest.mark.unit
@pytest.mark.asyncio
async def test_ipfrag_axes_disorder_and_alias():
    gen = StandardGenerator(strategy_types=["tcp_ipfrag"])
    items = await gen.generate("tls12", scan_level="fast", max_count=200)
    joined = "\n".join(i.strategy for i in items)
    assert "ipfrag_pos_tcp=" in joined
    assert "ipfrag_disorder" in joined
    assert "ipfrag_next=255" in joined

    gen2 = StandardGenerator(strategy_types=["ipfrag_tcp"])
    items2 = await gen2.generate("tls12", scan_level="single", max_count=5)
    assert items2
    assert "ipfrag_pos_tcp=" in items2[0].strategy


@pytest.mark.unit
@pytest.mark.asyncio
async def test_quic_ipfrag_alias_udp():
    gen = StandardGenerator(strategy_types=["ipfrag_udp"])
    items = await gen.generate("quic", scan_level="single", max_count=5)
    assert items
    assert "ipfrag_pos_udp=" in items[0].strategy


@pytest.mark.unit
def test_udp_inline_splits_multiline_desync():
    """UDP path must emit one --lua-desync per multiline strategy line."""
    import ast
    from pathlib import Path

    text = Path("src/blockchecks/engine/async_runner.py").read_text(encoding="utf-8")
    # Guard: no single-line append of whole strategy with embedded newlines
    assert 'config_lines.append(f"--lua-desync={strategy}")' not in text
    tree = ast.parse(text)
    assert tree is not None
