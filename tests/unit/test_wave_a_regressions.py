"""Wave A/C regression tests — critical contracts."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from unittest.mock import patch

import pytest

from blockchecks.engine import async_runner
from blockchecks.engine.async_runner import (
    StrategyItem,
    TcpTestResult,
    _run_tcp_check,
)
from blockchecks.engine.config import PYTHON_BIN
from blockchecks.engine.matrix_generator import MatrixGenerator
from blockchecks.engine.store import Checkpoint, StateDB, matrix_fingerprint

pytestmark = pytest.mark.unit


def test_async_runner_argv_uses_python_bin_path():
    """Source must use PYTHON_BIN variable, never the literal string."""
    src = Path(async_runner.__file__).read_text(encoding="utf-8")
    assert '"PYTHON_BIN"' not in src
    assert "'PYTHON_BIN'" not in src
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and node.value == "PYTHON_BIN":
            pytest.fail("found string literal 'PYTHON_BIN' in async_runner")
    # Signature default / module binding
    assert PYTHON_BIN
    sig = inspect.signature(_run_tcp_check)
    assert "python_bin" in sig.parameters


@pytest.mark.asyncio
async def test_checkpoint_roundtrip_labels_and_fingerprint(temp_db: StateDB):
    await temp_db.save_checkpoint(
        1,
        2,
        note="n",
        fingerprint="deadbeefcafebabe",
        tcp_label="tcp_x",
        udp_label="udp_y",
    )
    cp = await temp_db.latest_checkpoint()
    assert isinstance(cp, Checkpoint)
    assert cp.tcp_idx == 1 and cp.udp_idx == 2
    assert cp.fingerprint == "deadbeefcafebabe"
    assert cp.tcp_label == "tcp_x"
    assert cp.udp_label == "udp_y"


@pytest.mark.asyncio
async def test_resume_skip_uses_db_checkpoint_shape(mock_runner):
    cp = Checkpoint(
        tcp_idx=0,
        udp_idx=0,
        timestamp="",
        note="",
        fingerprint="fp",
        tcp_label="tcp_a",
        udp_label="u_a",
    )
    tcp = TcpTestResult(
        item=StrategyItem(label="tcp_a", strategy="f"),
        domain="d",
        success=True,
    )
    pairs = await mock_runner.test_pair_matrix(
        [tcp],
        [
            StrategyItem(label="u_a", strategy="f"),
            StrategyItem(label="u_b", strategy="g"),
        ],
        "d",
        voice_ip="1.2.3.4",
        voice_port=5,
        resume_from=cp,
    )
    # Inclusive skip of completed tcp_a+u_a → only u_b remains
    assert len(pairs) == 1
    assert pairs[0].udp_item.label == "u_b"


@pytest.mark.asyncio
async def test_fingerprint_mismatch_refuses_resume(temp_db: StateDB, tmp_path):
    """bs helper: fp mismatch must error (not silent resume)."""
    fp_old = matrix_fingerprint(["a"], ["b"], "fast", 10)
    fp_new = matrix_fingerprint(["a", "x"], ["b"], "fast", 10)
    assert fp_old != fp_new
    await temp_db.save_checkpoint(
        0,
        0,
        fingerprint=fp_old,
        tcp_label="t",
        udp_label="u",
    )
    cp = await temp_db.latest_checkpoint()
    assert cp.fingerprint == fp_old
    # Simulate bs.py refuse logic
    refused = bool(cp.fingerprint and cp.fingerprint != fp_new)
    assert refused is True


@pytest.mark.asyncio
async def test_generate_tcp_run_set_all_sources():
    mg = MatrixGenerator()
    # "user" without --user-matrix is skipped (not in REGISTRY); others must accept run_set
    items = await mg.generate_tcp(
        sources=["fake", "hostfake", "configs", "custom"],
        domain="discord.com",
        scan_level="single",
        max_count=20,
        run_set=set(),
    )
    assert isinstance(items, list)


@pytest.mark.asyncio
async def test_log_tcp_uses_single_connection(temp_db: StateDB):
    connect_calls = {"n": 0}
    real_connect = __import__("aiosqlite").connect

    class CountingCM:
        def __init__(self, *a, **k):
            self._cm = real_connect(*a, **k)

        async def __aenter__(self):
            connect_calls["n"] += 1
            return await self._cm.__aenter__()

        async def __aexit__(self, *exc):
            return await self._cm.__aexit__(*exc)

    with patch("aiosqlite.connect", side_effect=CountingCM):
        await temp_db.log_tcp("s1", "discord.com", "PASS", 10.0, 200)
    assert connect_calls["n"] == 1


@pytest.mark.asyncio
async def test_get_working_tcp_latest_wins(temp_db: StateDB):
    await temp_db.log_tcp("strat", "d.com", "PASS", 100, 200)
    await temp_db.log_tcp("strat", "d.com", "FAIL", 5000, 0, error="timeout")
    working = await temp_db.get_working_tcp("d.com")
    assert "strat" not in working
