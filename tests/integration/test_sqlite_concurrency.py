"""SQLite concurrent flush integration test.

Stress test for the B8 batch-flush path: N parallel async writers call
``log_tcp`` while others call ``flush``. Verifies zero row loss / duplication
in ``tcp_results`` — the race fixed by the atomic ``_flush_lock`` drain.
Resume skip after reopen uses ``begin_run(resume, fingerprint)`` and counts
WORKING rows only.

Runs with the same shared-store batch mode the production series uses
(batch_size=DEFAULT_DB_BATCH), so WAL contention / concurrent flushes are
exercised for real.
"""

from __future__ import annotations

import sqlite3

import pytest

from blockchecks.engine.store import open_run_store

pytestmark = [pytest.mark.integration, pytest.mark.slow]

N_WORKERS = 8
ROWS_PER_WORKER = 250
BATCH = 500  # DEFAULT_DB_BATCH


async def _writer(store, worker_id: int, rows: int) -> None:
    for i in range(rows):
        # unique domain per row → no legitimate duplicates in tcp_results.
        await store.log_tcp(
            "fake:blob=stun:repeats=6",
            f"domain-{worker_id}-{i}.com",
            "PASS" if i % 2 == 0 else "FAIL",
            float(i % 100),
            http_code=200 if i % 2 == 0 else 0,
            config_path="fake:blob=stun:repeats=6",
        )


@pytest.mark.asyncio
async def test_concurrent_flush_no_row_loss(tmp_path):
    store = open_run_store(tmp_path / "race.db", batch_size=BATCH)
    await store.init()

    import asyncio

    # Half the workers hammer log_tcp; half hammer flush concurrently.
    async def flusher():
        for _ in range(60):
            await store.flush()
            await asyncio.sleep(0.001)

    tasks = [asyncio.create_task(_writer(store, w, ROWS_PER_WORKER)) for w in range(N_WORKERS)]
    tasks.append(asyncio.create_task(flusher()))
    await asyncio.gather(*tasks)
    await store.flush()
    await store.close()

    con = sqlite3.connect(tmp_path / "race.db")
    n = con.execute("SELECT COUNT(*) FROM tcp_results").fetchone()[0]
    dups = con.execute(
        "SELECT COUNT(*) FROM ("
        "  SELECT strategy_id, domain, status, COUNT(*) c FROM tcp_results"
        "  GROUP BY strategy_id, domain, status, timestamp HAVING c > 1)"
    ).fetchone()[0]
    con.close()

    expected = N_WORKERS * ROWS_PER_WORKER
    assert n == expected, f"row loss: expected {expected}, got {n}"
    assert dups == 0, f"duplicate rows: {dups}"


@pytest.mark.asyncio
async def test_concurrent_flush_resume_consistency(tmp_path):
    """PASS rows survive concurrent flush and show up after ``--resume``.

    ``get_completed_tcp_keys`` is run-scoped WORKING (PASS/THROTTLED) only.
    Reopen without ``begin_run(resume=True, fingerprint=…)`` starts a new
    campaign and correctly returns no skip keys.
    """
    import asyncio

    fp = "concurrent-flush-resume"
    db_path = tmp_path / "resume.db"
    store = open_run_store(db_path, batch_size=BATCH)
    await store.init()
    await store.begin_run(fingerprint=fp)

    async def flusher():
        for _ in range(80):
            await store.flush()
            await asyncio.sleep(0.001)

    tasks = [asyncio.create_task(_writer(store, w, ROWS_PER_WORKER)) for w in range(N_WORKERS)]
    tasks.append(asyncio.create_task(flusher()))
    await asyncio.gather(*tasks)
    await store.flush()
    run_id = store.run_id
    await store.close()

    store2 = open_run_store(db_path, resume=True)
    await store2.init()
    assert await store2.begin_run(fingerprint=fp) == run_id
    keys = await store2.get_completed_tcp_keys()
    expected_pass = N_WORKERS * (ROWS_PER_WORKER // 2)
    assert len(keys) == expected_pass, f"resume PASS keys: expected {expected_pass}, got {len(keys)}"
    await store2.close()
