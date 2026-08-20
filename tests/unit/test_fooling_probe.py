"""Fooling viability grid + ECH/HTTP classifiers."""

from blockchecks.checkers.fooling_probe import (
    FOOLING_GRID,
    evaluate_grid,
    fooling_strategy,
    is_fooling_viable,
    run_fooling_grid,
    run_split_grid,
)


def test_ssl35_is_not_viable():
    assert is_fooling_viable("SSL error code 35", 0) is False
    assert is_fooling_viable("WRONG_VERSION_NUMBER", 0) is False
    assert is_fooling_viable("", 200) is True


def test_evaluate_grid_keeps_working_cells():
    outcomes = {
        "tcp_ts=-1000": (True, "", 200),
        "tcp_md5": (False, "timeout", 0),
        "badsum": (False, "SSL routines: SSL error 35", 0),
        "tcp_seq=1000": (False, "Connection reset", 0),
        "tcp_ack=-66000:tcp_ts_up": (True, "", 200),
    }
    res = evaluate_grid(outcomes)
    assert "tcp_ts=-1000" in res.viable
    assert "tcp_ack=-66000:tcp_ts_up" in res.viable
    assert "badsum" not in res.viable
    assert "badsum" in res.failed


def test_run_fooling_grid_with_probe_fn():
    def probe(strategy: str):
        if "badsum" in strategy:
            return False, "SSL error 35", 0
        return True, "", 200

    res = run_fooling_grid(probe)
    assert "tcp_ts=-1000" in res.viable
    assert "badsum" not in res.viable
    assert len(FOOLING_GRID) == 5
    assert fooling_strategy("badsum").endswith(":badsum")


def test_run_split_grid_first_hit():
    def probe(strategy: str):
        return ("sniext" in strategy, "", 200 if "sniext" in strategy else 0)

    assert run_split_grid(probe) == "sni_marker"


def test_split_grid_includes_seqovl():
    from blockchecks.checkers.fooling_probe import SPLIT_GRID

    assert any(mode == "seqovl" for mode, _ in SPLIT_GRID)


def test_blob_grid_keeps_working_classes():
    import asyncio

    from blockchecks.checkers.fooling_probe import BLOB_GRID, run_blob_grid_async

    def probe(strategy: str):
        return ("stun" in strategy or "google" in strategy, "", 200)

    viable = asyncio.run(run_blob_grid_async(probe))
    assert "stun" in viable
    assert "tls_clienthello" in viable
    assert "empty" not in viable
    assert len(BLOB_GRID) == 3
