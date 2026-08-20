"""Live nfqws2 fooling grid plus ECH and HTTP:80 differentials.
probe_fn injects the real probe. Without it the grid is empty and generators do not prune.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from blockchecks.engine.fail_phase import classify_fail_phase

# (label, lua-desync suffix appended to fake:blob=stun:repeats=6)
FOOLING_GRID: tuple[tuple[str, str], ...] = (
    ("tcp_ts=-1000", "tcp_ts=-1000"),
    ("tcp_md5", "tcp_md5"),
    ("badsum", "badsum"),
    ("tcp_seq=1000", "tcp_seq=1000"),
    ("tcp_ack=-66000:tcp_ts_up", "tcp_ack=-66000:tcp_ts_up"),
)

SPLIT_GRID: tuple[tuple[str, str], ...] = (
    ("first_byte", "multisplit:pos=1"),
    ("sni_marker", "multisplit:pos=sniext+1"),
    ("disorder", "multidisorder:pos=1,midsld"),
    ("seqovl", "multisplit:pos=1:seqovl=568"),
)

BLOB_GRID: tuple[tuple[str, str], ...] = (
    ("stun", "fake:blob=stun:repeats=6:tcp_ts=-1000"),
    ("tls_clienthello", "fake:blob=google:repeats=6:tcp_ts=-1000"),
    ("empty", "fake:repeats=6:tcp_ts=-1000"),
)

ProbeFn = Callable[[str], tuple[bool, str, int]]  # strategy → (ok, error, http)


@dataclass
class FoolingGridResult:
    viable: list[str] = field(default_factory=list)
    failed: dict[str, str] = field(default_factory=dict)
    split_mode: str = ""


def fooling_strategy(suffix: str, *, blob: str = "stun", repeats: int = 6) -> str:
    return f"fake:blob={blob}:repeats={repeats}:{suffix}"


def is_fooling_viable(error: str, http_code: int = 0) -> bool:
    """SSL 35 / handshake-class failures mean the fooling itself was rejected."""
    if not error and http_code in (200, 204, 101):
        return True
    blob = f"{error} {http_code}"
    if re_ssl35(blob):
        return False
    phase = classify_fail_phase(error, http_code)
    return phase.value in ("pass",) or http_code in (200, 204, 101)


def re_ssl35(text: str) -> bool:
    low = text.lower()
    return "ssl" in low and ("35" in low or "wrong_version" in low or "handshake" in low)


def evaluate_grid(outcomes: dict[str, tuple[bool, str, int]]) -> FoolingGridResult:
    """Classify a {label: (ok, error, http)} map into viable foolings."""
    res = FoolingGridResult()
    for label, _suffix in FOOLING_GRID:
        ok, err, code = outcomes.get(label, (False, "skipped", 0))
        if ok or is_fooling_viable(err, code):
            res.viable.append(label)
        else:
            res.failed[label] = err or f"http {code}"
    return res


def run_fooling_grid(probe_fn: ProbeFn, *, blob: str = "stun") -> FoolingGridResult:
    """Run the 5-cell fooling grid (parallel threads)."""
    from concurrent.futures import ThreadPoolExecutor

    def _one(label_suffix: tuple[str, str]) -> tuple[str, tuple[bool, str, int]]:
        label, suffix = label_suffix
        return label, probe_fn(fooling_strategy(suffix, blob=blob))

    with ThreadPoolExecutor(max_workers=len(FOOLING_GRID)) as pool:
        outcomes = dict(pool.map(_one, FOOLING_GRID))
    return evaluate_grid(outcomes)


async def run_fooling_grid_async(probe_fn, *, blob: str = "stun") -> FoolingGridResult:
    """Async variant — ``probe_fn`` may be sync or async."""
    import asyncio
    import inspect

    async def _one(label: str, suffix: str) -> tuple[str, tuple[bool, str, int]]:
        out = probe_fn(fooling_strategy(suffix, blob=blob))
        if inspect.isawaitable(out):
            out = await out
        return label, out

    pairs = await asyncio.gather(*(_one(label, suffix) for label, suffix in FOOLING_GRID))
    return evaluate_grid(dict(pairs))


def run_split_grid(probe_fn: ProbeFn) -> str:
    """Return the first split mode that the probe reports as working."""
    for mode, strat in SPLIT_GRID:
        ok, err, code = probe_fn(strat)
        if ok or is_fooling_viable(err, code):
            return mode
    return ""


async def run_split_grid_async(probe_fn) -> str:
    import inspect

    for mode, strat in SPLIT_GRID:
        out = probe_fn(strat)
        if inspect.isawaitable(out):
            out = await out
        ok, err, code = out
        if ok or is_fooling_viable(err, code):
            return mode
    return ""


async def run_blob_grid_async(probe_fn) -> list[str]:
    """Blob-class viability: keep classes whose probe succeeds."""
    import inspect

    viable: list[str] = []
    for cls, strat in BLOB_GRID:
        out = probe_fn(strat)
        if inspect.isawaitable(out):
            out = await out
        ok, err, code = out
        if cls != "empty" and (ok or is_fooling_viable(err, code)):
            viable.append(cls)
    return viable


def probe_ech_blocked(
    domain: str,
    timeout: float = 5.0,
    resolved_ip: str | None = None,
) -> bool | None:
    """A/B ClientHello with ECH vs ECH-off. True → ECH path uniquely fails."""
    from blockchecks.checkers.curl_probe import CurlProbeRequest, run_curl_probe

    kwargs = dict(domain=domain, timeout=timeout, resolved_ip=resolved_ip)
    on = run_curl_probe(CurlProbeRequest(**kwargs, disable_ech=False))
    off = run_curl_probe(CurlProbeRequest(**kwargs, disable_ech=True))
    if on.success == off.success:
        return False if on.success else None
    return bool(off.success and not on.success)


def probe_http_blocked(
    domain: str,
    timeout: float = 5.0,
    resolved_ip: str | None = None,
) -> bool:
    """GET :80 — True when plaintext HTTP is DPI-blocked / unreachable."""
    from blockchecks.checkers.curl_probe import CurlProbeRequest, run_curl_probe

    r = run_curl_probe(
        CurlProbeRequest(
            domain=domain,
            timeout=timeout,
            resolved_ip=resolved_ip,
            curl_url=f"http://{domain}/",
            protocol="http",
        )
    )
    return not r.success
