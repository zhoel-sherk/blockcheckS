"""ByeDPI (ciadpi) strategy matrix generator.

A self-contained strategy source for ``--generate byedpi``. Unlike the
combinatorial StandardGenerator, this generator emits a curated pool of
strategies expressed directly in byedpi CLI syntax. Two sub-pools:

* **native** — one-liners that exist in byedpi but have no nfqws2
  equivalent (OOB/disoob, fake-sni, -A auto chains, mod-http, drop-sack).
* **translated** — nfqws2 syntax fed through ``byedpi_translator.translate``
  so both syntaxes share one pipeline.

Every emitted item stores the *byedpi argv* in ``strategy`` (space-joined)
and keeps the original nfqws2 line (when translated) in ``label`` prefixed
with ``byedpi:``. The probe front-end (ByedpiManager) re-parses ``strategy``
with ``shlex.split``.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from blockchecks.engine.byedpi_translator import translate
from blockchecks.engine.generators import StrategyGenerator, StrategyItem

# ── Native ciadpi one-liners (byedpi-only families, see docs §3) ─────

# Curated from ByeByeDPI proxytest_strategies.list patterns and byedpi README.
NATIVE_BYEDPI = [
    # OOB / disoob — byedpi-only
    "-o1 -a1",
    "-o1 -a1 -r-5+se",
    "-q1 -a1",
    "-q1 -s1 -a1",
    # fake-sni — dynamic SNI in fake packet
    "-n {sni} -Qr -f-1 -r1+s -a1",
    "-n {sni} -f-1 -t8 -a1",
    # disorder / split ladders
    "--fake -1 --ttl 8 --split 1+s --disorder 3+s -a1",
    "--fake -1 --split 1+s --disorder 1+s -a1",
    "-s1+s -d3+s -a1",
    "-s0+sm -d0+sm -a1",
    # TLS record split in SNI
    "-r3+s -a1",
    "-r-5+se -a1",
    # md5sig (Linux)
    "-f-1 -S -a1",
    "-f-1 -S --split 1+s -a1",
    # mod-http (header case) — HTTP :80
    "-M h -a1",
    "-M h,d -a1",
    # fake-tls-mod rand (SessionID/Random/KeyExchange random)
    "-Qr -f-1 -a1",
    "-Qr -f-1 -r1+s -a1",
]

#: Native lines that only make sense for :80 HTTP probing.
NATIVE_HTTP_ONLY = frozenset({"-M h -a1", "-M h,d -a1"})


# ── Translated nfqws2 seed lines (confirmed families) ───────

# NOTE: dual-fake ALT2 (stun+max_ru, BEST 107ms) needs TWO nfqws2
# rawsends — ciadpi accepts a single -l fake-data, so it is not in this pool.
# See docs/byedpi_engine.md §3 "dual-fake needs 2 ciadpi processes".

TRANSLATED_SEEDS = [
    "fake:blob=stun:repeats=6:tcp_ts=-1000",
    "fake:blob=max_ru:repeats=6:tcp_ts=-1000",
    "fake:blob=google:repeats=6:tcp_ts=-1000",
    "fake:blob=4pda:repeats=6:tcp_ts=-1000",
    "hostfakesplit:nofake2:tcp_ts=-1000",
    "hostfakesplit:disorder_after:nofake2:tcp_ack=-66000:tcp_ts_up",
    "fakedsplit:pos=1:pattern=stun:repeats=1",
    "fakedsplit:pos=midsld:pattern=google:repeats=1",
    "fakeddisorder:pos=1:pattern=google",
    "multisplit:pos=1,midsld",
    "multisplit:pos=1:repeats=6",
    "tlsrec:pos=3+s",
    "oob:urp=b",
    "oob:urp=s",
    "syndata:tls_mod=rnd",
]


@dataclass
class ByedpiMatrixGenerator(StrategyGenerator):
    """Curated byedpi strategy pool (native + translated nfqws2)."""

    include_native: bool = True
    include_translated: bool = True
    include_http: bool = True

    async def generate(
        self,
        protocol: str = "tls12",
        state_db=None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 100,
        run_set=None,
    ) -> list[StrategyItem]:
        items: list[StrategyItem] = []
        http_mode = protocol == "http"

        if self.include_native:
            for line in NATIVE_BYEDPI:
                if line in NATIVE_HTTP_ONLY and not http_mode:
                    continue
                items.append(
                    StrategyItem(
                        label=f"byedpi_native:{line}",
                        strategy=line,
                        protocol="http" if line in NATIVE_HTTP_ONLY else "tls12",
                    )
                )

        if self.include_translated:
            for seed in TRANSLATED_SEEDS:
                if "tcp" not in seed.lower() and http_mode:
                    # http protocol only gets native HTTP lines
                    continue
                tr = translate(seed)
                if tr is None:
                    continue
                argv = tr.argv
                # multi-line seeds (dual-fake) become argv per line
                label = seed.replace("\n", "|")
                items.append(
                    StrategyItem(
                        label=f"byedpi:{label}",
                        strategy=shlex.join(argv),
                    )
                )

        # Dedup by strategy argv while preserving order
        seen: set[str] = set()
        deduped: list[StrategyItem] = []
        for item in items:
            if item.strategy in seen:
                continue
            seen.add(item.strategy)
            deduped.append(item)
        return deduped[:max_count]
