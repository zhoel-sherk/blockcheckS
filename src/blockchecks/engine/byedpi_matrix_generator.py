"""Emit byedpi (ciadpi) strategies: native one-liners and nfqws2 lines run through byedpi_translator.
Item.strategy is space-joined argv; a translated nfqws2 line is stored in label.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from blockchecks.engine.byedpi_translator import translate
from blockchecks.engine.generators import StrategyGenerator, StrategyItem

# Native ciadpi one-liners

# Native ciadpi one-liners (no nfqws2 equivalent).
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


# Translated nfqws2 seed lines

# Dual-fake needs two nfqws2 rawsends; ciadpi takes one -l fake-data, so it is omitted.

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
