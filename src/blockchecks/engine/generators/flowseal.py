"""Flowseal strategy generator — full technique coverage for nfqws2.

Covers desync patterns from Flowseal ``general*.bat`` suites
(https://github.com/Flowseal/zapret-discord-youtube), rewritten as lua-desync
cores. Not tied to a single bat; axes expand across all techniques + custom
blobs. Volume may exceed 1000 strategies — callers use ``max_count``.

Fooling map: ts→tcp_ts=-1000, badseq→badsid, md5sig→tcp_md5.
"""

from __future__ import annotations

from collections.abc import Iterator

from blockchecks.engine.blob_aliases import BLOB_ALIAS_MAP, resolve_blob_path
from blockchecks.engine.generators.base import StrategyGenerator, StrategyItem
from blockchecks.engine.store import RunStateStore

REPEATS = [3, 4, 6, 8, 11, 12]
FOOLINGS = ["tcp_ts=-1000", "tcp_md5", "badsid"]
FOOLINGS_TS_MD5 = ["tcp_ts=-1000", "tcp_md5", "tcp_ts=-1000:tcp_md5"]
SPLIT_POS = [1, 2, "midsld", "sniext+1", "1,midsld", "2,sniext+1"]
SEQOVL = [480, 568, 652, 664, 679, 681]
# Flowseal badseq-increment variants (ALT4 1000, FTA_ALT2 10000000, ALT8/ALT 2)
BADSEQ_INCREMENTS = [2, 1000, 10000000]
HOSTS = ["www.google.com", "ya.ru", "ozon.ru"]
SNI_LIST = ["www.google.com", "fonts.google.com", "ya.ru"]
TLS_MOD_NONE = "tls_mod=none"

_TCP_PREFERRED = ("stun", "stun2", "max_ru", "google", "4pda", "tls_vk")
_QUIC_PREFERRED = (
    "quic_google",
    "quic_dbank",
    "quic_initial",
    "quic_4pda",
    "quic_vk",
    "quic_tencent",
    "quic_steam",
)
_UDP_PREFERRED = ("discord_udp", "game_udp", "quic_dbank", "stun")


def _available_aliases(preferred: tuple[str, ...]) -> list[str]:
    out = [n for n in preferred if n in BLOB_ALIAS_MAP and resolve_blob_path(n)]
    return out or list(preferred[:3])


def _tcp_blobs() -> list[str]:
    return _available_aliases(_TCP_PREFERRED)


def _quic_blobs() -> list[str]:
    found = [n for n in _QUIC_PREFERRED if resolve_blob_path(n)]
    return found or ["quic_google", "quic_dbank"]


def _udp_blobs() -> list[str]:
    found = [n for n in _UDP_PREFERRED if resolve_blob_path(n)]
    return found or ["discord_udp", "stun"]


def _pattern_blobs(blobs: list[str]) -> list[str]:
    pats = list(dict.fromkeys([*blobs, "stun2"]))
    return [b for b in pats if resolve_blob_path(b) or b in blobs]


class FlowsealGenerator(StrategyGenerator):
    """Flowseal-like nfqws2 strategy matrix (all bat techniques + custom blobs)."""

    async def generate(
        self,
        protocol: str = "tls12",
        state_db: RunStateStore = None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 100,
        run_set: set = None,
    ) -> list[StrategyItem]:
        if protocol == "quic":
            return list(self._take(self._iter_quic(), scan_level, max_count, "quic"))
        if protocol == "udp_voice":
            return list(self._take(self._iter_udp(), scan_level, max_count, "udp_voice"))
        if protocol == "http":
            return list(self._take(self._iter_http(), scan_level, max_count, "http"))
        return list(self._take(self._iter_tcp(), scan_level, max_count, "tls12"))

    def _take(
        self,
        it: Iterator[tuple[str, str]],
        scan_level: str,
        max_count: int,
        protocol: str,
    ) -> list[StrategyItem]:
        items: list[StrategyItem] = []
        seen: set[str] = set()
        for label, strategy in it:
            if strategy in seen:
                continue
            seen.add(strategy)
            items.append(StrategyItem(label=label, strategy=strategy, protocol=protocol))
            if scan_level == "single" or len(items) >= max_count:
                break
        return items

    def _iter_tcp(self) -> Iterator[tuple[str, str]]:
        blobs = _tcp_blobs()
        pats = _pattern_blobs(blobs)
        b0, b1 = blobs[0], blobs[1] if len(blobs) > 1 else blobs[0]
        pat0 = pats[0]

        # Seeds — one of each technique so low max_count still covers families
        yield (
            "flw_multi_seed",
            (f"fake:blob={b0}:repeats=6:tcp_ts=-1000\nfake:blob={b1}:repeats=6:tcp_ts=-1000"),
        )
        yield "flw_split_seed", f"multisplit:pos=1:seqovl=568:seqovl_pattern={pat0}"
        yield "flw_exp_seqovl480", f"multisplit:pos=1:seqovl=480:seqovl_pattern={pat0}"
        yield "flw_fds_seed", "fakedsplit:pos=1:pattern=0x00000000:tcp_ts=-1000:repeats=1"
        yield "flw_hf_seed", "hostfakesplit:host=ozon.ru:tcp_ts=-1000:tcp_md5:repeats=1"
        yield (
            "flw_md_seed",
            (
                "fake:blob=0x00000000:repeats=11:badsid:tls_mod=rnd,dupsid,sni=www.google.com\n"
                "multidisorder:pos=1,midsld"
            ),
        )
        yield "flw_syndata", "syndata"
        yield "flw_syndata_md", "syndata\nmultidisorder:pos=1,midsld"
        yield "flw_fake_seed", f"fake:blob={b0}:repeats=6:tcp_ts=-1000"
        yield (
            "flw_tlsmod_seed",
            (f"fake:blob={b0}:repeats=6:tcp_ts=-1000:tls_mod=rnd,dupsid,sni=www.google.com"),
        )
        yield "flw_ipid_seed", f"fake:blob={b0}:repeats=6:tcp_ts=-1000:ip_id=zero"
        yield "flw_null_seed", "fake:blob=0x00000000:repeats=6:tcp_ts=-1000"
        yield "flw_blind_seed", "fake:repeats=6:tcp_ts=-1000"

        # Full expansion
        yield from self._expand_multi(blobs)
        yield from self._expand_multisplit(blobs, pats)
        yield from self._expand_fakedsplit(blobs)
        yield from self._expand_hostfake(blobs)
        yield from self._expand_multidisorder(blobs)
        yield from self._expand_singles(blobs)

    def _expand_multi(self, blobs: list[str]) -> Iterator[tuple[str, str]]:
        pairs = [(a, b) for i, a in enumerate(blobs) for b in blobs[i + 1 :]]
        for b1, b2 in pairs:
            for r in REPEATS:
                for fool in FOOLINGS:
                    yield (
                        f"flw_multi_{b1}+{b2}_r{r}_{fool}",
                        f"fake:blob={b1}:repeats={r}:{fool}\nfake:blob={b2}:repeats={r}:{fool}",
                    )
        # Flowseal badseq-increment variants (ALT4/ALT8/FTA_ALT2)
        for b1, b2 in pairs:
            for inc in BADSEQ_INCREMENTS:
                for r in (6, 8):
                    yield (
                        f"flw_multi_{b1}+{b2}_r{r}_badseq{inc}",
                        (
                            f"fake:blob={b1}:repeats={r}:tcp_seq={inc}\n"
                            f"fake:blob={b2}:repeats={r}:tcp_seq={inc}"
                        ),
                    )
        if len(blobs) >= 3:
            for i, b1 in enumerate(blobs):
                for j, b2 in enumerate(blobs):
                    if j <= i:
                        continue
                    for b3 in blobs[j + 1 :]:
                        for r in (6, 4, 8):
                            for fool in ("tcp_ts=-1000", "badsid"):
                                yield (
                                    f"flw_triple_{b1}+{b2}+{b3}_r{r}_{fool}",
                                    (
                                        f"fake:blob={b1}:repeats={r}:{fool}\n"
                                        f"fake:blob={b2}:repeats={r}:{fool}\n"
                                        f"fake:blob={b3}:repeats={r}:{fool}"
                                    ),
                                )

    def _expand_multisplit(self, blobs: list[str], pats: list[str]) -> Iterator[tuple[str, str]]:
        for pos in SPLIT_POS:
            for seqovl in SEQOVL:
                for pat in pats:
                    yield (
                        f"flw_split_p{pos}_s{seqovl}_{pat}",
                        f"multisplit:pos={pos}:seqovl={seqovl}:seqovl_pattern={pat}",
                    )
                    for blob in blobs[:4]:
                        for r in (6, 8, 4):
                            for fool in ("tcp_ts=-1000", "badsid"):
                                yield (
                                    f"flw_fake_split_{blob}_r{r}_p{pos}_s{seqovl}_{pat}_{fool}",
                                    (
                                        f"fake:blob={blob}:repeats={r}:{fool}\n"
                                        f"multisplit:pos={pos}:seqovl={seqovl}:seqovl_pattern={pat}"
                                    ),
                                )

    def _expand_fakedsplit(self, blobs: list[str]) -> Iterator[tuple[str, str]]:
        for pat in ["0x00000000", *blobs[:3]]:
            for fool in FOOLINGS:
                core = f"fakedsplit:pos=1:pattern={pat}:{fool}:repeats=1"
                yield f"flw_fds_p1_{pat}_{fool}", core
                for blob in blobs[:3]:
                    for r in (6, 8):
                        yield (
                            f"flw_fake_fds_{blob}_r{r}_{pat}_{fool}",
                            f"fake:blob={blob}:repeats={r}:{fool}\n{core}",
                        )

    def _expand_hostfake(self, blobs: list[str]) -> Iterator[tuple[str, str]]:
        for host in HOSTS:
            for fool in FOOLINGS_TS_MD5:
                for disorder in (False, True):
                    if disorder:
                        core = f"hostfakesplit:disorder_after:host={host}:{fool}:repeats=1"
                        tag = "hf_disorder"
                    else:
                        core = f"hostfakesplit:host={host}:{fool}:repeats=1"
                        tag = "hf"
                    yield f"flw_{tag}_{host}_{fool}", core
                    for blob in blobs[:3]:
                        for r in (6, 8):
                            yield (
                                f"flw_fake_{tag}_{blob}_r{r}_{host}_{fool}",
                                f"fake:blob={blob}:repeats={r}:{fool}\n{core}",
                            )
        # Flowseal ALT3: hostfakesplit-mod=host=...,altorder=1 (fake+hostfake)
        for host in HOSTS[:2]:
            for mod in ("altorder=1", ""):
                for r in (6, 8):
                    core = f"hostfakesplit:host={host}:tcp_ts=-1000"
                    if mod:
                        core += f":{mod}"
                    yield (
                        f"flw_fake_hf_alt3_{host.split('.')[0]}_{mod or 'plain'}_r{r}",
                        f"fake:blob=stun:repeats={r}:tcp_ts=-1000\n{core}",
                    )

    def _expand_multidisorder(self, blobs: list[str]) -> Iterator[tuple[str, str]]:
        for pos in ("1", "midsld", "1,midsld"):
            for fool in ("badsid", "tcp_ts=-1000"):
                for sni in SNI_LIST:
                    for r in (11, 8, 6):
                        for blob in ("0x00000000", *blobs[:2]):
                            fake = (
                                f"fake:blob={blob}:repeats={r}:{fool}:tls_mod=rnd,dupsid,sni={sni}"
                            )
                            yield (
                                f"flw_md_{blob}_r{r}_p{pos}_{fool}_sni={sni}",
                                f"{fake}\nmultidisorder:pos={pos}",
                            )

    def _expand_singles(self, blobs: list[str]) -> Iterator[tuple[str, str]]:
        for blob in blobs:
            for r in REPEATS:
                for fool in FOOLINGS:
                    yield f"flw_fake_{blob}_r{r}_{fool}", f"fake:blob={blob}:repeats={r}:{fool}"
                for sni in SNI_LIST:
                    for r2 in (6, 8):
                        yield (
                            f"flw_tlsmod_{blob}_sni={sni}_r{r2}",
                            (
                                f"fake:blob={blob}:repeats={r2}:tcp_ts=-1000:"
                                f"tls_mod=rnd,dupsid,sni={sni}"
                            ),
                        )
            # Flowseal badseq-increment (ALT4/ALT8/FTA_ALT2)
            for inc in BADSEQ_INCREMENTS:
                for r in (6, 8):
                    yield (
                        f"flw_fake_{blob}_r{r}_badseq{inc}",
                        f"fake:blob={blob}:repeats={r}:tcp_seq={inc}",
                    )
            # fake-tls-mod=none (ALT8/ALT10)
            for r in (6, 8):
                yield (
                    f"flw_tlsmod_none_{blob}_r{r}",
                    f"fake:blob={blob}:repeats={r}:tcp_ts=-1000:tls_mod=none",
                )
            for r in (6, 8):
                yield (
                    f"flw_ipid_{blob}_r{r}",
                    f"fake:blob={blob}:repeats={r}:tcp_ts=-1000:ip_id=zero",
                )
        for r in (6, 11, 12):
            for fool in FOOLINGS:
                yield f"flw_null_r{r}_{fool}", f"fake:blob=0x00000000:repeats={r}:{fool}"
                yield f"flw_blind_r{r}_{fool}", f"fake:repeats={r}:{fool}"
        # Flowseal ALT5: syndata + multidisorder link
        yield "flw_syndata_mdis", "syndata\nmultidisorder:pos=1,midsld:seqovl=1"
        # Flowseal ALT4: fake + multisplit WITHOUT split params (default pos=2)
        for blob in blobs[:3]:
            for inc in (1000, 2):
                yield (
                    f"flw_fake_msplit_{blob}_r6_badseq{inc}",
                    f"fake:blob={blob}:repeats=6:tcp_seq={inc}\nmultisplit",
                )
        # fake + multisplit with split-pos=2,sniext+1 (ALT7)
        for blob in blobs[:2]:
            yield (
                f"flw_fake_msplit_{blob}_pos2sniext",
                f"fake:blob={blob}:repeats=8:tcp_ts=-1000\nmultisplit:pos=2,sniext+1:seqovl=679",
            )

    def _iter_quic(self) -> Iterator[tuple[str, str]]:
        for blob in _quic_blobs():
            for r in (1, 2, 5, 6, 10, 11, 20):
                yield f"flw_quic_{blob}_r{r}", f"fake:blob={blob}:repeats={r}"
                yield f"flw_quic_{blob}_r{r}_badsum", f"fake:blob={blob}:repeats={r}:badsum"

    def _iter_udp(self) -> Iterator[tuple[str, str]]:
        for blob in _udp_blobs():
            for r in (3, 4, 6, 10, 12, 14):
                yield f"flw_udp_{blob}_r{r}", f"fake:blob={blob}:repeats={r}"
                yield f"flw_udp_{blob}_r{r}_ttl5", f"fake:blob={blob}:repeats={r}:ip_ttl=5"

    def _iter_http(self) -> Iterator[tuple[str, str]]:
        for blob in ("max_ru", "google", "0x00000000"):
            if blob != "0x00000000" and not resolve_blob_path(blob):
                continue
            for r in (6, 8, 11):
                for fool in FOOLINGS:
                    yield (
                        f"flw_http_{blob}_r{r}_{fool}",
                        f"fake:blob={blob}:repeats={r}:{fool}",
                    )
