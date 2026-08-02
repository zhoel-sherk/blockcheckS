"""Flowseal ALT2 strategy generator."""

from blockchecks.engine.generators.base import StrategyGenerator, StrategyItem
from blockchecks.engine.store import RunStateStore


class FlowsealGenerator(StrategyGenerator):
    """Flowseal ALT2 → nfqws2 strategy generator.

    Generates 35+ combos based on Flowseal's battle-tested parameters:
    - multi-blob fake (2-3 blobs simultaneously)
    - multisplit with seqovl variations
    - hostfakesplit with host substitution
    - fake+tls_mod SNI spoofing
    - fooling variations (ts, md5, badseq)
    """

    async def generate(
        self,
        protocol: str = "tls12",
        state_db: RunStateStore = None,
        domain: str = "",
        scan_level: str = "fast",
        max_count: int = 100,
        run_set: set = None,
    ) -> list[StrategyItem]:
        # Flowseal TCP families only — skip for UDP protocols
        if protocol in ("udp_voice", "quic"):
            return []
        items = []
        blob_pairs = [
            ("stun", "max_ru"),
            ("stun", "google"),
            ("max_ru", "google"),
            ("stun", "4pda"),
        ]
        for b1, b2 in blob_pairs:
            for r in [6, 3, 8]:
                for fool in ["tcp_ts=-1000", "tcp_md5"]:
                    strat = f"fake:blob={b1}:repeats={r}:{fool}\nfake:blob={b2}:repeats={r}:{fool}"
                    label = f"flw_multi_{b1}+{b2}_r{r}_{fool}"
                    items.append(StrategyItem(label=label, strategy=strat))
                    if scan_level == "single":
                        return items[:max_count]

        # ── 2. Multisplit with seqovl (Flowseal ALT2 pattern) ──
        for pos in [1, 2, "midsld", "sniext+1"]:
            for seqovl in [568, 652, 664, 681]:
                for blob_name in ["google", "max_ru", "4pda"]:
                    strat = f"multisplit:pos={pos}:seqovl={seqovl}:seqovl_pattern={blob_name}"
                    label = f"flw_split_p{pos}_s{seqovl}_{blob_name}"
                    items.append(StrategyItem(label=label, strategy=strat))
                    if len(items) >= max_count:
                        return items[:max_count]

        # ── 3. Fake + TLS mod (SNI spoofing) ──
        for blob in ["google", "max_ru"]:
            for sni in ["www.google.com", "fonts.google.com", "ya.ru"]:
                for r in [6, 8]:
                    strat = (
                        f"fake:blob={blob}:repeats={r}:tcp_ts=-1000:tls_mod=rnd,dupsid,sni={sni}"
                    )
                    label = f"flw_fake_tlsmod_{blob}_sni={sni}_r{r}"
                    items.append(StrategyItem(label=label, strategy=strat))

        # ── 4. Hostfakesplit with host substitution ──
        for host in ["www.google.com", "ozon.ru"]:
            for fool in ["tcp_md5", "tcp_ts=-1000"]:
                strat = f"hostfakesplit:host={host}:{fool}:repeats=1"
                label = f"flw_hf_host={host}_{fool}"
                items.append(StrategyItem(label=label, strategy=strat))
                # With disorder_after
                strat2 = f"hostfakesplit:disorder_after:host={host}:{fool}:repeats=1"
                label2 = f"flw_hf_disorder_host={host}_{fool}"
                items.append(StrategyItem(label=label2, strategy=strat2))

        # ── 5. Fake with null blob + repeats (Flowseal game filter style) ──
        for r in [6, 12]:
            for fool in ["tcp_ts=-1000", "tcp_md5"]:
                strat = f"fake:blob=0x00000000:repeats={r}:{fool}"
                label = f"flw_null_r{r}_{fool}"
                items.append(StrategyItem(label=label, strategy=strat))

        # ── 6. Blind fake (no blob, auto-generated) — rarely works, but Flowseal has it ──
        for r in [6, 11]:
            strat = f"fake:repeats={r}:tcp_ts=-1000"
            label = f"flw_blind_r{r}"
            items.append(StrategyItem(label=label, strategy=strat))

        # ── 7. ip-id=zero for Google (Flowseal-specific) ──
        for r in [6, 8]:
            strat = f"fake:blob=google:repeats={r}:tcp_ts=-1000:ip_id=zero"
            label = f"flw_google_ipid_r{r}"
            items.append(StrategyItem(label=label, strategy=strat))

        return items[:max_count]
