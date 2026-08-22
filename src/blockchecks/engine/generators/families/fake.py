"""Fake-packet expanders: fake, multi-fake, triple-fake, plus TTL and fooling."""

from __future__ import annotations

from itertools import product

from blockchecks.engine.generators.families._helpers import (
    StrategyParams,
    _fooling_clause,
    _with_ack_drop,
    _with_send_md5,
    emit_rows,
    expand_axes,
    required_foolings,
    ttl_companion_rows,
)

_ACK_BLOBS = ("stun", "google", "0x00000000")


def _hf_core(variant: str, fool: str) -> str:
    f = _fooling_clause(fool)
    return {
        "base": f"hostfakesplit:nofake2{f}:repeats=1",
        "disorder": f"hostfakesplit:disorder_after:nofake2{f}:repeats=1",
    }.get(variant, f"hostfakesplit:{variant}{f}:repeats=1")


def _fake_hf_line(hf: str, fool: str) -> str:
    f = _fooling_clause(fool)
    if hf == "base":
        return f"hostfakesplit:nofake2{f}:repeats=1"
    return f"hostfakesplit:{hf}:nofake2{f}:repeats=1"


class FakeFamiliesMixin:
    """Strategy families built around fake ClientHello packets + blobs."""

    def _fam_fake(self, items, seen, family, scan_level, known_working):
        """Expand fake family."""
        p = StrategyParams.from_family(family, scan_level=scan_level)

        def _core(a: dict) -> tuple[str, str]:
            fool, blob, r = a["fool"], a["blob"], a["r"]
            return (
                f"std_fake_{blob}_r{r}_{fool or 'nofool'}",
                f"fake:blob={blob}:repeats={r}{_fooling_clause(fool)}",
            )

        axes = {"blob": p.blobs, "r": p.repeats, "fool": p.foolings}
        cores = expand_axes(axes, _core)
        if emit_rows(self._add, items, seen, scan_level, cores):
            return items

        ip6 = family.get("ipv6_extra", ())
        fool = next(iter(required_foolings(p.foolings)), "tcp_ts=-1000")
        if ip6 and scan_level != "single":
            emit_rows(
                self._add,
                items,
                seen,
                "fast",
                expand_axes(
                    {"ip6": ip6, "blob": ("stun", "google")},
                    lambda a: (
                        f"std_fake_{a['blob']}_r6_{a['ip6']}",
                        f"fake:blob={a['blob']}:repeats=6:{a['ip6']}:{fool}",
                    ),
                ),
            )

        combos = list(product(p.blobs, p.repeats, p.foolings))
        ack = [
            (f"{lab}_ackdrop", _with_ack_drop(st))
            for (lab, st), (blob, _r, fool) in zip(cores, combos, strict=True)
            if p.ack_drop and fool in ("", "tcp_ts=-1000") and blob in _ACK_BLOBS
        ]
        md5 = [
            (f"{lab}_sendmd5", _with_send_md5(st))
            for (lab, st), (_blob, _r, fool) in zip(cores, combos, strict=True)
            if p.send_md5 and "tcp_md5" in fool
        ]
        ttl = [
            row
            for lab, st in cores
            if not (scan_level == "fast" and lab in known_working)
            for row in ttl_companion_rows(lab, st, p.ttl_static, p.ttl_auto)
        ]
        tls = expand_axes(
            {
                "blob": tuple(b for b in p.blobs if b in ("google", "0x00000000")),
                "r": (6, 8),
                "tmod": tuple(t for t in p.tls_mods if t),
            },
            lambda a: (
                f"std_fake_{a['blob']}_r{a['r']}_tlsmod={a['tmod'][:20]}",
                f"fake:blob={a['blob']}:repeats={a['r']}:tls_mod={a['tmod']}",
            ),
        )
        # tls_mod companions only when the core has no fooling (matches prior nest)
        empty_fool = not any(p.foolings) or "" in p.foolings
        emit_rows(self._add, items, seen, scan_level, ack + md5 + ttl + (tls if empty_fool else []))
        return items

    def _fam_hostfake(self, items, seen, family, scan_level, known_working):
        """Expand hostfake family."""
        p = StrategyParams.from_family(
            family,
            scan_level=scan_level,
            foolings=required_foolings(family.get("foolings", ())),
        )

        def _core(a: dict) -> tuple[str, str]:
            fool, variant = a["fool"], a["variant"]
            return (
                f"std_hf_{variant}_{fool or 'nofool'}",
                _hf_core(variant, fool),
            )

        cores = expand_axes({"fool": p.foolings, "variant": p.variants}, _core)
        if hosts := tuple(family.get("hosts") or ()):
            extra = expand_axes(
                {"host": hosts, "fool": required_foolings(p.foolings) or ("tcp_ts=-1000",)},
                lambda a: (
                    f"std_hf_host_{a['host']}_{a['fool'] or 'nofool'}",
                    f"hostfakesplit:host={a['host']}:nofake2{_fooling_clause(a['fool'])}:repeats=1",
                ),
            )
            if emit_rows(self._add, items, seen, scan_level, extra):
                return items
        if emit_rows(self._add, items, seen, scan_level, cores):
            return items

        combos = list(product(p.foolings, p.variants))
        ack = [
            (f"{lab}_ackdrop", _with_ack_drop(st))
            for (lab, st), (fool, variant) in zip(cores, combos, strict=True)
            if p.ack_drop and fool == "tcp_ts=-1000" and variant == "base"
        ]
        md5 = [
            (f"{lab}_sendmd5", _with_send_md5(st))
            for (lab, st), (fool, variant) in zip(cores, combos, strict=True)
            if p.send_md5 and "tcp_md5" in fool and variant == "base"
        ]
        ttl = [
            row
            for lab, st in cores
            if not (scan_level == "fast" and lab in known_working)
            for row in ttl_companion_rows(lab, st, p.ttl_static, p.ttl_auto)
        ]
        emit_rows(self._add, items, seen, scan_level, ack + md5 + ttl)
        return items

    def _fam_multi_fake(self, items, seen, family, scan_level, _known_working):
        """Expand multi_fake family."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        repeat_pairs = family.get("repeat_pairs", [(r, r) for r in family.get("repeats", [6])])
        rows = expand_axes(
            {"pair": p.blob_pairs, "rp": repeat_pairs, "fool": p.foolings},
            lambda a: (
                f"std_multi_{a['pair'][0]}+{a['pair'][1]}_r{a['rp'][0]}+{a['rp'][1]}"
                f"_{a['fool'] or 'nofool'}",
                (
                    f"fake:blob={a['pair'][0]}:repeats={a['rp'][0]}{_fooling_clause(a['fool'])}\n"
                    f"fake:blob={a['pair'][1]}:repeats={a['rp'][1]}{_fooling_clause(a['fool'])}"
                ),
            ),
        )
        emit_rows(self._add, items, seen, scan_level, rows)
        return items

    def _fam_triple_fake(self, items, seen, family, scan_level, _known_working):
        """Expand triple_fake family."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        rows = expand_axes(
            {"t": p.triples, "r": p.repeats, "fool": p.foolings},
            lambda a: (
                f"std_triple_{a['t'][0]}+{a['t'][1]}+{a['t'][2]}_r{a['r']}_{a['fool'] or 'nofool'}",
                "\n".join(
                    f"fake:blob={b}:repeats={a['r']}{_fooling_clause(a['fool'])}" for b in a["t"]
                ),
            ),
        )
        emit_rows(self._add, items, seen, scan_level, rows)
        return items

    def _fam_fake_multidisorder(self, items, seen, family, scan_level, _known_working):
        """Expand fake_multidisorder family."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        rows = expand_axes(
            {"blob": p.blobs, "pos": p.positions, "r": p.repeats, "fool": p.foolings},
            lambda a: (
                f"std_fmd_{a['blob']}_p{a['pos']}_r{a['r']}_{a['fool'] or 'nofool'}",
                (
                    f"fake:blob={a['blob']}:repeats={a['r']}{_fooling_clause(a['fool'])}\n"
                    f"multidisorder:pos={a['pos']}{_fooling_clause(a['fool'])}"
                ),
            ),
        )
        emit_rows(self._add, items, seen, scan_level, rows)
        return items

    def _fam_fake_hostfake(self, items, seen, family, scan_level, _known_working):
        """Expand fake_hostfake family."""
        p = StrategyParams.from_family(
            family,
            scan_level=scan_level,
            foolings=required_foolings(family.get("foolings", ())),
        )
        rows = expand_axes(
            {
                "blob": p.blobs,
                "r": p.repeats,
                "fool": p.foolings,
                "hf": p.hf_variants,
            },
            lambda a: (
                f"std_fh_{a['blob']}_r{a['r']}_{a['hf']}_{a['fool'] or 'nofool'}",
                (
                    f"fake:blob={a['blob']}:repeats={a['r']}{_fooling_clause(a['fool'])}\n"
                    f"{_fake_hf_line(a['hf'], a['fool'])}"
                ),
            ),
        )
        emit_rows(self._add, items, seen, scan_level, rows)
        return items

    def _fam_rst_fake(self, items, seen, family, scan_level, _known_working):
        """Expand rst_fake family (Geneva ACK→RST duplicates on empty ACK)."""
        mods = tuple(family.get("mods", ["rst:badsum"]))
        fakes = tuple(family.get("flag_fakes", ()))
        if emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"mod": mods},
                lambda a: (
                    f"std_rst_{a['mod'].replace(':', '_').replace('=', '_')}",
                    f"--payload=empty --out-range=s1<d1\n{a['mod']}",
                ),
            ),
        ):
            return items
        emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"fake": fakes},
                lambda a: (
                    f"std_rst_{a['fake'].split(':')[0]}_"
                    f"{a['fake'].replace(':', '_').replace('=', '_')[:40]}",
                    f"--payload=empty --out-range=s1<d1\n{a['fake']}",
                ),
            ),
        )
        return items

    def _fam_synack(self, items, seen, family, scan_level, _known_working):
        """Expand synack family (Geneva SYN→SA split handshake)."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        modes = tuple(dict.fromkeys(family.get("modes", ["synack"])))
        if emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"mode": modes},
                lambda a: (f"std_synack_{a['mode']}", f"synack_split:mode={a['mode']}"),
            ),
        ):
            return items
        self._add(items, seen, "std_synack_bare", "synack")
        emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"fool": p.foolings or ("",)},
                lambda a: (
                    f"std_synack_fool_{a['fool'] or 'nofool'}",
                    f"synack{_fooling_clause(a['fool'])}",
                ),
            ),
        )
        return items
