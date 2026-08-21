"""Split expanders: multisplit, fakedsplit, disorder, ipfrag, plus SNI/Host positions."""

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


def _disorder_seqovl_ok(pos: str, seqovl: int) -> bool:
    """Zapret2 cancels disorder seqovl when seqovl >= numeric_pos (1-based)."""
    head = pos.split(",", 1)[0].strip()
    if not head.isdigit():
        return True
    return seqovl < int(head)


def _ipfrag_opts(kind: str, pos: str, disorder: bool, nxt) -> str:
    return "".join(
        (
            f"ipfrag_pos_{kind}={pos}",
            ":ipfrag_disorder" if disorder else "",
            f":ipfrag_next={nxt}" if nxt is not None else "",
        )
    )


def _ipfrag_label(prefix: str, pos: str, disorder: bool, nxt) -> str:
    return "".join(
        (
            f"{prefix}{pos}",
            "_disorder" if disorder else "",
            f"_next{nxt}" if nxt is not None else "",
        )
    )


def _skip_null(blobs: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(b for b in blobs if b != "0x00000000")


class SplitFamiliesMixin:
    """Strategy families built around TCP segment splitting/order manipulation."""

    def _fam_multisplit(self, items, seen, family, scan_level, _known_working):
        """Expand multisplit family."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        blobs = _skip_null(p.seqovl_blobs)

        def _core(a: dict) -> tuple[str, str]:
            pos, seqovl, fool, blob = a["pos"], a["seqovl"], a["fool"], a["blob"]
            return (
                f"std_split_{pos}_s{seqovl}_{blob}_{fool or 'nofool'}",
                f"multisplit:pos={pos}:seqovl={seqovl}:seqovl_pattern={blob}{_fooling_clause(fool)}",
            )

        cores = expand_axes(
            {"pos": p.positions, "seqovl": p.seqovl, "fool": p.foolings, "blob": blobs},
            _core,
        )
        if emit_rows(self._add, items, seen, scan_level, cores):
            return items
        ttl = [
            row
            for lab, st in cores
            for row in ttl_companion_rows(lab, st, p.ttl_static, p.ttl_auto)
        ]
        emit_rows(self._add, items, seen, scan_level, ttl)
        if family.get("padencap"):
            emit_rows(
                self._add,
                items,
                seen,
                scan_level,
                expand_axes(
                    {"tmod": ("rnd,dupsid,padencap", "rnd,dupsid")},
                    lambda a: (
                        f"std_seqovl_pad_{a['tmod'][:12]}",
                        (
                            f"fake:blob=google:repeats=6:tls_mod={a['tmod']}\n"
                            f"multisplit:pos=10,sniext+1:seqovl=1"
                        ),
                    ),
                ),
            )
        return items

    def _fam_multidisorder(self, items, seen, family, scan_level, _known_working):
        """Expand multidisorder family."""
        p = StrategyParams.from_family(family, scan_level=scan_level)

        def _bare(a: dict) -> tuple[str, str]:
            pos, fool, blob = a["pos"], a["fool"], a["blob"]
            return (
                f"std_mdis_{pos}_{blob}_{fool or 'nofool'}",
                f"multidisorder:pos={pos}:seqovl_pattern={blob}{_fooling_clause(fool)}",
            )

        if emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes({"pos": p.positions, "fool": p.foolings, "blob": p.seqovl_blobs}, _bare),
        ):
            return items
        seqovl_rows = [
            (
                f"std_mdis_{pos}_s{seqovl}_{blob}_{fool or 'nofool'}",
                (
                    f"multidisorder:pos={pos}:seqovl={seqovl}"
                    f":seqovl_pattern={blob}{_fooling_clause(fool)}"
                ),
            )
            for pos, fool, blob, seqovl in product(
                p.positions, p.foolings, p.seqovl_blobs, p.seqovl
            )
            if _disorder_seqovl_ok(pos, seqovl)
        ]
        emit_rows(self._add, items, seen, scan_level, seqovl_rows)
        return items

    def _fam_fakedsplit(self, items, seen, family, scan_level, _known_working):
        """Expand fakedsplit family."""
        return self._fam_faked_core(items, seen, family, scan_level, "fakedsplit", "std_fds")

    def _fam_fakeddisorder(self, items, seen, family, scan_level, _known_working):
        """Expand fakeddisorder family."""
        return self._fam_faked_core(items, seen, family, scan_level, "fakeddisorder", "std_fdd")

    def _fam_faked_core(self, items, seen, family, scan_level, fn: str, prefix: str):
        p = StrategyParams.from_family(
            family,
            scan_level=scan_level,
            foolings=required_foolings(family.get("foolings", ())),
        )
        blobs = _skip_null(p.pattern_blobs)

        def _core(a: dict) -> tuple[str, str]:
            pos, blob, fool, r = a["pos"], a["blob"], a["fool"], a["r"]
            return (
                f"{prefix}_p{pos}_{blob}_r{r}_{fool or 'nofool'}",
                f"{fn}:pos={pos}:pattern={blob}{_fooling_clause(fool)}:repeats={r}",
            )

        cores = expand_axes(
            {"pos": p.positions, "blob": blobs, "fool": p.foolings, "r": p.repeats},
            _core,
        )
        if emit_rows(self._add, items, seen, scan_level, cores):
            return items
        combos = list(product(p.positions, blobs, p.foolings, p.repeats))
        ack = [
            (f"{lab}_ackdrop", _with_ack_drop(st))
            for (lab, st), (_pos, _blob, fool, r) in zip(cores, combos, strict=True)
            if p.ack_drop and fool == "tcp_ts=-1000" and r == 6
        ]
        md5 = [
            (f"{lab}_sendmd5", _with_send_md5(st))
            for (lab, st), (_pos, _blob, fool, r) in zip(cores, combos, strict=True)
            if p.send_md5 and "tcp_md5" in fool and r == 6
        ]
        emit_rows(self._add, items, seen, scan_level, ack + md5)
        return items

    def _fam_fake_multisplit(self, items, seen, family, scan_level, _known_working):
        """Expand fake_multisplit family."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        pairs = tuple(pair for pair in p.blob_pairs if pair[0] != pair[1])
        rows = expand_axes(
            {
                "pair": pairs,
                "pos": p.positions,
                "seqovl": p.seqovl,
                "r": p.repeats,
                "fool": p.foolings,
            },
            lambda a: (
                (
                    f"std_fms_{a['pair'][0]}+{a['pair'][1]}_p{a['pos']}_"
                    f"s{a['seqovl']}_r{a['r']}_{a['fool'] or 'nofool'}"
                ),
                (
                    f"fake:blob={a['pair'][0]}:repeats={a['r']}{_fooling_clause(a['fool'])}\n"
                    f"multisplit:pos={a['pos']}:seqovl={a['seqovl']}"
                    f":seqovl_pattern={a['pair'][1]}{_fooling_clause(a['fool'])}"
                ),
            ),
        )
        emit_rows(self._add, items, seen, scan_level, rows)
        return items

    def _fam_fake_multisplit_hostfake(self, items, seen, family, scan_level, _known_working):
        """Expand fake_multisplit_hostfake family."""
        p = StrategyParams.from_family(
            family,
            scan_level=scan_level,
            foolings=required_foolings(family.get("foolings", ())),
        )
        pairs = tuple(pair for pair in p.blob_pairs if pair[0] != pair[1])
        rows = expand_axes(
            {
                "pair": pairs,
                "pos": p.positions,
                "seqovl": p.seqovl,
                "r": p.repeats,
                "fool": p.foolings,
                "host": p.hf_hosts,
            },
            lambda a: (
                (
                    f"std_fmsh_{a['pair'][0]}+{a['pair'][1]}_p{a['pos']}_"
                    f"s{a['seqovl']}_h{a['host'].split('.')[0]}_r{a['r']}_{a['fool'] or 'nofool'}"
                ),
                (
                    f"fake:blob={a['pair'][0]}:repeats={a['r']}{_fooling_clause(a['fool'])}\n"
                    f"multisplit:pos={a['pos']}:seqovl={a['seqovl']}"
                    f":seqovl_pattern={a['pair'][1]}{_fooling_clause(a['fool'])}\n"
                    f"hostfakesplit:host={a['host']}:nofake2{_fooling_clause(a['fool'])}:repeats=1"
                ),
            ),
        )
        emit_rows(self._add, items, seen, scan_level, rows)
        return items

    def _fam_fake_fakedsplit(self, items, seen, family, scan_level, _known_working):
        """Expand fake_fakedsplit family."""
        p = StrategyParams.from_family(
            family,
            scan_level=scan_level,
            foolings=required_foolings(family.get("foolings", ())),
        )
        rows = expand_axes(
            {
                "blob": p.blobs,
                "pattern": p.pattern_blobs,
                "pos": p.positions,
                "r": p.repeats,
                "fool": p.foolings,
            },
            lambda a: (
                (
                    f"std_ffds_{a['blob']}+{a['pattern']}_p{a['pos']}_"
                    f"r{a['r']}_{a['fool'] or 'nofool'}"
                ),
                (
                    f"fake:blob={a['blob']}:repeats={a['r']}{_fooling_clause(a['fool'])}\n"
                    f"fakedsplit:pos={a['pos']}:pattern={a['pattern']}{_fooling_clause(a['fool'])}"
                ),
            ),
        )
        emit_rows(self._add, items, seen, scan_level, rows)
        return items

    def _fam_tcp_ipfrag(self, items, seen, family, scan_level, _known_working):
        """Expand tcp_ipfrag family."""
        return self._fam_ipfrag(items, seen, family, scan_level, kind="tcp", proto="tls12")

    def _fam_quic_ipfrag(self, items, seen, family, scan_level, _known_working):
        """Expand quic_ipfrag family."""
        return self._fam_ipfrag(items, seen, family, scan_level, kind="udp", proto="quic")

    def _fam_ipfrag(self, items, seen, family, scan_level, *, kind: str, proto: str):
        p = StrategyParams.from_family(family, scan_level=scan_level)
        disorder = tuple(family.get("disorder", [False]))
        nxts = tuple(family.get("ipfrag_next", [None]))
        prefix = f"std_{'tcp' if kind == 'tcp' else 'quic'}_ipfrag_pos"
        combo_blobs = tuple(b for b in family.get("combo_blobs", ("",)) if b)
        if kind == "udp":
            combo_blobs = combo_blobs or ("fake_default_quic",)

        def _bare(a: dict) -> tuple[str, str]:
            pos, dis, nxt = a["pos"], a["disorder"], a["nxt"]
            opts = _ipfrag_opts(kind, pos, dis, nxt)
            return (
                _ipfrag_label(prefix, pos, dis, nxt),
                f"send:ipfrag:{opts}\ndrop",
            )

        if emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes({"pos": p.positions, "disorder": disorder, "nxt": nxts}, _bare),
            protocol=proto,
        ):
            return items

        def _combo(a: dict) -> tuple[str, str]:
            pos, blob, r, dis = a["pos"], a["blob"], a["r"], a["disorder"]
            opts = _ipfrag_opts(kind, pos, dis, None)
            tag = f"std_{'tcp' if kind == 'tcp' else 'quic'}_fake_ipfrag"
            mid = f"_{blob}" if kind == "tcp" else ""
            return (
                _ipfrag_label(f"{tag}{mid}_r{r}_pos", pos, dis, None),
                f"fake:blob={blob}:repeats={r}\nsend:ipfrag:{opts}\ndrop",
            )

        emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {
                    "pos": p.positions,
                    "blob": combo_blobs,
                    "r": p.repeats,
                    "disorder": disorder[:1],
                },
                _combo,
            ),
            protocol=proto,
        )
        return items
