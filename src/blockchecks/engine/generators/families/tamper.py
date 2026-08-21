"""Header/tamper expanders: syndata, tcpseg, oob, geneva, wssize, http, quic, udp."""

from __future__ import annotations

from blockchecks.engine.generators.families._helpers import (
    StrategyParams,
    _fooling_clause,
    _with_ip6_send_drop,
    emit_rows,
    expand_axes,
    ttl_companion_rows,
)

# IPv6 foolings used by quic_fake ip6_send_drop variants (kept local to avoid
# a circular import with standard.py constants).
_FAST_FOOLINGS_IPV6 = ("ip6_hopbyhop", "ip6_destopt")


class TamperFamiliesMixin:
    """Strategy families built around header/flag/signature tampering."""

    def _fam_syndata(self, items, seen, family, scan_level, _known_working):
        """Expand syndata family."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        plus_split = tuple(family.get("plus_split", (False,)))

        def _core(a: dict) -> tuple[str, str]:
            blob, tmod, plus = a["blob"], a["tmod"], a["plus"]
            if blob:
                strat = f"syndata:blob={blob}"
                if tmod:
                    strat += f":tls_mod={tmod}"
            else:
                strat = "syndata"
            if plus:
                strat = strat + "\nmultisplit:pos=1,midsld:seqovl=1"
            label = f"std_syn_{blob or 'bare'}_{tmod[:15] or 'nomod'}" + (
                "_split" if plus else ""
            )
            return label, strat

        if emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes({"blob": p.blobs, "tmod": p.tls_mods, "plus": plus_split}, _core),
        ):
            return items
        if family.get("plus_hostfake"):
            self._add(
                items,
                seen,
                "std_syn_bare_hf_ts",
                "syndata\nhostfakesplit:nofake2:tcp_ts=-1000",
            )
        return items

    def _fam_tcpseg(self, items, seen, family, scan_level, _known_working):
        """Expand tcpseg family."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        ip_id = family.get("ip_id", "rnd")
        emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"pos": p.positions, "r": p.repeats},
                lambda a: (
                    f"std_tcpseg_p{a['pos']}_r{a['r']}",
                    f"tcpseg:pos={a['pos']}:ip_id={ip_id}:repeats={a['r']}",
                ),
            ),
        )
        return items

    def _fam_oob(self, items, seen, family, scan_level, _known_working):
        """Expand oob family."""
        in_range = family.get("in_range")
        urps = tuple(family.get("urps", ()))
        emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"urp": urps},
                lambda a: (
                    f"std_oob_urp{a['urp']}",
                    (
                        f"--in-range={in_range}\noob:urp={a['urp']}"
                        if in_range
                        else f"oob:urp={a['urp']}"
                    ),
                ),
            ),
        )
        return items

    def _fam_geneva_fool(self, items, seen, family, scan_level, _known_working):
        """Expand geneva_fool family (custom fool= Lua hooks, Geneva 1-9/22/24)."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"fool": p.fools, "r": p.repeats},
                lambda a: (
                    f"std_gva_{a['fool'].replace('=', '_').replace(':', '_')}_r{a['r']}",
                    f"send:{a['fool']}:repeats={a['r']}",
                ),
            ),
        )
        return items

    def _fam_wssize(self, items, seen, family, scan_level, _known_working):
        """Expand wssize companion family (blockcheck2 standard)."""
        sizes = tuple(family.get("sizes", ["wssize:wsize=1:scale=6"]))
        if emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            [("std_wssize", size) for size in sizes],
        ):
            return items
        if any(family.get("combos", (False,))):
            self._add(
                items,
                seen,
                "std_wssize_multisplit",
                f"{sizes[0]}\nmultisplit:pos=1:seqovl=1",
            )
        return items

    def _fam_http_simple(self, items, seen, family, scan_level, _known_working):
        """Expand http_simple family."""
        variants = tuple(family.get("variants", ()))
        emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"variant": variants},
                lambda a: (f"std_http_{a['variant'].replace(':', '_')}", a["variant"]),
            ),
            protocol="http",
        )
        return items

    def _fam_http_fake(self, items, seen, family, scan_level, _known_working):
        """Expand http_fake family."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"blob": p.blobs, "r": p.repeats, "fool": p.foolings},
                lambda a: (
                    f"std_http_fake_{a['blob']}_r{a['r']}_{a['fool'] or 'nofool'}",
                    f"fake:blob={a['blob']}:repeats={a['r']}{_fooling_clause(a['fool'])}",
                ),
            ),
            protocol="http",
        )
        return items

    def _fam_http_tls_dual(self, items, seen, family, scan_level, _known_working):
        """Expand http_tls_dual family."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        blobs = tuple(str(b) for b in family.get("http_blobs", ()))
        emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"blob": blobs, "r": p.repeats, "fool": p.foolings},
                lambda a: (
                    f"std_http_tls_dual_{a['blob']}_r{a['r']}_{a['fool'] or 'nofool'}",
                    f"fake:blob={a['blob']}:repeats={a['r']}{_fooling_clause(a['fool'])}",
                ),
            ),
            protocol="http",
        )
        return items

    def _fam_quic_fake(self, items, seen, family, scan_level, _known_working):
        """Expand quic_fake family."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        if emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"blob": p.blobs, "r": p.repeats, "fool": p.foolings},
                lambda a: (
                    f"std_quic_fake_{a['blob']}_r{a['r']}_{a['fool'] or 'nofool'}",
                    f"fake:blob={a['blob']}:repeats={a['r']}{_fooling_clause(a['fool'])}",
                ),
            ),
            protocol="quic",
        ):
            return items
        if family.get("ip6_send_drop"):
            emit_rows(
                self._add,
                items,
                seen,
                scan_level,
                expand_axes(
                    {"fool": tuple(family.get("ip6_fools", _FAST_FOOLINGS_IPV6))},
                    lambda a: (
                        f"std_quic_ip6_{a['fool'].replace(':', '_')}",
                        f"--filter-l3=ipv6\n{_with_ip6_send_drop(a['fool'])}",
                    ),
                ),
                protocol="quic",
            )
        return items

    def _fam_quic_gv(self, items, seen, family, scan_level, _known_working):
        """Expand quic_gv family."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"blob": p.blobs, "r": p.repeats},
                lambda a: (
                    f"std_quic_gv_{a['blob']}_r{a['r']}",
                    f"fake:blob={a['blob']}:repeats={a['r']}",
                ),
            ),
            protocol="quic",
        )
        return items

    def _fam_udp_discord(self, items, seen, family, scan_level, _known_working):
        """Expand udp_discord family (voice UDP 50000-50100)."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        cores = expand_axes(
            {"blob": p.blobs or ("discord_udp",), "r": p.repeats},
            lambda a: (
                f"std_udp_{a['blob']}_r{a['r']}",
                f"fake:blob={a['blob']}:repeats={a['r']}",
            ),
        )
        if emit_rows(self._add, items, seen, scan_level, cores, protocol="udp_voice"):
            return items
        ttl = [
            row
            for lab, st in cores
            for row in ttl_companion_rows(
                lab, st, p.ttl_static, p.ttl_auto, auto_fmt="autottl"
            )
        ]
        emit_rows(self._add, items, seen, scan_level, ttl, protocol="udp_voice")
        return items

    def _fam_udp_quic(self, items, seen, family, scan_level, _known_working):
        """Expand udp_quic family (compact lua-desync cores; C-filters elsewhere)."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"blob": p.blobs, "r": p.repeats},
                lambda a: (
                    f"std_udp_quic_{a['blob']}_r{a['r']}",
                    f"fake:blob={a['blob']}:repeats={a['r']}",
                ),
            ),
            protocol="quic",
        )
        return items

    def _fam_udp_game(self, items, seen, family, scan_level, _known_working):
        """Expand udp_game family (compact cores; optional --out-range selector)."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"blob": p.blobs, "r": p.repeats, "orng": p.out_range or (None,)},
                lambda a: (
                    f"std_udp_game_{a['blob']}_r{a['r']}_{a['orng'] or 'no'}",
                    (
                        f"--out-range={a['orng']}\nfake:blob={a['blob']}:repeats={a['r']}"
                        if a["orng"]
                        else f"fake:blob={a['blob']}:repeats={a['r']}"
                    ),
                ),
            ),
            protocol="udp_game",
        )
        return items

    def _fam_udp_multiblob(self, items, seen, family, scan_level, _known_working):
        """Expand udp_multiblob family (two compact fake cores)."""
        p = StrategyParams.from_family(family, scan_level=scan_level)
        emit_rows(
            self._add,
            items,
            seen,
            scan_level,
            expand_axes(
                {"prof": p.profiles, "r": p.repeats},
                lambda a: (
                    f"std_udp_multiblob_{a['prof'][0]}+{a['prof'][1]}_r{a['r']}",
                    (
                        f"fake:blob={a['prof'][0]}:repeats={a['r']}\n"
                        f"fake:blob={a['prof'][1]}:repeats={a['r']}"
                    ),
                ),
            ),
            protocol="udp_voice",
        )
        return items
