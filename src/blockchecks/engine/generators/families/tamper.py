"""Tamper/header family expansion: syndata, tcpseg, oob, geneva, wssize, http/quic/udp.

Methods follow the ``_fam_<name>(items, seen, family, scan_level, known_working)``
contract and delegate dedup/append to ``self._add``.
"""

from __future__ import annotations

from blockchecks.engine.config import VOICE_UDP_FILTER
from blockchecks.engine.generators.families._helpers import (
    _blob_abs,
    _with_ip6_send_drop,
)

# IPv6 foolings used by quic_fake ip6_send_drop variants (kept local to avoid
# a circular import with standard.py constants).
_FAST_FOOLINGS_IPV6 = ("ip6_hopbyhop", "ip6_destopt")


class TamperFamiliesMixin:
    """Strategy families built around header/flag/signature tampering."""

    def _fam_syndata(self, items, seen, family, scan_level, _known_working):
        """Expand syndata family."""
        for blob in family["blobs"]:
            for tmod in family["tls_mods"]:
                for plus in family["plus_split"]:
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
                    self._add(items, seen, label, strat)
                    if scan_level == "single":
                        return items
        if family.get("plus_hostfake") and scan_level != "single":
            strat = "syndata\nhostfakesplit:nofake2:tcp_ts=-1000"
            self._add(items, seen, "std_syn_bare_hf_ts", strat)
        return items

    def _fam_tcpseg(self, items, seen, family, scan_level, _known_working):
        """Expand tcpseg family."""
        for pos in family["positions"]:
            for r in family["repeats"]:
                strat = f"tcpseg:pos={pos}:ip_id={family['ip_id']}:repeats={r}"
                self._add(items, seen, f"std_tcpseg_p{pos}_r{r}", strat)
                if scan_level == "single":
                    return items
        return items

    def _fam_oob(self, items, seen, family, scan_level, _known_working):
        """Expand oob family."""
        in_range = family.get("in_range")
        for urp in family["urps"]:
            if in_range:
                strat = f"--in-range={in_range}\noob:urp={urp}"
            else:
                strat = f"oob:urp={urp}"
            self._add(items, seen, f"std_oob_urp{urp}", strat)
            if scan_level == "single":
                return items
        return items

    def _fam_geneva_fool(self, items, seen, family, scan_level, _known_working):
        """Expand geneva_fool family (custom fool= Lua hooks, Geneva 1-9/22/24)."""
        for fool in family.get("fools", []):
            for r in family.get("repeats", [1]):
                strat = f"send:{fool}:repeats={r}"
                tag = fool.replace("=", "_").replace(":", "_")
                label = f"std_gva_{tag}_r{r}"
                self._add(items, seen, label, strat)
                if scan_level == "single":
                    return items
        return items

    def _fam_wssize(self, items, seen, family, scan_level, _known_working):
        """Expand wssize companion family (blockcheck2 standard)."""
        for size in family.get("sizes", ["wssize:wsize=1:scale=6"]):
            self._add(items, seen, "std_wssize", size)
            if scan_level == "single":
                return items
        for combo in family.get("combos", [False]):
            if combo:
                strat = f"{family['sizes'][0]}\nmultisplit:pos=1:seqovl=1"
                self._add(items, seen, "std_wssize_multisplit", strat)
                if scan_level == "single":
                    return items
        return items

    def _fam_http_simple(self, items, seen, family, scan_level, _known_working):
        """Expand http_simple family."""
        for variant in family["variants"]:
            label = f"std_http_{variant.replace(':', '_')}"
            self._add(items, seen, label, variant, protocol="http")
            if scan_level == "single":
                return items
        return items

    def _fam_http_fake(self, items, seen, family, scan_level, _known_working):
        """Expand http_fake family."""
        for blob_name in family["blobs"]:
            blob = f":blob={blob_name}"
            for repeats in family["repeats"]:
                for fool in family["foolings"]:
                    fool_str = f":{fool}" if fool else ""
                    strat = f"fake{blob}:repeats={repeats}{fool_str}"
                    label = f"std_http_fake_{blob_name}_r{repeats}_{fool or 'nofool'}"
                    self._add(items, seen, label, strat, protocol="http")
                    if scan_level == "single":
                        return items
        return items

    def _fam_http_tls_dual(self, items, seen, family, scan_level, _known_working):
        """Expand http_tls_dual family."""
        for blob_name in family["http_blobs"]:
            for repeats in family["repeats"]:
                for fool in family["foolings"]:
                    fool_str = f":{fool}" if fool else ""
                    strat = f"fake:blob={blob_name}:repeats={repeats}{fool_str}"
                    label = f"std_http_tls_dual_{blob_name}_r{repeats}_{fool or 'nofool'}"
                    self._add(items, seen, label, strat, protocol="http")
                    if scan_level == "single":
                        return items
        return items

    def _fam_quic_fake(self, items, seen, family, scan_level, _known_working):
        """Expand quic_fake family."""
        for blob_name in family["blobs"]:
            for r in family["repeats"]:
                for fool in family.get("foolings", [""]):
                    fool_str = f":{fool}" if fool else ""
                    strat = f"fake:blob={blob_name}:repeats={r}{fool_str}"
                    label = f"std_quic_fake_{blob_name}_r{r}_{fool or 'nofool'}"
                    self._add(items, seen, label, strat, protocol="quic")
                    if scan_level == "single":
                        return items
        if family.get("ip6_send_drop"):
            for fool in family.get("ip6_fools", _FAST_FOOLINGS_IPV6):
                self._add(
                    items,
                    seen,
                    f"std_quic_ip6_{fool.replace(':', '_')}",
                    f"--filter-l3=ipv6\n{_with_ip6_send_drop(fool)}",
                    protocol="quic",
                )
        return items

    def _fam_quic_gv(self, items, seen, family, scan_level, _known_working):
        """Expand quic_gv family."""
        for blob_name in family["blobs"]:
            for r in family["repeats"]:
                strat = f"fake:blob={blob_name}:repeats={r}"
                label = f"std_quic_gv_{blob_name}_r{r}"
                self._add(items, seen, label, strat, protocol="quic")
                if scan_level == "single":
                    return items
        return items

    def _fam_udp_discord(self, items, seen, family, scan_level, _known_working):
        """Expand udp_discord family (voice UDP 50000-50100)."""
        blobs = family.get("blobs", ["discord_udp"])
        for blob_name in blobs:
            for r in family["repeats"]:
                core = f"fake:blob={blob_name}:repeats={r}"
                strat = f"--filter-udp={VOICE_UDP_FILTER}\n{core}"
                self._add(items, seen, f"std_udp_{blob_name}_r{r}", strat, protocol="udp_voice")
                if scan_level == "single":
                    return items
                for ttl in family.get("ttl_static", []):
                    self._add(
                        items,
                        seen,
                        f"std_udp_{blob_name}_r{r}_ttl{ttl}",
                        f"--filter-udp={VOICE_UDP_FILTER}\n{core}:ip_ttl={ttl}",
                        protocol="udp_voice",
                    )
                for ttl in family.get("ttl_auto", []):
                    self._add(
                        items,
                        seen,
                        f"std_udp_{blob_name}_r{r}_autottl",
                        f"--filter-udp={VOICE_UDP_FILTER}\n{core}:ip_autottl={ttl}",
                        protocol="udp_voice",
                    )

        return items

    def _fam_udp_quic(self, items, seen, family, scan_level, _known_working):
        """Expand udp_quic family."""
        for ports in family["port_ranges"]:
            for blob_name in family["blobs"]:
                for r in family["repeats"]:
                    s = (
                        f"--filter-udp={ports} "
                        f"--blob={blob_name}:@{_blob_abs(blob_name)} "
                        f"--payload=quic_initial "
                        f"--lua-desync=fake:blob={blob_name}:repeats={r}"
                    )
                    self._add(items, seen, f"std_udp_quic_{blob_name}_r{r}", s, protocol="quic")
                    if scan_level == "single":
                        return items

        return items

    def _fam_udp_game(self, items, seen, family, scan_level, _known_working):
        """Expand udp_game family."""
        for ports in family["port_ranges"]:
            for blob_name in family["blobs"]:
                for r in family["repeats"]:
                    for orng in family["out_range"]:
                        s = (
                            f"--filter-udp={ports} "
                            f"--blob={blob_name}:@{_blob_abs(blob_name)} "
                            f"--payload=unknown "
                            f"--lua-desync=fake:blob={blob_name}:repeats={r}"
                            + (f" --out-range={orng}" if orng else "")
                        )
                        self._add(
                            items,
                            seen,
                            f"std_udp_game_r{r}_{orng or 'no'}",
                            s,
                            protocol="udp_game",
                        )
                        if scan_level == "single":
                            return items

        return items

    def _fam_udp_multiblob(self, items, seen, family, scan_level, _known_working):
        """Expand udp_multiblob family."""
        for b1, b2 in family["profiles"]:
            for r in family["repeats"]:
                s = (
                    f"--filter-udp=443 --filter-l7=stun "
                    f"--blob={b1}:@{_blob_abs(b1)} "
                    f"--payload=stun "
                    f"--lua-desync=fake:blob={b1}:repeats={r}\n"
                    f"--filter-udp=443 --filter-l7=discord "
                    f"--blob={b2}:@{_blob_abs(b2)} "
                    f"--payload=discord_ip_discovery "
                    f"--lua-desync=fake:blob={b2}:repeats={r}"
                )
                self._add(items, seen, f"std_udp_multiblob_{b1}+{b2}_r{r}", s, protocol="udp_voice")
                if scan_level == "single":
                    return items

        return items
