"""Fake-packet expanders: fake, multi-fake, triple-fake, plus TTL and fooling."""

from __future__ import annotations

from blockchecks.engine.generators.families._helpers import _with_ack_drop, _with_send_md5


class FakeFamiliesMixin:
    """Strategy families built around fake ClientHello packets + blobs."""

    def _fam_fake(self, items, seen, family, scan_level, known_working):
        """Expand fake family."""
        if scan_level != "single":
            for ip6 in family.get("ipv6_extra", []):
                for blob_name in ("stun", "google"):
                    strat = f"fake:blob={blob_name}:repeats=6:{ip6}"
                    self._add(items, seen, f"std_fake_{blob_name}_r6_{ip6}", strat)
        for blob_name in family["blobs"]:
            blob = f":blob={blob_name}"
            for repeats in family["repeats"]:
                for fool in family["foolings"]:
                    fool_str = f":{fool}" if fool else ""
                    strat = f"fake{blob}:repeats={repeats}{fool_str}"
                    label = f"std_fake_{blob_name}_r{repeats}_{fool or 'nofool'}"
                    self._add(items, seen, label, strat)

                    if scan_level == "single":
                        return items

                    if (
                        family.get("ack_drop")
                        and fool in ("", "tcp_ts=-1000")
                        and blob_name
                        in (
                            "stun",
                            "google",
                            "0x00000000",
                        )
                    ):
                        self._add(items, seen, f"{label}_ackdrop", _with_ack_drop(strat))
                    if family.get("send_md5") and "tcp_md5" in (fool or ""):
                        self._add(items, seen, f"{label}_sendmd5", _with_send_md5(strat))

                    if scan_level == "fast" and label in known_working:
                        continue

                    for ttl in family["ttl_static"]:
                        self._add(items, seen, f"{label}_ttl{ttl}", f"{strat}:ip_ttl={ttl}")
                    for ttl in family["ttl_auto"]:
                        self._add(items, seen, f"{label}_autottl{ttl}", f"{strat}:ip_autottl={ttl}")
                    if blob_name in ("google", "0x00000000") and not fool:
                        for tmod in family["tls_mods"]:
                            if not tmod:
                                continue
                            for r in [6, 8]:
                                s = f"fake:blob={blob_name}:repeats={r}:tls_mod={tmod}"
                                self._add(
                                    items,
                                    seen,
                                    f"std_fake_{blob_name}_r{r}_tlsmod={tmod[:20]}",
                                    s,
                                )
        return items

    def _fam_hostfake(self, items, seen, family, scan_level, known_working):
        """Expand hostfake family."""
        for fool in family["foolings"]:
            fool_str = f":{fool}" if fool else ""
            for variant in family["variants"]:
                if variant == "base":
                    core = f"hostfakesplit:nofake2{fool_str}:repeats=1"
                elif variant == "disorder":
                    core = f"hostfakesplit:disorder_after:nofake2{fool_str}:repeats=1"
                else:
                    core = f"hostfakesplit:{variant}{fool_str}:repeats=1"
                label = f"std_hf_{variant}_{fool or 'nofool'}"
                self._add(items, seen, label, core)
                if scan_level == "single":
                    return items

                if family.get("ack_drop") and fool in ("", "tcp_ts=-1000") and variant == "base":
                    self._add(items, seen, f"{label}_ackdrop", _with_ack_drop(core))
                if family.get("send_md5") and "tcp_md5" in (fool or "") and variant == "base":
                    self._add(items, seen, f"{label}_sendmd5", _with_send_md5(core))

                if scan_level == "fast" and label in known_working:
                    continue

                for ttl in family["ttl_static"]:
                    self._add(items, seen, f"{label}_ttl{ttl}", f"{core}:ip_ttl={ttl}")
                for ttl in family["ttl_auto"]:
                    self._add(items, seen, f"{label}_autottl{ttl}", f"{core}:ip_autottl={ttl}")
        return items

    def _fam_multi_fake(self, items, seen, family, scan_level, _known_working):
        """Expand multi_fake family."""
        repeat_pairs = family.get(
            "repeat_pairs",
            [(r, r) for r in family.get("repeats", [6])],
        )
        for b1, b2 in family["blob_pairs"]:
            for r1, r2 in repeat_pairs:
                for fool in family["foolings"]:
                    f = f":{fool}" if fool else ""
                    strat = f"fake:blob={b1}:repeats={r1}{f}\nfake:blob={b2}:repeats={r2}{f}"
                    self._add(
                        items,
                        seen,
                        f"std_multi_{b1}+{b2}_r{r1}+{r2}_{fool or 'nofool'}",
                        strat,
                    )
                    if scan_level == "single":
                        return items
        return items

    def _fam_triple_fake(self, items, seen, family, scan_level, _known_working):
        """Expand triple_fake family."""
        for b1, b2, b3 in family["triples"]:
            for r in family["repeats"]:
                for fool in family["foolings"]:
                    f = f":{fool}" if fool else ""
                    strat = (
                        f"fake:blob={b1}:repeats={r}{f}\n"
                        f"fake:blob={b2}:repeats={r}{f}\n"
                        f"fake:blob={b3}:repeats={r}{f}"
                    )
                    self._add(
                        items,
                        seen,
                        f"std_triple_{b1}+{b2}+{b3}_r{r}_{fool or 'nofool'}",
                        strat,
                    )
                    if scan_level == "single":
                        return items
        return items

    def _fam_fake_multidisorder(self, items, seen, family, scan_level, _known_working):
        """Expand fake_multidisorder family."""
        for blob_name in family["blobs"]:
            for pos in family["positions"]:
                for r in family["repeats"]:
                    for fool in family["foolings"]:
                        f = f":{fool}" if fool else ""
                        strat = f"fake:blob={blob_name}:repeats={r}{f}\nmultidisorder:pos={pos}{f}"
                        label = f"std_fmd_{blob_name}_p{pos}_r{r}_{fool or 'nofool'}"
                        self._add(items, seen, label, strat)
                        if scan_level == "single":
                            return items
        return items

    def _fam_fake_hostfake(self, items, seen, family, scan_level, _known_working):
        """Expand fake_hostfake family."""
        for blob_name in family["blobs"]:
            for r in family["repeats"]:
                for fool in family["foolings"]:
                    f = f":{fool}" if fool else ""
                    for hf in family["hf_variants"]:
                        if hf == "base":
                            hf_core = f"hostfakesplit:nofake2{f}:repeats=1"
                        else:
                            hf_core = f"hostfakesplit:{hf}:nofake2{f}:repeats=1"
                        strat = f"fake:blob={blob_name}:repeats={r}{f}\n{hf_core}"
                        self._add(
                            items,
                            seen,
                            f"std_fh_{blob_name}_r{r}_{hf}_{fool or 'nofool'}",
                            strat,
                        )
                        if scan_level == "single":
                            return items
        return items

    def _fam_rst_fake(self, items, seen, family, scan_level, _known_working):
        """Expand rst_fake family (Geneva ACK→RST duplicates on empty ACK)."""
        for mod in family.get("mods", ["rst:badsum"]):
            strat = f"--payload=empty --out-range=s1<d1\n{mod}"
            label = f"std_rst_{mod.replace(':', '_').replace('=', '_')}"
            self._add(items, seen, label, strat)
            if scan_level == "single":
                return items
        for fake in family.get("flag_fakes", []):
            strat = f"--payload=empty --out-range=s1<d1\n{fake}"
            label = f"std_rst_{fake.split(':')[0]}_{fake.replace(':', '_').replace('=', '_')[:40]}"
            self._add(items, seen, label, strat)
            if scan_level == "single":
                return items
        return items

    def _fam_synack(self, items, seen, family, scan_level, _known_working):
        """Expand synack family (Geneva SYN→SA split handshake)."""
        seen_modes: set[str] = set()
        for mode in family.get("modes", ["synack"]):
            if mode in seen_modes:
                continue
            seen_modes.add(mode)
            core = f"synack_split:mode={mode}"
            label = f"std_synack_{mode}"
            self._add(items, seen, label, core)
            if scan_level == "single":
                return items
        # bare synack (single-packet S→SA)
        self._add(items, seen, "std_synack_bare", "synack")
        for fool in family.get("foolings", [""]):
            f = f":{fool}" if fool else ""
            strat = f"synack{f}"
            self._add(items, seen, f"std_synack_fool_{fool or 'nofool'}", strat)
            if scan_level == "single":
                return items
        return items
