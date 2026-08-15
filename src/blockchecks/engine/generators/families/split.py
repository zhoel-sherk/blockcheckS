"""Split-family expansion: multisplit / fakedsplit / disorder / ipfrag + SNI/Host.

Methods follow the ``_fam_<name>(items, seen, family, scan_level, known_working)``
contract and delegate dedup/append to ``self._add``.
"""

from __future__ import annotations

from blockchecks.engine.generators.families._helpers import _with_ack_drop, _with_send_md5


class SplitFamiliesMixin:
    """Strategy families built around TCP segment splitting/order manipulation."""

    def _fam_multisplit(self, items, seen, family, scan_level, _known_working):
        """Expand multisplit family."""
        pos_seqovl_pairs = [
            ("1", 1),
            ("2", 652),
            ("midsld", 1),
            ("sniext+1", 679),
            ("1,midsld", 1),
            ("host+1", 681),
        ]
        for pos, seqovl in pos_seqovl_pairs:
            for fool in family["foolings"]:
                fool_str = f":{fool}" if fool else ""
                for blob_name in family["seqovl_blobs"]:
                    if blob_name == "0x00000000":
                        continue
                    strat = (
                        f"multisplit:pos={pos}:seqovl={seqovl}:seqovl_pattern={blob_name}{fool_str}"
                    )
                    label = f"std_split_{pos}_s{seqovl}_{blob_name}_{fool or 'nofool'}"
                    self._add(items, seen, label, strat)
                    if scan_level == "single":
                        return items
                    for ttl in family["ttl_static"]:
                        self._add(items, seen, f"{label}_ttl{ttl}", f"{strat}:ip_ttl={ttl}")
                    for ttl in family["ttl_auto"]:
                        self._add(items, seen, f"{label}_autottl{ttl}", f"{strat}:ip_autottl={ttl}")
        if family.get("padencap") and scan_level != "single":
            for tmod in ("rnd,dupsid,padencap", "rnd,dupsid"):
                strat = (
                    f"fake:blob=google:repeats=6:tls_mod={tmod}\n"
                    f"multisplit:pos=10,sniext+1:seqovl=1"
                )
                self._add(items, seen, f"std_seqovl_pad_{tmod[:12]}", strat)
        return items

    def _fam_multidisorder(self, items, seen, family, scan_level, _known_working):
        """Expand multidisorder family."""
        for pos in family["positions"]:
            for fool in family["foolings"]:
                f = f":{fool}" if fool else ""
                for blob_name in family["seqovl_blobs"]:
                    strat = f"multidisorder:pos={pos}:seqovl_pattern={blob_name}{f}"
                    label = f"std_mdis_{pos}_{blob_name}_{fool or 'nofool'}"
                    self._add(items, seen, label, strat)
                    if scan_level == "single":
                        return items
                    for seqovl in family["seqovl"]:
                        strat = (
                            f"multidisorder:pos={pos}:seqovl={seqovl}:seqovl_pattern={blob_name}{f}"
                        )
                        label = f"std_mdis_{pos}_s{seqovl}_{blob_name}_{fool or 'nofool'}"
                        self._add(items, seen, label, strat)
                        if scan_level == "single":
                            return items
        return items

    def _fam_fakedsplit(self, items, seen, family, scan_level, _known_working):
        """Expand fakedsplit family."""
        for pos in family["positions"]:
            for blob_name in family["pattern_blobs"]:
                if blob_name == "0x00000000":
                    continue
                for fool in family["foolings"]:
                    f = f":{fool}" if fool else ""
                    for r in family["repeats"]:
                        strat = f"fakedsplit:pos={pos}:pattern={blob_name}{f}:repeats={r}"
                        label = f"std_fds_p{pos}_{blob_name}_r{r}_{fool or 'nofool'}"
                        self._add(items, seen, label, strat)
                        if scan_level == "single":
                            return items
                        if family.get("ack_drop") and fool in ("", "tcp_ts=-1000") and r == 6:
                            self._add(items, seen, f"{label}_ackdrop", _with_ack_drop(strat))
                        if family.get("send_md5") and "tcp_md5" in (fool or "") and r == 6:
                            self._add(items, seen, f"{label}_sendmd5", _with_send_md5(strat))
        return items

    def _fam_fakeddisorder(self, items, seen, family, scan_level, _known_working):
        """Expand fakeddisorder family."""
        for pos in family["positions"]:
            for blob_name in family["pattern_blobs"]:
                if blob_name == "0x00000000":
                    continue
                for fool in family["foolings"]:
                    f = f":{fool}" if fool else ""
                    for r in family["repeats"]:
                        strat = f"fakeddisorder:pos={pos}:pattern={blob_name}{f}:repeats={r}"
                        label = f"std_fdd_p{pos}_{blob_name}_r{r}_{fool or 'nofool'}"
                        self._add(items, seen, label, strat)
                        if scan_level == "single":
                            return items
                        if family.get("ack_drop") and fool in ("", "tcp_ts=-1000") and r == 6:
                            self._add(items, seen, f"{label}_ackdrop", _with_ack_drop(strat))
                        if family.get("send_md5") and "tcp_md5" in (fool or "") and r == 6:
                            self._add(items, seen, f"{label}_sendmd5", _with_send_md5(strat))
        return items

    def _fam_fake_multisplit(self, items, seen, family, scan_level, _known_working):
        """Expand fake_multisplit family."""
        for fake_blob, pattern_blob in family["blob_pairs"]:
            if fake_blob == pattern_blob:
                continue
            for pos in family["positions"]:
                for seqovl in family["seqovl"]:
                    for r in family["repeats"]:
                        for fool in family["foolings"]:
                            f = f":{fool}" if fool else ""
                            fake_line = f"fake:blob={fake_blob}:repeats={r}{f}"
                            split_line = (
                                f"multisplit:pos={pos}:seqovl={seqovl}"
                                f":seqovl_pattern={pattern_blob}{f}"
                            )
                            strat = f"{fake_line}\n{split_line}"
                            label = (
                                f"std_fms_{fake_blob}+{pattern_blob}_p{pos}_"
                                f"s{seqovl}_r{r}_{fool or 'nofool'}"
                            )
                            self._add(items, seen, label, strat)
                            if scan_level == "single":
                                return items
        return items

    def _fam_fake_multisplit_hostfake(self, items, seen, family, scan_level, _known_working):
        """Expand fake_multisplit_hostfake family."""
        for fake_blob, pattern_blob in family["blob_pairs"]:
            if fake_blob == pattern_blob:
                continue
            for pos in family["positions"]:
                for seqovl in family["seqovl"]:
                    for r in family["repeats"]:
                        for fool in family["foolings"]:
                            f = f":{fool}" if fool else ""
                            for host in family["hf_hosts"]:
                                strat = (
                                    f"fake:blob={fake_blob}:repeats={r}{f}\n"
                                    f"multisplit:pos={pos}:seqovl={seqovl}"
                                    f":seqovl_pattern={pattern_blob}{f}\n"
                                    f"hostfakesplit:host={host}:nofake2{f}:repeats=1"
                                )
                                label = (
                                    f"std_fmsh_{fake_blob}+{pattern_blob}_p{pos}_"
                                    f"s{seqovl}_h{host.split('.')[0]}_r{r}_{fool or 'nofool'}"
                                )
                                self._add(items, seen, label, strat)
                                if scan_level == "single":
                                    return items
        return items

    def _fam_fake_fakedsplit(self, items, seen, family, scan_level, _known_working):
        """Expand fake_fakedsplit family."""
        for blob_name in family["blobs"]:
            for pattern_blob in family["pattern_blobs"]:
                for pos in family["positions"]:
                    for r in family["repeats"]:
                        for fool in family["foolings"]:
                            f = f":{fool}" if fool else ""
                            strat = (
                                f"fake:blob={blob_name}:repeats={r}{f}\n"
                                f"fakedsplit:pos={pos}:pattern={pattern_blob}{f}"
                            )
                            label = (
                                f"std_ffds_{blob_name}+{pattern_blob}_p{pos}_"
                                f"r{r}_{fool or 'nofool'}"
                            )
                            self._add(items, seen, label, strat)
                            if scan_level == "single":
                                return items
        return items

    def _fam_tcp_ipfrag(self, items, seen, family, scan_level, _known_working):
        """Expand tcp_ipfrag family."""
        for pos in family["positions"]:
            for disorder in family.get("disorder", [False]):
                for nxt in family.get("ipfrag_next", [None]):
                    opts = f"ipfrag_pos_tcp={pos}"
                    if disorder:
                        opts += ":ipfrag_disorder"
                    if nxt is not None:
                        opts += f":ipfrag_next={nxt}"
                    strat = f"send:ipfrag:{opts}\ndrop"
                    label = f"std_tcp_ipfrag_pos{pos}"
                    if disorder:
                        label += "_disorder"
                    if nxt is not None:
                        label += f"_next{nxt}"
                    self._add(items, seen, label, strat)
                    if scan_level == "single":
                        return items
        for pos in family["positions"]:
            for blob_name in family.get("combo_blobs", [""]):
                if not blob_name:
                    continue
                for r in family["repeats"]:
                    for disorder in family.get("disorder", [False])[:1]:
                        opts = f"ipfrag_pos_tcp={pos}"
                        if disorder:
                            opts += ":ipfrag_disorder"
                        strat = f"fake:blob={blob_name}:repeats={r}\nsend:ipfrag:{opts}\ndrop"
                        label = f"std_tcp_fake_ipfrag_{blob_name}_r{r}_pos{pos}"
                        if disorder:
                            label += "_disorder"
                        self._add(items, seen, label, strat)
                        if scan_level == "single":
                            return items
        return items

    def _fam_quic_ipfrag(self, items, seen, family, scan_level, _known_working):
        """Expand quic_ipfrag family."""
        for pos in family["positions"]:
            for disorder in family.get("disorder", [False]):
                for nxt in family.get("ipfrag_next", [None]):
                    opts = f"ipfrag_pos_udp={pos}"
                    if disorder:
                        opts += ":ipfrag_disorder"
                    if nxt is not None:
                        opts += f":ipfrag_next={nxt}"
                    strat = f"send:ipfrag:{opts}\ndrop"
                    label = f"std_quic_ipfrag_pos{pos}"
                    if disorder:
                        label += "_disorder"
                    if nxt is not None:
                        label += f"_next{nxt}"
                    self._add(items, seen, label, strat, protocol="quic")
                    if scan_level == "single":
                        return items
        for pos in family["positions"]:
            for r in family["repeats"]:
                for disorder in family.get("disorder", [False])[:1]:
                    opts = f"ipfrag_pos_udp={pos}"
                    if disorder:
                        opts += ":ipfrag_disorder"
                    strat = f"fake:blob=fake_default_quic:repeats={r}\nsend:ipfrag:{opts}\ndrop"
                    label = f"std_quic_fake_ipfrag_r{r}_pos{pos}"
                    if disorder:
                        label += "_disorder"
                    self._add(items, seen, label, strat, protocol="quic")
                    if scan_level == "single":
                        return items
        return items
