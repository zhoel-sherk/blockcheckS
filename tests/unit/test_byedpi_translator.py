"""Unit tests for byedpi_translator (nfqws2 → ciadpi argv mapping)."""

from __future__ import annotations

import pytest

from blockchecks.engine.byedpi_translator import (
    TRANSLATION_FULL,
    TRANSLATION_PARTIAL,
    can_translate,
    translate,
)

pytestmark = pytest.mark.unit


def test_tcp_ts_untranslatable():
    assert translate("fake:blob=stun:repeats=6:tcp_ts=-1000") is None
    assert translate("hostfakesplit:nofake2:tcp_ts=-1000") is None
    assert not can_translate("fake:blob=stun:repeats=6:tcp_ts=-1000")


def test_fake_md5_argv():
    t = translate("fake:blob=stun:repeats=6:tcp_md5")
    assert t is not None
    assert "--md5sig" in t.argv


def test_fake_blob_uses_real_path():
    t = translate("fake:blob=stun:repeats=6")
    assert t is not None
    assert any(a == "-l" for a in t.argv)
    lp = t.argv[t.argv.index("-l") + 1]
    assert lp.endswith("stun.bin")


def test_hostfakesplit_without_tcp_ts():
    t = translate("hostfakesplit:nofake2")
    assert t is not None
    assert t.argv[:2] == ["--split", "1+sm"]


def test_hostfakesplit_disorder_drops_ack():
    t = translate("hostfakesplit:disorder_after:nofake2:tcp_ack=-66000:tcp_ts_up")
    assert t is not None
    assert t.argv[:4] == ["--split", "1+sm", "--disorder", "1+sm"]
    assert "--ttl" not in t.argv
    assert any("tcp_ack" in n and "dropped" in n for n in t.notes)
    assert any("tcp_ts_up" in n and "dropped" in n for n in t.notes)
    assert t.quality == TRANSLATION_PARTIAL


def test_fakedsplit_full():
    t = translate("fakedsplit:pos=1:pattern=stun:repeats=1")
    assert t is not None
    assert t.argv[:4] == ["--fake", "1", "--disorder", "1"]
    assert t.quality == TRANSLATION_FULL


def test_fakedsplit_midsld():
    t = translate("fakedsplit:pos=midsld:pattern=google")
    assert t is not None
    assert t.argv[:4] == ["--fake", "0+sm", "--disorder", "0+sm"]


def test_fakeddisorder():
    t = translate("fakeddisorder:pos=1:pattern=google")
    assert t is not None
    assert t.argv[:4] == ["--disorder", "1", "--fake", "1"]


def test_multisplit_positions():
    t = translate("multisplit:pos=1,midsld")
    assert t is not None
    assert "--split" in t.argv
    assert t.argv.count("--split") == 2


def test_tlsrec():
    t = translate("tlsrec:pos=3+s")
    assert t is not None
    assert t.argv == ["-r", "3+s"]


def test_oob_urp():
    t = translate("oob:urp=b")
    assert t.argv == ["-o", "0"]
    t = translate("oob:urp=s")
    assert t.argv == ["-o", "0+sm"]


def test_syndata():
    t = translate("syndata:tls_mod=rnd")
    assert t is not None
    assert t.argv == ["-f", "-1", "-Q", "rand"]


def test_unmapped_fooling_skip():
    assert translate("fake:blob=stun:repeats=6:badsum") is None
    assert translate("fake:blob=stun:repeats=6:badseq") is None


def test_seqovl_skip():
    assert translate("multisplit:pos=1:seqovl=68") is None


def test_quic_blob_not_skipped():
    t = translate("fake:blob=quic_initial:repeats=11")
    assert t is not None
    assert t.argv[:2] == ["-f", "-1"]


def test_dupsid_in_tls_mod_not_skipped():
    t = translate(
        "fake:blob=google:repeats=6:tls_mod=rnd,dupsid,sni=www.google.com"
    )
    assert t is not None
    assert t.argv[:2] == ["-f", "-1"]


def test_dup_token_still_skips():
    assert translate("fake:blob=stun:repeats=6:dup") is None


def test_quic_token_still_skips():
    assert translate("fake:blob=stun:repeats=6:quic") is None


def test_ip6_fooling_still_skips():
    assert translate("fake:blob=stun:repeats=6:ip6_hopbyhop") is None


def test_unknown_family_skip():
    assert translate("circular:fails=3") is None
    assert translate("") is None


def test_translate_multi_line_dual_fake_first_line_only():
    # Dual-fake ALT2 needs two nfqws2 rawsends; ciadpi takes one -l.
    dual = "fake:blob=stun:repeats=6\nfake:blob=max_ru:repeats=6"
    t = translate(dual)
    assert t is not None
    # Only the first line's blob is present (single -l).
    assert t.argv.count("-l") == 1
