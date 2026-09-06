"""Blob-class filter and custom-Lua activation from triage."""

from blockchecks.engine.blob_filter import (
    aliases_for_class,
    blob_class,
    filter_blob_aliases,
    lua_files_for_triage,
)
from blockchecks.engine.triage import TriageProfile


def test_blob_class_aliases():
    assert blob_class("stun") == "stun"
    assert blob_class("google") == "tls_clienthello"
    assert blob_class("quic_google") == "quic"
    assert blob_class("discord_udp") == "discord_udp"


def test_filter_empty_viable_keeps_all():
    pool = ["stun", "google", "quic_google"]
    assert filter_blob_aliases(pool, TriageProfile()) == pool


def test_filter_by_class_and_name():
    pool = ["stun", "stun2", "google", "quic_google"]
    profile = TriageProfile(viable_blobs=["stun", "tls_clienthello"])
    assert filter_blob_aliases(pool, profile) == ["stun", "stun2", "google"]


def test_dupfake_lua_activates_on_silent_drop():
    files = lua_files_for_triage(TriageProfile(silent_drop_after_sni=True))
    assert "dupfake.lua" in files
    assert lua_files_for_triage(TriageProfile()) == []


def test_aliases_for_class_includes_google():
    aliases = aliases_for_class("tls_clienthello")
    assert "tls_clienthello" in aliases
    assert "google" in aliases
    assert "max_ru" in aliases


def test_blob_class_full_map():
    from blockchecks.engine.blob_filter import BLOB_CLASS_MAP, blob_class

    for alias, cls in BLOB_CLASS_MAP.items():
        assert blob_class(alias) == cls


def test_blob_class_prefix_and_other():
    from blockchecks.engine.blob_filter import blob_class

    assert blob_class("quic_custom") == "quic"
    assert blob_class("tls_custom") == "tls_clienthello"
    assert blob_class("zzz") == "other"
    assert blob_class("quic") == "other"


def test_aliases_for_class_quic_and_stun():
    from blockchecks.engine.blob_filter import aliases_for_class

    q = aliases_for_class("quic")
    assert "quic_google" in q
    assert "quic_initial" in q
    assert "quic" not in q
    assert aliases_for_class("stun") == ["stun", "stun2"]


def test_filter_none_profile_returns_alias_map():
    from blockchecks.engine.blob_aliases import BLOB_ALIAS_MAP
    from blockchecks.engine.blob_filter import filter_blob_aliases
    from blockchecks.engine.triage import TriageProfile

    assert filter_blob_aliases(None, None) == list(BLOB_ALIAS_MAP)
    assert filter_blob_aliases(None, TriageProfile()) == list(BLOB_ALIAS_MAP)


def test_filter_protocol_udp_and_quic_keep_transport_blobs():
    from blockchecks.engine.blob_filter import filter_blob_aliases
    from blockchecks.engine.triage import TriageProfile

    pool = ["tls_clienthello", "discord_udp"]
    prof = TriageProfile(viable_blobs=["tls_clienthello"])
    assert filter_blob_aliases(pool, prof, protocol="udp_voice") == pool
    assert filter_blob_aliases(pool, prof, protocol="tcp") == ["tls_clienthello"]

    pool2 = ["quic_google", "stun"]
    prof2 = TriageProfile(viable_blobs=["stun"])
    assert filter_blob_aliases(pool2, prof2, protocol="quic") == pool2


def test_filter_keeps_alias_by_exact_name():
    from blockchecks.engine.blob_filter import filter_blob_aliases
    from blockchecks.engine.triage import TriageProfile

    pool = ["stun", "notreal"]
    prof = TriageProfile(viable_blobs=["notreal"])
    assert filter_blob_aliases(pool, prof) == ["notreal"]


def test_lua_files_dedupe():
    from blockchecks.engine.blob_filter import lua_files_for_triage
    from blockchecks.engine.triage import TriageProfile

    assert lua_files_for_triage(None) == []
    assert lua_files_for_triage(TriageProfile()) == []
    files = lua_files_for_triage(TriageProfile(silent_drop_after_sni=True))
    assert files == list(dict.fromkeys(files))
    assert len(files) == len(set(files))
    assert "dupfake.lua" in files
