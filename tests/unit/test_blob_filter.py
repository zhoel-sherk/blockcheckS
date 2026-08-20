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
