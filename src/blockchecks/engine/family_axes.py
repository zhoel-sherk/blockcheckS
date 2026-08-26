"""Scan constants and per-family axis tables for FamilySpec.

``family_spec`` must not import ``StandardGenerator``. Constants live here so
both the registry and ``standard.py`` can share them without a cycle.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

# Full foolings matching blockcheck2.sh def.inc FOOLINGS46_TCP
ALL_FOOLINGS_TCP = [
    "",
    "tcp_md5",
    "badsum",
    "tcp_seq=-3000",
    "tcp_seq=1000000",
    "tcp_ack=-66000:tcp_ts_up",
    "tcp_ts=-1000",
    "tcp_flags_unset=ACK",
    "tcp_flags_set=SYN",
]
ALL_FOOLINGS_UDP = ["badsum"]
# FOOLINGS6_TCP / FOOLINGS6_UDP from def.inc
ALL_FOOLINGS_IPV6 = [
    "ip6_hopbyhop",
    "ip6_hopbyhop:ip6_hopbyhop2",
    "ip6_destopt",
    "ip6_routing",
    "ip6_ah",
]
FAST_FOOLINGS_IPV6 = ["ip6_hopbyhop", "ip6_destopt"]

# Extended repeats, TTL
ALL_REPEATS = [6, 3, 1, 8, 10, 11, 12, 2, 4, 5, 7, 9, 14, 15, 20]  # 100,260 only for tcpseg
ALL_TTL = [1, 5, 7, 12, 63, 64, 127, 128, 255]  # zapret2 ttl_discover: 0 <= ttl <= 255
ALL_AUTOTTL = ["-1,3-20", "-2,5-15", "-3,7-12", "-4,3-20", "-5,5-15"]

# All split positions from blockcheck2.sh
ALL_SPLIT_POSITIONS = [
    "1",
    "2",
    "3",
    "23",
    "45",
    "midsld",
    "sniext+1",
    "sniext+4",
    "host+1",
    "1,midsld",
    "1,midsld,1220",
    "1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1",
]
# Sequence overlap values (Flowseal variants)
ALL_SEQOVL = [1, 568, 652, 664, 679, 681]

# TLS modification flags (from blockcheck2.sh standard scripts)
TLS_MODS = [
    "",  # no mod
    "rnd",  # randomize extensions
    "rnd,dupsid",  # + duplicate session ID
    "rnd,dupsid,padencap",  # + pad encapsulation
    "rnd,dupsid,sni=www.google.com",  # + SNI substitution
    "rnd,dupsid,sni=fonts.google.com",
    "rnd,dupsid,sni=ya.ru",
]

# TCP blobs plus a null TLS blob (first, so a capped --max still hits it)
ALL_BLOBS_TCP = ["0x00000000", "stun", "max_ru", "google", "4pda"]

# Foolings for fast/default scans (flags + full seq only in full)
# Geneva flag/seq fools (tcp_flags_set/unset, tcp_seq, tcp_ack) promoted to fast
FAST_FOOLINGS_TCP = [
    "tcp_ts=-1000",
    "",
    "tcp_md5",
    "badsum",
    "tcp_ack=-66000:tcp_ts_up",
    "tcp_md5:tcp_ts=-1000",
    "tcp_seq=-3000",
    "tcp_seq=1000000",
    "tcp_flags_unset=ACK",
    "tcp_flags_set=SYN",
]
FAST_REPEATS = [6, 8, 3, 11, 12, 4, 14]


def _axes(**kwargs: object) -> Mapping[str, object]:
    return MappingProxyType(kwargs)


# Insertion order is the ``strategy_types=["all"]`` expansion order.
FAMILY_AXES: Mapping[str, Mapping[str, object]] = MappingProxyType(
    {
        "fake": _axes(
            blobs=ALL_BLOBS_TCP,
            repeats=FAST_REPEATS,
            foolings=FAST_FOOLINGS_TCP,
            ttl_static=ALL_TTL,
            ttl_auto=ALL_AUTOTTL,
            tls_mods=TLS_MODS[:3],
            ack_drop=True,
            send_md5=True,
        ),
        "hostfake": _axes(
            foolings=[f for f in FAST_FOOLINGS_TCP[:5] if f],
            variants=["base", "disorder", "nofake1", "midhost=midsld", "nodrop"],
            ttl_static=ALL_TTL,
            ttl_auto=ALL_AUTOTTL,
            ack_drop=True,
            send_md5=True,
        ),
        "multisplit": _axes(
            repeats=[1, 6, 11],
            positions=ALL_SPLIT_POSITIONS,
            foolings=FAST_FOOLINGS_TCP[:4],
            seqovl=ALL_SEQOVL,
            seqovl_blobs=ALL_BLOBS_TCP,
            ttl_static=ALL_TTL,
            ttl_auto=ALL_AUTOTTL,
            padencap=True,
        ),
        "multidisorder": _axes(
            positions=["1", "2", "midsld", "method+2", "1,midsld"],
            foolings=FAST_FOOLINGS_TCP[:4],
            seqovl=[664, 681],
            seqovl_blobs=ALL_BLOBS_TCP,
            padencap=True,
        ),
        "syndata": _axes(
            blobs=["0x1603", "fake_default_tls", ""],
            tls_mods=["", "rnd,dupsid", "rnd,dupsid,sni=www.google.com"],
            plus_split=[False, True],
            plus_hostfake=True,
        ),
        "tcpseg": _axes(
            positions=["0,1", "0,midsld"],
            repeats=[1, 20, 100, 260],
            ip_id="rnd",
        ),
        "oob": _axes(urps=["b", "0", "2", "midsld"], in_range="-s1"),
        "multi_fake": _axes(
            blob_pairs=[
                ("stun", "max_ru"),
                ("max_ru", "stun"),
                ("stun", "google"),
                ("google", "stun"),
                ("max_ru", "google"),
                ("google", "max_ru"),
                ("stun", "4pda"),
                ("4pda", "stun"),
            ],
            repeat_pairs=[(6, 6), (6, 3), (8, 6), (3, 6)],
            foolings=["tcp_ts=-1000", "tcp_md5", "badsum", ""],
        ),
        "triple_fake": _axes(
            triples=[
                ("stun", "max_ru", "google"),
                ("stun", "google", "max_ru"),
                ("max_ru", "stun", "google"),
                ("google", "stun", "max_ru"),
            ],
            repeats=[6, 3],
            foolings=["tcp_ts=-1000", "badsum", ""],
        ),
        "fake_multisplit": _axes(
            blob_pairs=[
                ("stun", "max_ru"),
                ("stun", "google"),
                ("max_ru", "google"),
                ("stun", "4pda"),
                ("google", "max_ru"),
                ("4pda", "google"),
            ],
            pattern_blobs=ALL_BLOBS_TCP,
            seqovl=[664, 681, 652],
            positions=["2", "1,midsld", "midsld"],
            repeats=[6, 3, 8],
            foolings=["tcp_ts=-1000", "tcp_md5", "badsum", ""],
        ),
        "fake_multisplit_hostfake": _axes(
            blob_pairs=[
                ("google", "max_ru"),
                ("stun", "max_ru"),
                ("stun", "google"),
                ("max_ru", "google"),
            ],
            seqovl=[664, 681],
            positions=["1", "2"],
            repeats=[6, 8],
            foolings=["tcp_ts=-1000", "tcp_md5", "badsum"],
            hf_hosts=["www.google.com", "fonts.google.com"],
        ),
        "fake_multidisorder": _axes(
            blobs=ALL_BLOBS_TCP,
            positions=["1", "2", "midsld", "method+2"],
            repeats=[6, 3, 8, 11],
            foolings=["tcp_ts=-1000", "tcp_md5", "badsum", ""],
        ),
        "fakedsplit": _axes(
            positions=["1", "midsld", "sniext+1", "method+2"],
            pattern_blobs=ALL_BLOBS_TCP,
            foolings=[f for f in FAST_FOOLINGS_TCP[:4] if f],
            repeats=[6, 11],
            ack_drop=True,
            send_md5=True,
        ),
        "fakeddisorder": _axes(
            positions=["1", "midsld", "method+2"],
            pattern_blobs=ALL_BLOBS_TCP,
            foolings=[f for f in FAST_FOOLINGS_TCP[:4] if f],
            repeats=[6, 11],
            ack_drop=True,
            send_md5=True,
        ),
        "fake_fakedsplit": _axes(
            blobs=ALL_BLOBS_TCP,
            positions=["1", "midsld", "method+2"],
            pattern_blobs=ALL_BLOBS_TCP,
            repeats=[6, 3, 8],
            foolings=["tcp_ts=-1000", "tcp_md5", "badsum"],
        ),
        "tcp_ipfrag": _axes(
            positions=[8, 16, 24, 32, 40, 48, 64],
            repeats=[6, 11, 4],
            combo_blobs=["", "stun", "google"],
            disorder=[False, True],
            ipfrag_next=[None, 255],
        ),
        "fake_hostfake": _axes(
            blobs=ALL_BLOBS_TCP,
            repeats=[6, 3, 8, 11, 2],
            foolings=["tcp_ts=-1000", "tcp_md5", "badsum"],
            hf_variants=["base", "disorder_after"],
            ack_drop=True,
            send_md5=True,
        ),
        "rst_fake": _axes(
            mods=[
                "rst:badsum",
                "rst:ip_ttl=10",
                "rst:ip_ttl=1",
                "rst:tcp_md5",
                "rst:rstack:badsum",
                "rst:rstack:ip_ttl=10",
                "rst:rstack:ip_ttl=1",
                "rst:badsum:tcp_md5",
            ],
            flag_fakes=[
                "send:tcp_flags_set=FIN,RST,ACK,PSH,URG,ECE:badsum",
                "send:tcp_flags_set=FIN,RST,ECE,ACK,CWR:ip_ttl=10",
                "send:tcp_flags_set=FIN,RST,ACK,PSH,URG:tcp_md5",
                "send:tcp_flags_set=FIN:tcp_md5",
            ],
        ),
        # syn|synack omitted — '|' breaks nfqws2 conf splitter
        "synack": _axes(
            modes=["synack", "synack", "acksyn"],
            foolings=[""],
        ),
        "wssize": _axes(
            sizes=["wssize:wsize=1:scale=6"],
            combos=[False, True],
        ),
        "geneva_fool": _axes(
            fools=[
                "fool=bs_dataofs:badsum",
                "fool=bs_dataofs:ip_ttl=10",
                "fool=bs_iplen:len=64",
                "fool=bs_iplen:len=78",
                "fool=bs_corrupt_load",
                "fool=bs_corrupt_load:badsum",
                "fool=bs_corrupt_load:ip_ttl=8",
                "fool=bs_corrupt_wscale",
                "fool=bs_corrupt_uto",
            ],
            repeats=[1, 2],
        ),
        "udp_discord": _axes(
            blobs=["discord_udp", "stun"],
            repeats=[6, 12, 3, 2],
            ttl_static=[5],
            ttl_auto=["-2,3-20"],
        ),
        "udp_quic": _axes(
            port_ranges=["443"],
            blobs=[
                "quic_google",
                "quic_dbank",
                "quic_gv_kyber_1",
                "quic_gv_kyber_2",
            ],
            repeats=[1, 2, 5, 6, 10, 11, 20],
        ),
        "udp_game": _axes(
            port_ranges=["1024-65535"],
            blobs=["quic_initial_dbankcloud_ru", "game_udp"],
            repeats=[10, 12, 14],
            out_range=[None, "n1-<n3", "n1-<n4", "n1-<n5"],
        ),
        "udp_multiblob": _axes(
            profiles=[
                ("stun", "discord_udp"),
                ("quic_dbank", "discord_udp"),
                ("game_udp", "discord_udp"),
            ],
            repeats=[6, 10, 12],
        ),
        "http_simple": _axes(
            variants=[
                "http_hostcase",
                "http_methodeol",
                "http_hostcase:spell=hoSt",
                "http_domcase",
                "http_unixeol",
            ],
        ),
        "http_fake": _axes(
            blobs=["fake_default_http", "0x00000000"],
            repeats=FAST_REPEATS[:4],
            foolings=FAST_FOOLINGS_TCP[:4],
        ),
        "http_tls_dual": _axes(
            http_blobs=["fake_default_http"],
            repeats=[6, 3],
            foolings=["tcp_ts=-1000", "badsum", ""],
        ),
        "quic_fake": _axes(
            blobs=["fake_default_quic", "quic_initial", "quic_google", "quic_vk"],
            repeats=[1, 2, 5, 6, 10, 11, 20],
            foolings=["", "badsum"],
            ip6_send_drop=True,
        ),
        "quic_gv": _axes(
            blobs=["quic_gv_kyber_1", "quic_gv_kyber_2", "quic_google"],
            repeats=[1, 2, 5, 6, 11],
        ),
        "quic_ipfrag": _axes(
            positions=[8, 16, 24, 32, 40, 48, 64],
            repeats=[6, 11, 4],
            disorder=[False, True],
            ipfrag_next=[None, 255],
        ),
    }
)
