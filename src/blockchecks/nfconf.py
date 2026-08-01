"""Export best StateDB strategies to nfqws2 configs (keenetic + raw)."""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

from blockchecks.engine.conf_builder import (
    DEFAULT_KEENETIC_PREFIX,
    build_keenetic_conf,
    build_raw_conf,
    write_user_list,
)
from blockchecks.engine.config import BLOB_DIR, PROJECT_DIR
from blockchecks.engine.db_logger import StateDB


def _load_domains(path: str) -> list[str]:
    domains = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                domains.append(line)
    return domains


async def collect_export_strategies(
    db: StateDB,
    *,
    domain: str,
    limit: int,
    domains: list[str] | None = None,
    common_only: bool = True,
) -> tuple[list[str], list[str], list[str]]:
    """Pick TCP/UDP/QUIC strategy strings for export."""
    tcp_strats: list[str] = []
    if common_only and domains and len(domains) > 1:
        for row in await db.get_common_tcp(domains, limit=limit):
            cfg = await db.get_strategy_config(row["strategy"], "tcp")
            tcp_strats.append(cfg or row["strategy"])
    if not tcp_strats:
        covered = await db.get_best_by_coverage(limit=limit)
        if covered:
            for row in covered:
                cfg = await db.get_strategy_config(row["strategy"], "tcp")
                tcp_strats.append(cfg or row["strategy"])
        else:
            for row in await db.get_best_tcp(domain, limit=limit):
                cfg = await db.get_strategy_config(row["strategy"], "tcp")
                tcp_strats.append(cfg or row["strategy"])
        if not tcp_strats:
            working = await db.get_working_tcp(domain)
            for name in working[:limit]:
                cfg = await db.get_strategy_config(name, "tcp")
                tcp_strats.append(cfg or name)

    udp_strats: list[str] = []
    pairs = await db.get_best_pairs(domain, limit=limit * 2)
    seen_udp: set[str] = set()
    for p in pairs:
        u = p["udp"]
        if u in seen_udp:
            continue
        seen_udp.add(u)
        cfg = await db.get_strategy_config(u, "udp")
        udp_strats.append(cfg or u)
        if len(udp_strats) >= limit:
            break
    if not udp_strats:
        for row in await db.get_best_udp(limit=limit):
            cfg = await db.get_strategy_config(row["strategy"], "udp")
            udp_strats.append(cfg or row["strategy"])
    if not udp_strats:
        udp_strats = ["fake:blob=discord_udp:repeats=6"]

    # QUIC: best HTTP/3 strategies from state.db
    quic_strats: list[str] = []
    for row in await db.get_best_quic(domain, limit=limit):
        cfg = await db.get_strategy_config(row["strategy"], "quic")
        quic_strats.append(cfg or row["strategy"])
    if not quic_strats:
        quic_strats = ["fake:blob=quic_initial:repeats=11"]
    return tcp_strats, udp_strats, quic_strats


async def export_configs(
    *,
    db_path: str = "state.db",
    domain: str = "discord.com",
    limit: int = 3,
    out_dir: str = "output",
    isp_interface: str = "eth3",
    prefix: str = DEFAULT_KEENETIC_PREFIX,
    mode: str = "auto",
    domains_file: str | None = None,
    timestamp: str | None = None,
    common_only: bool = True,
) -> dict:
    """Write keenetic + raw conf (+ user.list). Returns paths dict."""
    db = StateDB(db_path)
    await db.init()

    if domains_file and os.path.exists(domains_file):
        domains = _load_domains(domains_file)
    else:
        cov = os.path.join(PROJECT_DIR, "presets", "domains", "coverage.txt")
        domains = _load_domains(cov) if os.path.exists(cov) else [domain]

    tcp_s, udp_s, quic_s = await collect_export_strategies(
        db, domain=domain, limit=limit, domains=domains, common_only=common_only
    )

    ts = timestamp or time.strftime("%Y%m%d_%H%M%S")
    os.makedirs(out_dir, exist_ok=True)
    keenetic_path = os.path.join(out_dir, f"nfqws2_{ts}.conf")
    raw_path = os.path.join(out_dir, f"nfqws2_raw_{ts}.conf")
    user_list = os.path.join(out_dir, "user.list")

    comment = f"domain={domain} limit={limit} tcp={len(tcp_s)} udp={len(udp_s)} quic={len(quic_s)}"
    keenetic = build_keenetic_conf(
        tcp_strategies=tcp_s,
        udp_strategies=udp_s,
        quic_strategies=quic_s,
        isp_interface=isp_interface,
        prefix=prefix,
        mode=mode,
        domains=domains,
        comment=comment,
    )
    raw = build_raw_conf(
        tcp_strategies=tcp_s,
        udp_strategies=udp_s,
        quic_strategies=quic_s,
        blobs_dir=BLOB_DIR
        if not os.path.isdir(os.path.join(prefix, "blobs"))
        else os.path.join(prefix, "blobs"),
        domains=domains,
        comment=comment,
    )
    with open(keenetic_path, "w", encoding="utf-8") as f:
        f.write(keenetic)
    with open(raw_path, "w", encoding="utf-8") as f:
        f.write(raw)
    write_user_list(user_list, domains)

    return {
        "keenetic": keenetic_path,
        "raw": raw_path,
        "user_list": user_list,
        "tcp": tcp_s,
        "udp": udp_s,
        "quic": quic_s,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Export best strategies from state.db to nfqws2 conf files"
    )
    p.add_argument("--db", default="state.db")
    p.add_argument(
        "-d", "--domain", default="discord.com", help="Primary domain for ranking fallback"
    )
    p.add_argument("--limit", type=int, default=3)
    p.add_argument("--out-dir", default="output")
    p.add_argument("--isp-interface", default="eth3")
    p.add_argument(
        "--prefix",
        default=DEFAULT_KEENETIC_PREFIX,
        help="Keenetic install prefix for lua/blobs paths",
    )
    p.add_argument("--mode", default="auto", choices=["auto", "list", "all"])
    p.add_argument(
        "--domains-file",
        default=None,
        help="Domain list for user.list / hostlist (default: coverage.txt)",
    )
    p.add_argument(
        "--no-common-only",
        action="store_true",
        help="Export best per-domain strategies instead of COMMON intersection",
    )
    args = p.parse_args(argv)

    result = asyncio.run(
        export_configs(
            db_path=args.db,
            domain=args.domain,
            limit=args.limit,
            out_dir=args.out_dir,
            isp_interface=args.isp_interface,
            prefix=args.prefix,
            mode=args.mode,
            domains_file=args.domains_file,
            common_only=not args.no_common_only,
        )
    )
    print(f"  keenetic: {result['keenetic']}")
    print(f"  raw:      {result['raw']}")
    print(f"  user.list:{result['user_list']}")
    print(f"  TCP ({len(result['tcp'])}):")
    for s in result["tcp"]:
        print(f"    - {s[:90]}")
    print(f"  UDP ({len(result['udp'])}):")
    for s in result["udp"]:
        print(f"    - {s[:90]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
