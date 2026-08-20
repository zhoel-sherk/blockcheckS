"""Export best store strategies to nfqws2 configs (keenetic and raw)."""

from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

from blockchecks.engine.conf_builder import (
    DEFAULT_KEENETIC_PREFIX,
    _keep_export_strategy,
    build_keenetic_conf,
    build_raw_conf,
    write_export_bundle,
    write_user_list,
)
from blockchecks.engine.config import BLOB_DIR
from blockchecks.engine.domain_loader import DEFAULT_DOMAINS_FILE, read_domain_lines
from blockchecks.engine.paths import DEFAULT_DB_PATH, DEFAULT_OUT_DIR, expand_path
from blockchecks.engine.store import RunStateStore, open_run_store


async def collect_export_strategies(
    db: RunStateStore,
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
            if resolved := _resolve_export_strategy(cfg, row["strategy"]):
                tcp_strats.append(resolved)
    if not tcp_strats:
        covered = await db.get_best_by_coverage(limit=limit)
        if covered:
            for row in covered:
                cfg = await db.get_strategy_config(row["strategy"], "tcp")
                if resolved := _resolve_export_strategy(cfg, row["strategy"]):
                    tcp_strats.append(resolved)
        else:
            for row in await db.get_best_tcp(domain, limit=limit):
                cfg = await db.get_strategy_config(row["strategy"], "tcp")
                if resolved := _resolve_export_strategy(cfg, row["strategy"]):
                    tcp_strats.append(resolved)
            if not tcp_strats:
                working = await db.get_working_tcp(domain)
                for name in working[:limit]:
                    cfg = await db.get_strategy_config(name, "tcp")
                    if resolved := _resolve_export_strategy(cfg, name):
                        tcp_strats.append(resolved)

    udp_strats: list[str] = []
    pairs = await db.get_best_pairs(domain, limit=limit * 2)
    seen_udp: set[str] = set()
    for p in pairs:
        u = p["udp"]
        if u in seen_udp:
            continue
        seen_udp.add(u)
        cfg = await db.get_strategy_config(u, "udp")
        if resolved := _resolve_export_strategy(cfg, u):
            udp_strats.append(resolved)
        if len(udp_strats) >= limit:
            break
    if not udp_strats:
        for row in await db.get_best_udp(limit=limit):
            cfg = await db.get_strategy_config(row["strategy"], "udp")
            if resolved := _resolve_export_strategy(cfg, row["strategy"]):
                udp_strats.append(resolved)
    if not udp_strats:
        udp_strats = ["fake:blob=discord_udp:repeats=6"]

    # QUIC: best HTTP/3 strategies from state.db
    quic_strats: list[str] = []
    for row in await db.get_best_quic(domain, limit=limit):
        cfg = await db.get_strategy_config(row["strategy"], "quic")
        if resolved := _resolve_export_strategy(cfg, row["strategy"]):
            quic_strats.append(resolved)
    if not quic_strats:
        quic_strats = ["fake:blob=quic_initial:repeats=11"]
    return tcp_strats, udp_strats, quic_strats


_IP2NET_CANDIDATES = (
    "/opt/zapret2/binaries/linux-x86_64/ip2net",
    "/opt/zapret2/ip2net/ip2net",
)

_IPSET_INLINE_LIMIT = 64  # > this many IPs → write a file instead of inline


def _resolve_export_strategy(config: str | None, name: str) -> str | None:
    """Return exportable strategy text; skip DB labels when config is missing."""
    if config:
        return config if _keep_export_strategy(config) else None
    if ":" in name and _keep_export_strategy(name):
        return name
    return None


def _find_ip2net() -> str | None:
    """Return a usable ip2net binary path, or None."""
    import shutil

    for cand in _IP2NET_CANDIDATES:
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which("ip2net")


def maybe_aggregate_ips(ips: list[str]) -> list[str]:
    """Aggregate raw IPs into CIDR subnets via ip2net when available.

    Falls back to a plain dedup list when ip2net is missing. Provider-agnostic:
    only collapses the input list, never reads data_block itself.
    """
    ip2net = _find_ip2net()
    unique = list(dict.fromkeys(ips))
    if not ip2net or not unique:
        return unique
    try:
        proc = subprocess.run(
            [ip2net, "-4"],
            input="\n".join(unique) + "\n",
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode == 0:
            out = [ln.strip() for ln in proc.stdout.splitlines() if ln.strip()]
            if out:
                return out
    except (OSError, subprocess.TimeoutExpired):
        pass
    return unique


def collect_domain_ips(
    domains: list[str],
    *,
    use_all_providers: bool = True,
) -> list[str]:
    """Collect IPs for *domains* from data_block DNS cache, provider-agnostic.

    Reads dns.db of the current provider first; when *use_all_providers* is set
    (default) it also reads every other provider under data_block/providers/
    so the exported ipset works regardless of which provider populated the repo.
    Never raises; missing dns.db / unparseable records are skipped.
    """
    from blockchecks.data_block.provider import get_provider_dir, iter_provider_dirs
    from blockchecks.data_block.store import ProviderStore

    domain_set = {d.strip().rstrip(".") for d in domains if d and d.strip()}
    if not domain_set:
        return []
    provider_dirs = iter_provider_dirs()
    if not use_all_providers:
        provider_dirs = [d for d in provider_dirs if d == get_provider_dir()]
    ips: list[str] = []
    seen_domains: set[str] = set()
    for prov_dir in provider_dirs:
        store = ProviderStore(prov_dir)
        recs = store.load_dns_records_sync() or {}
        for domain, (domain_ips, _ts) in recs.items():
            key = domain.strip().rstrip(".")
            if key not in domain_set or key in seen_domains:
                continue
            seen_domains.add(key)
            ips.extend(ip.strip() for ip in domain_ips if ip and ip.strip())
    return maybe_aggregate_ips(ips)


def resolve_ipset_for_export(
    domains: list[str],
    *,
    out_dir: str,
    use_all_providers: bool = True,
) -> tuple[list[str] | None, str | None]:
    """Return (ipset_ips, ipset_file) for export_configs.

    - ≤ _IPSET_INLINE_LIMIT IPs → inline ``ipset_ips`` (no file).
    - more → write ``user.ipset`` (one IP/CIDR per line) and return
      ``ipset_file`` pointing at it.
    Both None when no IPs found.
    """
    ips = collect_domain_ips(domains, use_all_providers=use_all_providers)
    if not ips:
        return None, None
    if len(ips) <= _IPSET_INLINE_LIMIT:
        return ips, None
    ipset_path = os.path.join(out_dir, "user.ipset")
    try:
        os.makedirs(out_dir, exist_ok=True)
        with open(ipset_path, "w", encoding="utf-8") as f:
            f.write("\n".join(ips) + "\n")
    except OSError:
        return ips, None
    return None, ipset_path


async def export_configs(
    *,
    db_path: str | None = None,
    store: RunStateStore | None = None,
    domain: str = "discord.com",
    limit: int = 3,
    out_dir: str | None = None,
    isp_interface: str = "eth3",
    prefix: str = DEFAULT_KEENETIC_PREFIX,
    mode: str = "auto",
    domains_file: str | None = None,
    timestamp: str | None = None,
    common_only: bool = True,
    use_ipset: bool = False,
    use_all_providers: bool = True,
) -> dict:
    """Write keenetic + raw conf (+ user.list). Returns paths dict.

    Prefer *store* (already-open DAO) over opening a second connection via *db_path*.
    """
    own_store = False
    if store is None:
        db = open_run_store(db_path)
        await db.init()
        own_store = True
    else:
        db = store
        await db.flush()

    out_dir = str(expand_path(out_dir, default=DEFAULT_OUT_DIR))

    if domains_file and os.path.exists(domains_file):
        domains = read_domain_lines(domains_file)
    elif os.path.exists(DEFAULT_DOMAINS_FILE):
        domains = read_domain_lines(DEFAULT_DOMAINS_FILE)
    else:
        domains = [domain]

    tcp_s, udp_s, quic_s = await collect_export_strategies(
        db, domain=domain, limit=limit, domains=domains, common_only=common_only
    )

    ts = timestamp or time.strftime("%Y%m%d_%H%M%S")
    os.makedirs(out_dir, exist_ok=True)
    keenetic_path = os.path.join(out_dir, f"nfqws2_{ts}.conf")
    raw_path = os.path.join(out_dir, f"nfqws2_raw_{ts}.conf")
    user_list = os.path.join(out_dir, "user.list")

    comment = f"domain={domain} limit={limit} tcp={len(tcp_s)} udp={len(udp_s)} quic={len(quic_s)}"
    ipset_ips: list[str] | None = None
    ipset_file: str | None = None
    if use_ipset:
        ipset_ips, ipset_file = resolve_ipset_for_export(
            domains, out_dir=out_dir, use_all_providers=use_all_providers
        )
    keenetic = build_keenetic_conf(
        tcp_strategies=tcp_s,
        udp_strategies=udp_s,
        quic_strategies=quic_s,
        isp_interface=isp_interface,
        prefix=prefix,
        mode=mode,
        domains=domains,
        comment=comment,
        ipset_ips=ipset_ips,
        ipset_file=ipset_file,
    )
    raw = build_raw_conf(
        tcp_strategies=tcp_s,
        udp_strategies=udp_s,
        quic_strategies=quic_s,
        blobs_dir=BLOB_DIR,
        domains=domains,
        comment=comment,
        ipset_ips=ipset_ips,
        ipset_file=ipset_file,
    )
    write_export_bundle(
        keenetic,
        out_dir,
        tcp_strats=tcp_s,
        udp_strats=udp_s,
        quic_strats=quic_s,
        ipset_file=ipset_file,
        conf_name=f"nfqws2_{ts}.conf",
    )
    with open(raw_path, "w", encoding="utf-8") as f:
        f.write(raw)
    write_user_list(user_list, domains)

    from blockchecks.engine.paths import reclaim_sudo_ownership

    artifacts = [
        keenetic_path,
        raw_path,
        user_list,
        Path(out_dir) / "blobs",
        Path(out_dir) / "lua",
        Path(out_dir) / "lists",
    ]
    if ipset_file:
        artifacts.append(ipset_file)
    for artifact in artifacts:
        reclaim_sudo_ownership(Path(artifact))

    if own_store:
        await db.close()

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
    p.add_argument("--db", default=None, help=f"State DB (default: {DEFAULT_DB_PATH})")
    p.add_argument(
        "-d", "--domain", default="discord.com", help="Primary domain for ranking fallback"
    )
    p.add_argument("--limit", type=int, default=3)
    p.add_argument("--out-dir", default=None, help=f"Export directory (default: {DEFAULT_OUT_DIR})")
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
    p.add_argument(
        "--ipset",
        action="store_true",
        help="Add nfqws2 --ipset filter from data_block DNS cache (domains' IPs, "
        "all providers); small sets inline via --ipset-ip, large sets as user.ipset",
    )
    p.add_argument(
        "--no-all-providers",
        action="store_true",
        help="With --ipset: use only the current host provider's dns.db",
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
            use_ipset=args.ipset,
            use_all_providers=not args.no_all_providers,
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
