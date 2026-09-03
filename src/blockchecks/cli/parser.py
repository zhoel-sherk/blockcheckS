"""argparse definitions and command dispatch."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import subprocess
import sys
from collections.abc import Callable

from blockchecks.terminal import init_terminal

init_terminal()

log = logging.getLogger(__name__)

from blockchecks.cli.commands.pair import cmd_pair
from blockchecks.cli.commands.tcp import cmd_tcp
from blockchecks.cli.commands.udp import cmd_udp
from blockchecks.cli.presets import list_presets
from blockchecks.engine.config import (
    CONFIGS_DIR,
    DEFAULT_BRIDGE_BATCH,
    DEFAULT_VOICE_IP,
    DEFAULT_VOICE_PORT,
    effective_default_pool_size,
)
from blockchecks.engine.paths import DEFAULT_DB_PATH, DEFAULT_OUT_DIR
from blockchecks.engine.settle_profile import DEFAULT_PROFILE_PATH

_BOOL = argparse.BooleanOptionalAction

_QUARANTINE_MIN_LO = 1
_QUARANTINE_MIN_HI = 10_000


def _quarantine_bound(value: str) -> int:
    """argparse type: integer in 1..10000."""
    try:
        n = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if n < _QUARANTINE_MIN_LO or n > _QUARANTINE_MIN_HI:
        raise argparse.ArgumentTypeError(
            f"must be {_QUARANTINE_MIN_LO}..{_QUARANTINE_MIN_HI}"
        )
    return n


# Positive BooleanOptionalAction dest → legacy ``no_*`` handler field (inverted).
_LEGACY_NO_FROM_POSITIVE: tuple[tuple[str, str], ...] = (
    ("adaptive", "no_adaptive"),
    ("preflight", "no_preflight"),
    ("wssize", "no_wssize"),
    ("http", "no_http"),
    ("quic", "no_quic"),
    ("voice", "no_voice"),
    ("secure_dns", "no_secure_dns"),
    ("auto_pin", "no_auto_pin"),
    ("family_gates", "no_family_gates"),
    ("adaptive_weights", "no_adaptive_weights"),
    ("fetch_deps", "no_fetch_deps"),
    ("common_only", "no_common_only"),
    ("quarantine", "no_quarantine"),
    ("export_on_stop", "no_export_on_stop"),
    ("hostlist", "no_hostlist"),
    ("use_settle_profile", "no_settle_profile"),
)


def namespace_compat(ns: argparse.Namespace) -> None:
    """Map positive BooleanOptionalAction fields to legacy ``no_*`` dest names."""
    for positive, legacy in _LEGACY_NO_FROM_POSITIVE:
        if hasattr(ns, positive):
            setattr(ns, legacy, not bool(getattr(ns, positive)))


def iter_subparsers(root: argparse.ArgumentParser | None = None) -> dict[str, argparse.ArgumentParser]:
    """Return subcommand name → subparser (public ``command`` dest, no private classes)."""
    root = root or build_parser()
    for action in root._actions:
        if action.dest != "command" or not getattr(action, "choices", None):
            continue
        return dict(action.choices)
    return {}


def _default_isp_interface() -> str:
    """Router WAN iface for exported conf; empty = omit unless user sets env."""
    return os.environ.get("BLOCKCHECKS_ISP_IFACE") or os.environ.get("ISP_INTERFACE") or ""


def add_store_args(parser: argparse.ArgumentParser, *, include_out_dir: bool = True) -> None:
    """Shared --db / --out-dir (XDG defaults applied post-parse)."""
    parser.add_argument(
        "--db",
        default=None,
        help=f"State DB (default: {DEFAULT_DB_PATH})",
    )
    if include_out_dir:
        parser.add_argument(
            "--out-dir",
            default=None,
            help=f"Export nfconf on finish (default for full: {DEFAULT_OUT_DIR})",
        )


def add_adaptive_args(parser: argparse.ArgumentParser) -> None:
    """AQ flags (full + scan/pair)."""
    g = parser.add_argument_group("adaptive queue (AQ)")
    g.add_argument(
        "--adaptive",
        action=_BOOL,
        default=True,
        help="Adaptive priority queue (default: ON; --no-adaptive for sequential matrix)",
    )
    g.add_argument(
        "--fan-out",
        action="store_true",
        help="Alias: raise --curl-parallel to at least 4 (one strategy × N domains)",
    )
    g.add_argument(
        "--adaptive-epsilon",
        type=float,
        default=0.1,
        metavar="E",
        help="epsilon-greedy exploration rate (default 0.1)",
    )
    g.add_argument(
        "--adaptive-weights",
        action=_BOOL,
        default=True,
        help="Load/save scan_weights in state.db (default: ON)",
    )


def add_profile_args(parser: argparse.ArgumentParser) -> None:
    """Register --profile smoke|fast|20h."""
    parser.add_argument(
        "--profile",
        choices=["smoke", "fast", "20h"],
        default=None,
        help="Predefined flag bundle (smoke=quick 20-item, fast=100-item, 20h=long-term series)",
    )


def add_time_limit_args(parser: argparse.ArgumentParser, *, include_export: bool = False) -> None:
    """Register --max-timeh / --max-timem."""
    from blockchecks.engine.run_deadline import add_time_limit_args as _add

    _add(parser, include_export=include_export)


def add_curl_fanout_args(parser: argparse.ArgumentParser) -> None:
    from blockchecks.engine.config import DEFAULT_CURL_PARALLEL, MAX_CURL_PARALLEL

    g = parser.add_argument_group("curl fan-out (B2)")
    g.add_argument(
        "--curl-parallel",
        type=int,
        default=DEFAULT_CURL_PARALLEL,
        metavar="N",
        help=f"Domains per nfqws2 session (1=off, max {MAX_CURL_PARALLEL})",
    )


def add_curl_repeats_args(
    parser: argparse.ArgumentParser, *, include_quic_timeout: bool = False
) -> None:
    """blockcheck2-style curl repeats per strategy."""
    g = parser.add_argument_group("curl repeats")
    g.add_argument(
        "--repeats",
        type=int,
        default=1,
        metavar="N",
        help="curl attempts per strategy (blockcheck2 REPEATS, 1-10, default 1)",
    )
    g.add_argument(
        "--parallel-repeats",
        action="store_true",
        help="Run repeats in parallel (blockcheck2 PARALLEL / GP repeat_parallel)",
    )
    g.add_argument(
        "--repeats-mode",
        choices=["fast", "stable"],
        default="fast",
        help="fast=stop on first PASS; stable=run all N like blockcheck2 (PASS if any)",
    )
    if include_quic_timeout:
        g.add_argument(
            "--quic-timeout",
            type=float,
            default=8.0,
            help="HTTP/3 curl timeout (default 8s)",
        )


def add_lua_bridge_args(parser: argparse.ArgumentParser) -> None:
    """Campaign TCP uses lua_bridge (scan_pick IPC). ``--classic`` is a no-op map."""
    g = parser.add_argument_group("lua bridge (scan_pick IPC)")
    g.add_argument(
        "--classic",
        action="store_true",
        help="Deprecated: ignored; campaign TCP always uses lua_bridge",
    )
    g.add_argument(
        "--probe-backend",
        choices=("classic", "lua_bridge"),
        default=None,
        metavar="{classic,lua_bridge}",
        help="Deprecated: classic is mapped to lua_bridge",
    )
    g.add_argument(
        "--lua-bridge",
        action="store_true",
        help="Deprecated no-op (lua_bridge is the only campaign TCP backend)",
    )
    g.add_argument(
        "--bridge-batch",
        type=int,
        default=DEFAULT_BRIDGE_BATCH,
        metavar="N",
        help=f"Strategies per bridge conf window (default {DEFAULT_BRIDGE_BATCH})",
    )
    g.add_argument(
        "--lua-extra",
        nargs="*",
        default=[],
        metavar="PATH",
        help="Extra --lua-init=@ paths after zapret-auto (or BLOCKCHECKS_LUA_EXTRA)",
    )


def add_domain_filter_args(parser: argparse.ArgumentParser) -> None:
    """Denylist filter for domain presets."""
    g = parser.add_argument_group("domain filter")
    g.add_argument(
        "--allow-unsafe-domains",
        action="store_true",
        help="Do not apply presets/domains/denylist.txt to --preset loads",
    )


def add_protocol_phase_args(parser: argparse.ArgumentParser) -> None:
    """GP leftover aliases: ``--http-off``/``--http3-off`` share dests with ``--no-*``."""
    g = parser.add_argument_group("protocol phases (GP aliases)")
    g.add_argument(
        "--http-off",
        dest="http",
        action="store_false",
        default=argparse.SUPPRESS,
        help="Alias of --no-http",
    )
    g.add_argument(
        "--http3-off",
        dest="quic",
        action="store_false",
        default=argparse.SUPPRESS,
        help="Alias of --no-quic",
    )
    g.add_argument(
        "--tls12-off",
        action="store_true",
        help="Skip TCP TLS phase when --protocol tls12",
    )
    g.add_argument(
        "--tls13-off",
        action="store_true",
        help="Skip TCP TLS phase when --protocol tls13",
    )


def add_family_gate_args(parser: argparse.ArgumentParser) -> None:
    """need_* family gating between standard strategy families."""
    g = parser.add_argument_group("family gates")
    g.add_argument(
        "--family-gates",
        action=_BOOL,
        default=True,
        help="need_* gating between standard families (default: ON for single/fast)",
    )


def add_ip_pin_args(parser: argparse.ArgumentParser) -> None:
    """IP pin file and auto-pin flags (scan/pair)."""
    g = parser.add_argument_group("IP pinning")
    g.add_argument(
        "--fixed-ip",
        default=None,
        help=(
            "Hosts-analog IP pin file (one 'domain IP' per line, # comments). "
            "Pinned IPs override DoH order; auto-refreshed at startup. "
            "Default: $BLOCKCHECKS_FIXED_IP"
        ),
    )
    g.add_argument(
        "--auto-pin",
        action=_BOOL,
        default=True,
        help="Auto-probe pinned/DoH IPs at startup (default: ON)",
    )


def add_secure_dns_args(
    parser: argparse.ArgumentParser,
    *,
    include_preflight: bool = False,
    include_preflight_toggle: bool = True,
    include_data_block_sync: bool = True,
) -> None:
    """DoH / UDP DNS flags; optional preflight group."""
    g = parser.add_argument_group("secure DNS")
    g.add_argument(
        "--secure-dns",
        action=_BOOL,
        default=True,
        help="DoH pre-resolve (default: ON)",
    )
    g.add_argument("--doh-server", default=None, help="Fixed DoH server URL")
    g.add_argument("--skip-dns-audit", action="store_true", help="Skip UDP vs DoH audit table")
    g.add_argument(
        "--allow-dns-hijack",
        action="store_true",
        help="Continue even on sinkhole/bogon DNS (UDP≠DoH is a warning; DoH+auto-pin is the mitigation)",
    )
    if include_data_block_sync:
        g.add_argument(
            "--data-block-sync",
            action="store_true",
            help="Export XDG providers into data_block/.git (commit+push); warning if missing",
        )
    if not include_preflight:
        return
    g = parser.add_argument_group("preflight")
    if include_preflight_toggle:
        g.add_argument(
            "--preflight",
            action=_BOOL,
            default=True,
            help="Run preflight checks (prolog, IP-block, port-block, baseline; default: ON)",
        )
    g.add_argument(
        "--quick",
        action="store_true",
        help="Quick preflight: run prolog only, skip deep baseline/IP-block/port-block probes",
    )
    g.add_argument(
        "--dpi-diag",
        action="store_true",
        help="Extra DPI diagnostics (SNI whitelist, FAT/l4-25, Siberian, CIDR-WL, AS/org DNS)",
    )
    g.add_argument("--skip-ip-block", action="store_true", help="Skip IP-block cross-test")
    g.add_argument(
        "--unblocked-dom",
        default=None,
        help="Reference unblocked domain (default: ripe.net)",
    )
    g.add_argument("--skip-baseline", action="store_true", help="Skip unblocked baseline check")
    g.add_argument("--skip-port-block", action="store_true", help="Skip TCP port probes")
    g.add_argument("--skip-prolog", action="store_true", help="Skip no-bypass prolog curl")
    g.add_argument(
        "--prolog-content",
        action="store_true",
        help="Validate HTTP body content during prolog (stricter than TLS-only)",
    )
    g.add_argument(
        "--force",
        action="store_true",
        help="Run strategy tests even if prolog passes",
    )
    g.add_argument("--skip-nfqws2-check", action="store_true", help="Skip host nfqws2 detection")
    g.add_argument(
        "--abort-on-nfqws2",
        action="store_true",
        help="Abort if nfqws2 already running on host",
    )


def add_system_deps_args(parser: argparse.ArgumentParser) -> None:
    """Host tool / zapret2 vendor fetch flags (1.0.1)."""
    g = parser.add_argument_group("system dependencies")
    g.add_argument(
        "--fetch-deps",
        action=_BOOL,
        default=True,
        help="Auto-download zapret2/nfqws2 when missing (default: ON)",
    )
    g.add_argument(
        "--offline",
        action="store_true",
        help="Never contact the network for dependency fetch",
    )
    g.add_argument(
        "--skip-deps-check",
        action="store_true",
        help="Skip verify_system_dependencies (advanced)",
    )


def add_campaign_args(parser: argparse.ArgumentParser, *, mode: str = "full") -> None:
    """Unified argument builder for scan, pair, and full matrix campaigns.

    Synchronizes flag names and default values across all campaign commands.
    """
    if mode in ("scan", "pair"):
        parser.add_argument(
            "-d",
            "--domain",
            action="append",
            default=None,
            help="Target domain (repeatable; scan/pair test the whole set)",
        )
        parser.add_argument(
            "--domains-file",
            default=None,
            help="Path to domain list file (one FQDN per line; wins over -d/--preset)",
        )
    else:  # full
        parser.add_argument("-d", "--domain", help="Single domain to test")
        parser.add_argument("--domains-file", help="Path to domain list file")

    parser.add_argument(
        "--preset", default=None, help="Domain preset name (presets/domains/{name}.txt)"
    )
    parser.add_argument(
        "-M", "--strategy-preset", default=None, help="Strategy preset (presets/strategies/{name})"
    )
    parser.add_argument(
        "--generate",
        nargs="?",
        const="custom,configs",
        default="",
        help="Use matrix generator (sources: custom,configs,fake,faked,...)",
    )
    parser.add_argument(
        "--tcp-sources",
        default="standard,custom,configs,flowseal"
        if mode == "full"
        else ("custom,configs" if mode == "pair" else ""),
        help="TCP strategy sources (comma-separated)",
    )

    if mode in ("pair", "full"):
        parser.add_argument(
            "--udp-sources",
            default="custom,standard_udp",
            help="UDP sources: custom,standard_udp,configs,flowseal,game",
        )

    if mode == "full":
        parser.add_argument("--quic-sources", default="standard_quic")
        parser.add_argument("--http-sources", default="custom,standard_http")
        parser.add_argument(
            "--http",
            action=_BOOL,
            default=True,
            help="HTTP :80 strategy phase (default: ON)",
        )
        parser.add_argument(
            "--quic",
            action=_BOOL,
            default=True,
            help="QUIC strategy phase (default: ON)",
        )
        parser.add_argument(
            "--voice",
            action=_BOOL,
            default=True,
            help="UDP voice phase (default: ON)",
        )
        parser.add_argument(
            "--tcp-only", action="store_true", help="Skip UDP, QUIC, and HTTP phases"
        )

    parser.add_argument(
        "--no-ech",
        "--disable-ech",
        dest="disable_ech",
        action="store_true",
        help="Disable Encrypted Client Hello (force plaintext SNI)",
    )
    parser.add_argument(
        "--wssize",
        action=_BOOL,
        default=True,
        help="wssize fallback on TLS 1.2 FAIL (default: ON; --no-wssize to skip)",
    )
    if mode in ("scan", "pair"):
        parser.add_argument(
            "--list-presets", action="store_true", help="List available presets and exit"
        )

    parser.add_argument(
        "--protocol",
        default="tls12",
        choices=["tls12", "tls13"],
        help="TLS protocol version to test",
    )
    parser.add_argument(
        "--scan-level",
        default="full" if mode == "full" else "fast",
        choices=["single", "fast", "full"],
        help="Scan thoroughness level",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=effective_default_pool_size(),
        help="Parallel netns pool size",
    )
    parser.add_argument(
        "--max",
        type=int,
        default=0 if mode == "full" else 100,
        help="Cap strategy matrix count (0=uncapped)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Curl probe timeout in seconds (default: 3.0)",
    )
    g = parser.add_argument_group("domain quarantine")
    g.add_argument(
        "--quarantine",
        action=_BOOL,
        default=True,
        help="Quarantine domains that never PASS (default: ON)",
    )
    g.add_argument(
        "--quarantine-min",
        type=_quarantine_bound,
        default=300,
        help="DPI FAILs (0 PASS) on a domain before quarantine (1–10000, default: 300)",
    )
    g.add_argument(
        "--dns-resolve-quarantine-min",
        dest="dns_resolve_quarantine_min",
        type=_quarantine_bound,
        default=50,
        help="dns_resolve FAILs before quarantine (1–10000, default: 50)",
    )
    g.add_argument(
        "--quarantine-auto-denylist",
        action="store_true",
        default=False,
        help="Append quarantined domains to presets/domains/denylist.txt",
    )
    if mode in ("pair", "full"):
        parser.add_argument(
            "--udp-timeout",
            type=float,
            default=3.0,
            help="UDP voice probe timeout in seconds (default: 3.0)",
        )
    parser.add_argument("--user-matrix", default="", help="Path to custom strategy list file")
    parser.add_argument(
        "--triage-from",
        default="",
        metavar="PATH",
        help="Load TriageProfile from triage.toml (overrides provider file after preflight)",
    )

    add_store_args(parser)
    parser.add_argument(
        "--db-batch",
        type=int,
        default=500,
        help="Buffer N DB writes before flush (default 500)",
    )
    parser.add_argument(
        "--resume", action="store_true", help="Resume prior run: skip domain×strategy in DB"
    )
    parser.add_argument(
        "--reprobe-failed",
        type=int,
        default=0,
        metavar="N",
        help=(
            "With --resume: re-queue infra FAIL pairs until N infra failures "
            "per pair; also skip DPI-shaped FAIL (0=off, only PASS/THROTTLED skipped)"
        ),
    )
    parser.add_argument(
        "--migrate-cwd-db",
        action="store_true",
        help="Copy ./state.db into XDG state.db if missing (or BLOCKCHECKS_MIGRATE_CWD_DB=1)",
    )

    add_secure_dns_args(parser, include_preflight=True)
    add_ip_pin_args(parser)
    add_system_deps_args(parser)
    add_curl_repeats_args(parser, include_quic_timeout=(mode == "full"))
    add_family_gate_args(parser)
    add_domain_filter_args(parser)
    add_adaptive_args(parser)
    add_curl_fanout_args(parser)
    add_profile_args(parser)
    add_lua_bridge_args(parser)
    add_time_limit_args(parser, include_export=(mode != "scan"))

    if mode != "scan":
        parser.add_argument(
            "--export-limit", type=int, default=3, help="Max strategies to export per category"
        )
        parser.add_argument(
            "--common-only",
            action=_BOOL,
            default=True,
            help="Export COMMON intersection (default: ON; --no-common-only for per-domain)",
        )

    if mode in ("pair", "full"):
        parser.add_argument("--ip", default=DEFAULT_VOICE_IP, help="Discord voice server IP")
        parser.add_argument(
            "--port", type=int, default=DEFAULT_VOICE_PORT, help="Discord voice server UDP port"
        )
        parser.add_argument(
            "--discover-dns",
            nargs="?",
            const=5,
            type=int,
            default=5 if mode == "full" else None,
            help="DNS + Maks-gaming IP list + dual UDP probe (no VPN)",
        )
        parser.add_argument(
            "--discover-dns-no-bootstrap",
            action="store_true",
            help="Skip nfqws2 UDP bootstrap during --discover-dns",
        )
        parser.add_argument(
            "--auto-discover",
            nargs="?",
            const=5,
            type=int,
            default=None,
            help="DNS + gateway discover via sing-box (VPN path)",
        )
        parser.add_argument(
            "--voice-region",
            default=os.environ.get("BLOCKCHECKS_VOICE_REGION", "finland"),
            metavar="REGION",
            help="Discord voice region for endpoint discovery",
        )
        parser.add_argument(
            "--voice-burst",
            action="store_true",
            help="Also probe with a >16KB UDP media burst (voice-traffic heuristic)",
        )
        parser.add_argument(
            "--full-voice", action="store_true", help="Complete Discord voice gateway handshake"
        )
        parser.add_argument(
            "--udp-bypass", action="store_true", help="Probe UDP through bypass path"
        )

    if mode == "pair":
        parser.add_argument(
            "--tcp-only", action="store_true", help="Skip UDP pair testing (TCP scan only)"
        )
        parser.add_argument("-c", "--config", help="Single TCP .conf file")
        parser.add_argument("-u", "--udp-config", help="Single UDP .conf file")
        parser.add_argument(
            "-C", "--configs-dir", default=CONFIGS_DIR, help="Directory of TCP configs"
        )

    if mode == "full":
        parser.add_argument(
            "--pair-max", type=int, default=200, help="Cap TCP×UDP pair combinations"
        )
        parser.add_argument(
            "--isp-interface",
            default=_default_isp_interface(),
            help="Router WAN interface for exported conf (env: BLOCKCHECKS_ISP_IFACE / ISP_INTERFACE)",
        )
        parser.add_argument("--prefix", default="/opt/etc/nfqws2", help="Router nfqws2 prefix path")
        parser.add_argument("--mode", default="auto", choices=["auto", "list", "all"])
        add_protocol_phase_args(parser)
        g = parser.add_argument_group("settle profile (B11)")
        g.add_argument(
            "--settle-profile",
            default=None,
            metavar="PATH",
            help="Load settle/curl timings from bench-settle JSON",
        )
        g.add_argument(
            "--use-settle-profile",
            action=_BOOL,
            default=True,
            help="Use settle profile when logs/settle_profile.json exists (default: ON)",
        )
        g.add_argument(
            "--no-settle-profile",
            dest="use_settle_profile",
            action="store_false",
            default=argparse.SUPPRESS,
            help="Disable auto-load of settle profile (alias of --no-use-settle-profile)",
        )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Python DEBUG logs + nfqws2 --debug=1 (toggle at runtime with SIGUSR1)",
    )
    parser.add_argument(
        "--nfqws2-debug",
        nargs="?",
        const="1",
        default=None,
        help="nfqws2 --debug: 1=logs/file, syslog, or @path/path",
    )


def ensure_system_deps_or_exit(args) -> int:
    """Live-run gates, then optional zapret/nfqws2 deps check. Returns 0 or 2."""
    warn_live_cli_flags(args)
    if rc := require_passwordless_sudo():
        return rc
    if getattr(args, "skip_deps_check", False):
        return 0
    from blockchecks.engine.system_deps import verify_system_dependencies

    fetch = not getattr(args, "no_fetch_deps", False)
    offline = bool(getattr(args, "offline", False))
    report = verify_system_dependencies(fetch=fetch, offline=offline)
    report.print_report()
    if not report.ok:
        return 2
    return 0


def warn_live_cli_flags(args) -> None:
    """Human-usage warnings: ignored -d/--preset, deprecated --classic."""
    domains_file = getattr(args, "domains_file", None)
    raw_domain = getattr(args, "domain", None)
    if isinstance(raw_domain, (list, tuple)):
        domain = ",".join(str(d) for d in raw_domain if str(d).strip())
    else:
        domain = str(raw_domain or "").strip()
    preset = getattr(args, "preset", None)
    if domains_file and domain:
        log.warning(
            "--domains-file=%s overrides -d/--domain=%s (file wins)",
            domains_file,
            domain,
        )
    if domains_file and preset:
        log.warning(
            "--domains-file=%s overrides --preset=%s (file wins)",
            domains_file,
            preset,
        )
    from blockchecks.engine.config import resolve_probe_backend

    resolve_probe_backend(args)


def require_passwordless_sudo() -> int:
    """Exit 2 before DNS if not root and ``sudo -n`` fails. Not skipped by --skip-deps-check."""
    if os.geteuid() == 0:
        return 0
    try:
        r = subprocess.run(
            ["sudo", "-n", "true"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        log.error(
            "ERROR: live runs need passwordless sudo (`sudo -n`); %s",
            exc,
        )
        return 2
    if r.returncode != 0:
        log.error(
            "ERROR: live runs need passwordless sudo (`sudo -n` / NOPASSWD). "
            "Do not wait for DNS: netns/nfqws2 cannot start. rc=%s %s",
            r.returncode,
            (r.stderr or r.stdout or "").strip()[:200],
        )
        return 2
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="blockcheckS - lightspeed DPI strategy tester")
    sub = parser.add_subparsers(dest="command", help="Commands")

    sub.add_parser(
        "full",
        help="Mass strategy×coverage test + nfqws2 conf export (see: bs full -h)",
    )

    stop = sub.add_parser(
        "stop",
        help="Gracefully stop active full/scan/pair run (SIGTERM → flush → export)",
    )
    stop.add_argument(
        "--force",
        action="store_true",
        help="SIGKILL if graceful shutdown exceeds --wait",
    )
    stop.add_argument(
        "--wait",
        type=float,
        default=120.0,
        metavar="SEC",
        help="Seconds to wait for graceful shutdown (default 120)",
    )

    serve = sub.add_parser(
        "serve",
        help="Run resident probe server (Unix socket + HTTP bridge, on-the-fly)",
    )
    serve.add_argument(
        "--pool",
        type=int,
        default=None,
        help="Netns pool size (default: effective default)",
    )
    serve.add_argument(
        "--bridge-batch",
        type=int,
        default=500,
        help="Lua bridge batch size (default 500)",
    )
    serve.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Default probe timeout seconds (default 3)",
    )
    serve.add_argument(
        "--classic",
        action="store_true",
        help="Deprecated: ignored; serve always uses lua_bridge",
    )
    serve.add_argument(
        "--http-port",
        type=int,
        default=None,
        help="Also expose an authenticated HTTP bridge on 127.0.0.1:PORT (optional)",
    )
    serve.add_argument(
        "--http-token",
        type=str,
        default=None,
        help="Bearer token for the HTTP bridge (default: BLOCKCHECKS_HTTP_TOKEN env "
        "or config.toml [http] token)",
    )
    serve.add_argument(
        "--debug",
        action="store_true",
        help="Python DEBUG logs + nfqws2 --debug=1 (toggle at runtime with SIGUSR1)",
    )

    tcp = sub.add_parser(
        "tcp",
        help="Single TCP strategy test on HOST (sync; use --ns for netns)",
        description=(
            "Oneshot TCP/TLS probe via TestRunner. Without --ns, traffic runs on "
            "the host network namespace (not an isolated netns pool slot)."
        ),
    )
    tcp.add_argument("-d", "--domain", required=True)
    tcp.add_argument("-s", "--strategy")
    tcp.add_argument("-c", "--config")
    tcp.add_argument("-C", "--configs-dir")
    tcp.add_argument("-f", "--file")
    tcp.add_argument("--test", choices=["custom", "standard"])
    tcp.add_argument("--test-dir", default=None, help="blockcheck2.d directory (default: $ZAPRET2/blockcheck2.d)")
    tcp.add_argument(
        "--protocol", default="tls12", choices=["http", "tls12", "tls13", "quic", "udp_voice"]
    )
    tcp.add_argument("--timeout", type=float, default=3.0)
    tcp.add_argument(
        "--hostlist",
        action=_BOOL,
        default=True,
        help="nfqws2 hostlist filter (default: ON)",
    )
    tcp.add_argument("--qnum", type=int, default=200)
    tcp.add_argument(
        "--ns",
        metavar="NAME",
        help="Run inside netns NAME (default: HOST, not netns)",
    )
    add_secure_dns_args(tcp, include_data_block_sync=False)
    add_system_deps_args(tcp)
    add_time_limit_args(tcp)
    add_curl_repeats_args(tcp)
    tcp.add_argument(
        "--debug",
        action="store_true",
        help="Python DEBUG logs + nfqws2 --debug=1 (toggle at runtime with SIGUSR1)",
    )
    tcp.add_argument(
        "--nfqws2-debug",
        nargs="?",
        const="1",
        default=None,
        help="nfqws2 --debug: 1=logs/file, syslog, or @path/path",
    )

    udp = sub.add_parser("udp", help="Single UDP strategy test (sync)")
    udp.add_argument("-c", "--config")
    udp.add_argument("-C", "--configs-dir")
    udp.add_argument("--ip", default=DEFAULT_VOICE_IP)
    udp.add_argument("--port", type=int, default=DEFAULT_VOICE_PORT)
    udp.add_argument(
        "--discover-dns",
        nargs="?",
        const=5,
        type=int,
        default=None,
        help="DNS + Maks-gaming IP list + dual UDP probe (no VPN)",
    )
    udp.add_argument(
        "--discover-dns-no-bootstrap",
        action="store_true",
        help="Skip nfqws2 UDP bootstrap during --discover-dns",
    )
    udp.add_argument(
        "--auto-discover",
        nargs="?",
        const=5,
        type=int,
        default=None,
        help="DNS + gateway discover via sing-box (VPN path)",
    )
    udp.add_argument(
        "--voice-region",
        default=os.environ.get("BLOCKCHECKS_VOICE_REGION", "finland"),
        metavar="REGION",
        help="Discord voice region for endpoint discovery "
        "(finland/russia/frankfurt/…; default BLOCKCHECKS_VOICE_REGION or finland)",
    )
    udp.add_argument(
        "--voice-burst",
        action="store_true",
        help="Also probe with a >16KB UDP media burst (voice-traffic heuristic; "
        "detects endpoints that only answer a sustained stream)",
    )
    udp.add_argument("--timeout", type=float, default=3.0)
    udp.add_argument("--qnum", type=int, default=201)
    udp.add_argument("--ns")
    udp.add_argument(
        "--debug",
        action="store_true",
        help="Python DEBUG logs + nfqws2 --debug=1 (toggle at runtime with SIGUSR1)",
    )
    udp.add_argument(
        "--nfqws2-debug",
        nargs="?",
        const="1",
        default=None,
        help="nfqws2 --debug: 1=logs/file, syslog, or @path/path",
    )
    add_system_deps_args(udp)

    scan = sub.add_parser("scan", help="Async TCP strategy batch scan")
    add_campaign_args(scan, mode="scan")

    preflight = sub.add_parser(
        "preflight",
        help="DNS/L3/stall triage + data_block triage.toml/hosts (no matrix)",
    )
    preflight.add_argument(
        "-d",
        "--domain",
        action="append",
        default=None,
        help="Target domain (repeatable)",
    )
    preflight.add_argument(
        "--preset", default=None, help="Domain preset name (presets/domains/{name}.txt)"
    )
    preflight.add_argument("--domains-file", help="Path to domain list file")
    preflight.add_argument(
        "--list-presets", action="store_true", help="List available presets and exit"
    )
    preflight.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Probe timeout in seconds (default: 3.0)",
    )
    preflight.add_argument(
        "--debug",
        action="store_true",
        help="Python DEBUG logs + nfqws2 --debug=1 (toggle at runtime with SIGUSR1)",
    )
    preflight.add_argument(
        "--nfqws2-debug",
        nargs="?",
        const="1",
        default=None,
        help="nfqws2 --debug: 1=logs/file, syslog, or @path/path",
    )
    preflight.add_argument(
        "--json",
        action="store_true",
        help="Print one JSON object to stdout (human logs on stderr)",
    )
    add_secure_dns_args(
        preflight, include_preflight=True, include_preflight_toggle=False
    )
    add_domain_filter_args(preflight)
    add_system_deps_args(preflight)

    composite = sub.add_parser("composite", help="Test composite nfqws2 config")
    composite.add_argument("-c", "--config", required=True, help="Path to composite .conf file")
    composite.add_argument(
        "-d", "--domains", nargs="+", help="Domains to test (default: Discord set)"
    )
    composite.add_argument("--parallel", type=int, default=effective_default_pool_size())
    composite.add_argument("--timeout", type=float, default=3.0)
    add_system_deps_args(composite)

    pair = sub.add_parser("pair", help="TCP x UDP pair matrix (async)")
    add_campaign_args(pair, mode="pair")

    sub.add_parser(
        "mcp",
        help="Model Context Protocol server (stdio) bridging LLM → bs serve daemon",
    )

    bench = sub.add_parser("bench-settle", help="Benchmark nfqws2 settle vs curl timeout")
    bench.add_argument("-d", "--domain", default="discord.com")
    bench.add_argument("-s", "--strategy", default=None, help="Single inline strategy")
    bench.add_argument(
        "-M",
        "--strategy-preset",
        default="timeout-benchmark",
        help="Strategy preset (default: timeout-benchmark)",
    )
    bench.add_argument(
        "--settle-times",
        default="",
        help="Comma-separated settle max seconds (default: 0.1,0.2,0.5,1,2)",
    )
    bench.add_argument(
        "--curl-timeouts",
        default="",
        help="Comma-separated curl timeouts (default: 0.5,1,1.5,2)",
    )
    bench.add_argument("--max-strategies", type=int, default=3)
    bench.add_argument(
        "--secure-dns",
        action=_BOOL,
        default=True,
        help="DoH pre-resolve (default: ON)",
    )
    bench.add_argument(
        "--write-profile",
        nargs="?",
        const=DEFAULT_PROFILE_PATH,
        default=None,
        metavar="PATH",
        help=f"Write settle profile JSON (default: {DEFAULT_PROFILE_PATH})",
    )
    bench.add_argument(
        "--no-write-profile",
        action="store_true",
        help="Skip writing settle profile JSON",
    )
    add_system_deps_args(bench)

    hb = sub.add_parser(
        "harvest-batch",
        help="Export top PASS strategies → dpi-tester batch.txt + manifest (+ raw confs)",
    )
    hb.add_argument(
        "-d",
        "--db",
        default=None,
        help=f"State DB (default: {DEFAULT_DB_PATH})",
    )
    hb.add_argument(
        "--out-dir",
        default=None,
        metavar="DIR",
        help="Destination root (default: XDG export/harvest/harvest_<ts>)",
    )
    hb.add_argument(
        "--top",
        type=int,
        default=20,
        help="Max candidates (default: 20)",
    )
    hb.add_argument(
        "--min-domains",
        type=int,
        default=2,
        help="Min distinct PASS domains per strategy (default: 2)",
    )
    hb.add_argument(
        "--proto",
        default="tcp",
        choices=["tcp", "udp", "quic"],
        help="Strategy protocol family (default: tcp)",
    )
    hb.add_argument(
        "--write-confs",
        action="store_true",
        help="Also emit self-contained raw nfqws2 confs (Tier-2 validation)",
    )
    hb.add_argument(
        "--exclude-quarantined",
        action="store_true",
        help="Drop domains currently in the quarantined table (default: keep them)",
    )

    gc = sub.add_parser(
        "gc",
        help="Prune debug logs, run summaries, harvest dirs, zapret2-dl, voice caches, optional DB rows (dry-run)",
    )
    gc_mode = gc.add_mutually_exclusive_group()
    gc_mode.add_argument(
        "--apply",
        action="store_true",
        help="Actually delete (default is dry-run)",
    )
    gc_mode.add_argument(
        "--dry-run",
        action="store_true",
        help="List deletions only (default; opposite of --apply)",
    )
    gc.add_argument(
        "--max-age-days",
        type=float,
        default=14,
        help="Age threshold for summaries/harvest/caches (default 14)",
    )
    gc.add_argument(
        "--nfqws2-keep",
        type=int,
        default=50,
        help="Newest nfqws2_*.log files to keep (default 50)",
    )
    gc.add_argument(
        "--db-days",
        type=float,
        default=None,
        metavar="N",
        help="Age-prune tcp_results/udp_results older than N days (opt-in; skipped if omitted)",
    )
    gc.add_argument(
        "--orphan-strategies",
        action="store_true",
        help="With --db-days, also drop strategies with no remaining tcp/udp rows",
    )
    gc.add_argument(
        "--db",
        default=None,
        help=f"State DB for --db-days (default: {DEFAULT_DB_PATH})",
    )

    db = sub.add_parser(
        "data-block",
        help="Export XDG provider store to a git data_block checkout",
    )
    db.add_argument(
        "--out",
        default=None,
        metavar="DIR",
        help="Destination data_block root (default: workspace submodule with .git)",
    )
    db.add_argument(
        "--git",
        action="store_true",
        help="git add/commit/push the destination (requires .git)",
    )
    db.add_argument(
        "--provider",
        default=None,
        metavar="SLUG",
        help="Export only this provider slug (default: all XDG providers)",
    )

    return parser


def dispatch(args: argparse.Namespace) -> int:  # noqa: C901
    if getattr(args, "debug", False):
        from blockchecks.engine.log import set_debug_mode

        set_debug_mode(True)
    else:
        dbg = getattr(args, "nfqws2_debug", None)
        if dbg is not None:
            os.environ["BLOCKCHECKS_NFQWS2_DEBUG"] = str(dbg)

    live = {"tcp", "udp", "scan", "pair", "composite", "bench-settle", "preflight"}
    # Skip deps when listing presets under scan/pair/preflight.
    if args.command in live and not (
        args.command in {"scan", "pair", "preflight"} and getattr(args, "list_presets", False)
    ):
        code = ensure_system_deps_or_exit(args)
        if code:
            return code

    def _scan(a: argparse.Namespace) -> int:
        if getattr(a, "list_presets", False):
            list_presets()
            return 0
        if a.generate:
            a.tcp_sources = (
                a.generate if a.generate != "custom,configs" else a.tcp_sources or "custom,configs"
            )
        a.generate = bool(a.generate)
        a.tcp_only = True
        a.udp_sources = ""
        a.configs_dir = CONFIGS_DIR
        a.config = None
        a.udp_config = None
        # Pair-only attrs not on scan CLI — set safe defaults for cmd_pair.
        a.full_voice = False
        a.udp_bypass = False
        a.auto_discover = None
        a.ip = DEFAULT_VOICE_IP
        a.port = DEFAULT_VOICE_PORT
        a.udp_timeout = 3.0
        return asyncio.run(cmd_pair(a))

    def _pair(a: argparse.Namespace) -> int:
        if getattr(a, "list_presets", False):
            list_presets()
            return 0
        if a.generate and a.generate != "custom,configs":
            a.tcp_sources = a.generate
        if getattr(a, "config", None) or getattr(a, "udp_config", None):
            a.generate = False
        else:
            a.generate = bool(a.generate) or bool(
                getattr(a, "tcp_sources", "") != "custom,configs"
                or getattr(a, "udp_sources", "") != "custom,standard_udp"
            )
        return asyncio.run(cmd_pair(a))

    def _composite(a: argparse.Namespace) -> int:
        from blockchecks.checkers.composite_runner import run as run_composite

        return asyncio.run(run_composite(a.config, a.domains, a.parallel, a.timeout))

    def _bench(a: argparse.Namespace) -> int:
        from blockchecks.cli.commands.bench_settle import cmd_bench_settle

        return asyncio.run(cmd_bench_settle(a))

    def _stop(a: argparse.Namespace) -> int:
        from blockchecks.cli.commands.stop import cmd_stop

        return cmd_stop(a)

    def _preflight(a: argparse.Namespace) -> int:
        from blockchecks.cli.commands.preflight import run_preflight_cmd

        if getattr(a, "list_presets", False):
            from blockchecks.cli.presets import list_presets

            list_presets()
            return 0
        return run_preflight_cmd(a)

    def _data_block(a: argparse.Namespace) -> int:
        from blockchecks.cli.commands.data_block import cmd_data_block

        return cmd_data_block(a)

    def _harvest_batch(a: argparse.Namespace) -> int:
        from blockchecks.cli.commands.harvest_batch import cmd_harvest_batch

        return cmd_harvest_batch(a)

    def _gc(a: argparse.Namespace) -> int:
        from blockchecks.cli.commands.gc import cmd_gc

        return cmd_gc(a)

    def _serve(a: argparse.Namespace) -> int:
        from blockchecks.cli.commands.serve import cmd_serve

        return cmd_serve(a)

    def _mcp(a: argparse.Namespace) -> int:
        from blockchecks.cli.commands.mcp import cmd_mcp

        return cmd_mcp(a)

    handlers: dict[str, Callable[[argparse.Namespace], int]] = {
        "tcp": cmd_tcp,
        "udp": cmd_udp,
        "scan": _scan,
        "pair": _pair,
        "composite": _composite,
        "bench-settle": _bench,
        "stop": _stop,
        "preflight": _preflight,
        "data-block": _data_block,
        "harvest-batch": _harvest_batch,
        "gc": _gc,
        "serve": _serve,
        "mcp": _mcp,
    }
    handler = handlers.get(args.command)
    if handler is not None:
        return handler(args)

    build_parser().print_help()
    return 1


def parse_cli_argv(
    argv: list[str],
    cfg: dict,
    *,
    apply_defaults: bool = True,
) -> tuple[argparse.Namespace, str | None, argparse.ArgumentParser]:
    """Parse argv with build_parser (or full sub-parser); apply namespace_compat."""
    from blockchecks.cli.profiles import flags_present_in_argv
    from blockchecks.cli.user_config import apply_parser_defaults, finalize_store_args

    if argv and argv[0] == "full":
        from blockchecks.main import build_arg_parser

        parser = build_arg_parser(cfg if apply_defaults else None)
        ns = parser.parse_args(argv[1:])
        ns.command = "full"
    else:
        parser = build_parser()
        if apply_defaults and cfg:
            for sub in iter_subparsers(parser).values():
                apply_parser_defaults(sub, cfg)
            apply_parser_defaults(parser, cfg)
        ns = parser.parse_args(argv)

    namespace_compat(ns)
    ns._explicit_cli = flags_present_in_argv(argv)
    if cfg:
        finalize_store_args(ns, cfg)
    cmd = getattr(ns, "command", None)
    return ns, cmd, parser


def main(argv: list[str] | None = None) -> int:
    """Entry point — argparse parse, pydantic projection, handler dispatch."""
    from blockchecks.cli.cliapp import main as cliapp_main

    return cliapp_main(argv)


def _main_argparse(argv: list[str] | None = None) -> int:
    from blockchecks.cli.user_config import (
        apply_parser_defaults,
        finalize_store_args,
        load_user_config,
    )
    from blockchecks.engine.paths import apply_pycache_prefix, configure_logging, ensure_dirs

    apply_pycache_prefix()
    ensure_dirs()
    configure_logging()
    user_cfg = load_user_config()
    paths_cfg = user_cfg.get("paths") if isinstance(user_cfg.get("paths"), dict) else {}
    if argv is None:
        argv = sys.argv[1:]
    from blockchecks.engine.paths import cwd_db_migrate_enabled, migrate_legacy_state_db

    migrate_legacy_state_db(enabled=cwd_db_migrate_enabled(paths_cfg) or "--migrate-cwd-db" in argv)

    if len(argv) > 0 and argv[0] == "full":
        from blockchecks.main import main as full_main

        return full_main(argv[1:], user_config=user_cfg)

    parser = build_parser()
    apply_parser_defaults(parser, user_cfg)
    old_argv = sys.argv
    try:
        sys.argv = ["bs", *argv]
        args = parser.parse_args(argv)
    finally:
        sys.argv = old_argv

    namespace_compat(args)
    from blockchecks.cli.profiles import flags_present_in_argv

    args._explicit_cli = flags_present_in_argv(argv)
    finalize_store_args(args, user_cfg)
    if getattr(args, "migrate_cwd_db", False):
        migrate_legacy_state_db(enabled=True)
    from blockchecks.engine.run_deadline import validate_time_limit_args

    validate_time_limit_args(parser, args)
    return dispatch(args)
