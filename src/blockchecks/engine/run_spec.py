"""RunSpec and CampaignContext dataclasses for a CLI run."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from blockchecks.engine.config import (
    DEFAULT_CURL_PARALLEL,
    DEFAULT_VOICE_IP,
    DEFAULT_VOICE_PORT,
    MAX_CURL_PARALLEL,
    SECURE_DNS_DEFAULT,
    effective_default_pool_size,
)
from blockchecks.engine.paths import DEFAULT_DB_PATH, DEFAULT_OUT_DIR


@dataclass
class RunSpec:
    """Typed specification for a blockcheckS execution session."""

    command: str = "full"
    domain: str | None = None
    domains_file: str | None = None
    preset: str | None = None
    strategy_preset: str | None = None
    protocol: str = "tls12"
    scan_level: str = "fast"
    parallel: int = field(default_factory=effective_default_pool_size)
    max_strategies: int = 0
    timeout: float = 3.0
    udp_timeout: float = 3.0
    db_path: str = DEFAULT_DB_PATH
    db_batch: int = 500
    out_dir: str = DEFAULT_OUT_DIR
    resume: bool = False
    force: bool = False
    disable_ech: bool = False
    try_wssize: bool = True
    use_adaptive: bool = True
    adaptive_epsilon: float = 0.1
    save_weights: bool = True
    curl_parallel: int = 1
    export_limit: int = 3
    common_only: bool = True
    secure_dns: bool = SECURE_DNS_DEFAULT
    doh_server: str | None = None
    skip_dns_audit: bool = False
    allow_dns_hijack: bool = False
    data_block_sync: bool = False
    allow_unsafe_domains: bool = False
    no_preflight: bool = False
    quick: bool = False
    tcp_sources: str = ""
    udp_sources: str = ""
    generate: str = ""
    user_matrix: str = ""
    voice_ip: str = DEFAULT_VOICE_IP
    voice_port: int = DEFAULT_VOICE_PORT
    discover_dns: int | None = None
    discover_dns_no_bootstrap: bool = False
    auto_discover: int | None = None
    voice_region: str = "finland"
    voice_burst: bool = False
    full_voice: bool = False
    udp_bypass: bool = False
    time_limit_h: float | None = None
    time_limit_m: float | None = None
    nfqws2_debug: str | None = None
    lua_extra: list[str] = field(default_factory=list)
    settle_profile: str | None = None
    no_settle_profile: bool = False
    no_http: bool = False
    no_quic: bool = False
    no_voice: bool = False
    tcp_only: bool = False
    pair_max: int = 200
    zero_pass_warn: int = 10
    isp_interface: str = "eth3"
    prefix: str = "/opt/etc/nfqws2"
    mode: str = "auto"
    profile: str | None = None
    raw_args: Any = None
    triage: Any = None

    @classmethod
    def from_args(cls, args: Any, *, command: str | None = None) -> RunSpec:
        """Construct a typed RunSpec from an argparse Namespace or Dict."""
        cmd = command or getattr(args, "command", "full") or "full"
        no_adaptive = bool(getattr(args, "no_adaptive", False))
        no_wssize = bool(getattr(args, "no_wssize", False))
        no_sec_dns = bool(getattr(args, "no_secure_dns", False))
        fan_out = bool(getattr(args, "fan_out", False))
        raw_curl_par = getattr(args, "curl_parallel", DEFAULT_CURL_PARALLEL)
        curl_parallel = max(1, min(raw_curl_par, MAX_CURL_PARALLEL))
        if fan_out and curl_parallel <= 1:
            curl_parallel = min(max(4, DEFAULT_CURL_PARALLEL), MAX_CURL_PARALLEL)

        return cls(
            command=cmd,
            domain=getattr(args, "domain", None) or None,
            domains_file=getattr(args, "domains_file", None) or None,
            preset=getattr(args, "preset", None) or None,
            strategy_preset=getattr(args, "strategy_preset", None) or None,
            protocol=getattr(args, "protocol", "tls12") or "tls12",
            scan_level=getattr(args, "scan_level", "fast") or "fast",
            parallel=int(getattr(args, "parallel", effective_default_pool_size())),
            max_strategies=int(getattr(args, "max", 0) or 0),
            timeout=float(getattr(args, "timeout", 3.0)),
            udp_timeout=float(getattr(args, "udp_timeout", 3.0)),
            db_path=getattr(args, "db", None) or DEFAULT_DB_PATH,
            db_batch=int(getattr(args, "db_batch", 500) or 500),
            out_dir=getattr(args, "out_dir", None) or DEFAULT_OUT_DIR,
            resume=bool(getattr(args, "resume", False)),
            force=bool(getattr(args, "force", False)),
            disable_ech=bool(getattr(args, "disable_ech", False)),
            try_wssize=not no_wssize,
            use_adaptive=not no_adaptive,
            adaptive_epsilon=float(getattr(args, "adaptive_epsilon", 0.1)),
            save_weights=not bool(getattr(args, "no_adaptive_weights", False)),
            curl_parallel=curl_parallel,
            export_limit=int(getattr(args, "export_limit", 3) or 3),
            common_only=not bool(getattr(args, "no_common_only", False)),
            secure_dns=SECURE_DNS_DEFAULT and not no_sec_dns,
            doh_server=getattr(args, "doh_server", None) or None,
            skip_dns_audit=bool(getattr(args, "skip_dns_audit", False)),
            allow_dns_hijack=bool(getattr(args, "allow_dns_hijack", False)),
            data_block_sync=bool(getattr(args, "data_block_sync", False)),
            allow_unsafe_domains=bool(getattr(args, "allow_unsafe_domains", False)),
            no_preflight=bool(getattr(args, "no_preflight", False)),
            quick=bool(getattr(args, "quick", False)),
            tcp_sources=getattr(args, "tcp_sources", "") or "",
            udp_sources=getattr(args, "udp_sources", "") or "",
            generate=getattr(args, "generate", "") or "",
            user_matrix=getattr(args, "user_matrix", "") or "",
            voice_ip=getattr(args, "ip", DEFAULT_VOICE_IP) or DEFAULT_VOICE_IP,
            voice_port=int(getattr(args, "port", DEFAULT_VOICE_PORT) or DEFAULT_VOICE_PORT),
            discover_dns=getattr(args, "discover_dns", None),
            discover_dns_no_bootstrap=bool(getattr(args, "discover_dns_no_bootstrap", False)),
            auto_discover=getattr(args, "auto_discover", None),
            voice_region=getattr(args, "voice_region", "finland") or "finland",
            voice_burst=bool(getattr(args, "voice_burst", False)),
            full_voice=bool(getattr(args, "full_voice", False)),
            udp_bypass=bool(getattr(args, "udp_bypass", False)),
            time_limit_h=getattr(args, "max_timeh", None),
            time_limit_m=getattr(args, "max_timem", None),
            nfqws2_debug=getattr(args, "nfqws2_debug", None),
            lua_extra=list(getattr(args, "lua_extra", None) or []),
            settle_profile=getattr(args, "settle_profile", None) or None,
            no_settle_profile=bool(getattr(args, "no_settle_profile", False)),
            no_http=bool(getattr(args, "no_http", False)),
            no_quic=bool(getattr(args, "no_quic", False)),
            no_voice=bool(getattr(args, "no_voice", False)),
            tcp_only=bool(getattr(args, "tcp_only", False)),
            pair_max=int(getattr(args, "pair_max", 200) or 200),
            zero_pass_warn=int(getattr(args, "zero_pass_warn", 10) or 10),
            isp_interface=getattr(args, "isp_interface", "eth3") or "eth3",
            prefix=getattr(args, "prefix", "/opt/etc/nfqws2") or "/opt/etc/nfqws2",
            mode=getattr(args, "mode", "auto") or "auto",
            profile=getattr(args, "profile", None),
            raw_args=args,
            triage=getattr(args, "triage", None),
        )


@dataclass
class CampaignContext:
    """Unified runtime context for execution phases (main, scan, pair)."""

    spec: RunSpec
    db: Any = None
    domains: list[str] = field(default_factory=list)
    primary: str = ""
    dns_cache: Any = None
    dns_audits: list[Any] = field(default_factory=list)
    triage: Any = None
    stop: Any = field(default_factory=lambda: None)
    deadline: Any = None
    runner: Any = None
    tcp_items: list[Any] = field(default_factory=list)
    udp_items: list[Any] = field(default_factory=list)
    quic_items: list[Any] = field(default_factory=list)
    http_items: list[Any] = field(default_factory=list)
