"""TriageProfile: coarse DPI flags plus per-domain detail. JSON-safe.
Filled by preflight so generators can drop useless branches.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from blockchecks.engine.fail_phase import FailPhase


def _fail_phase(value: object) -> FailPhase:
    if isinstance(value, FailPhase):
        return value
    if isinstance(value, str) and value in FailPhase._value2member_map_:
        return FailPhase(value)
    return FailPhase.UNKNOWN


@dataclass
class TriageProfile:
    """Interference profile derived from preflight probes."""

    # DNS / L3-L4
    dns_hijacked: bool = False
    dns_sinkhole: bool = False
    unbypassable_l3: bool = False  # L4 SYN drop / ICMP block / IP blackhole
    l3_phase: FailPhase = FailPhase.UNKNOWN

    # Handshake / early DPI
    handshake_phase: FailPhase = FailPhase.UNKNOWN
    rst_at_sni: bool = False
    silent_drop_after_sni: bool = False

    # Stream stall
    stall_phase: FailPhase = FailPhase.UNKNOWN
    stall_at_bytes: int | None = None

    # QoS
    bandwidth_throttled: bool = False
    read_rate_bps: float = 0.0

    # UDP / QUIC
    quic_drop: bool = False
    udp_blocked: bool = False
    voice_ok: bool = False

    # TLS fingerprint (multi-profile ClientHello baseline)
    client_hello_len: int = 0
    is_tls_fingerprint_blocked: bool = False
    requires_postquantum_awareness: bool = False
    fingerprint_pass: dict[str, bool] = field(default_factory=dict)  # profile → ok

    # Per-domain detail (prolog/IP/stall) for the bandit context.
    domain_phases: dict[str, str] = field(default_factory=dict)

    # Fooling / hop / split diagnostics (Tier 1 preflight)
    viable_foolings: list[str] = field(default_factory=list)
    viable_blobs: list[str] = field(default_factory=list)
    split_mode: str = ""  # first_byte | sni_marker | disorder | seqovl | ""
    server_hops: int | None = None
    dpi_hops: int | None = None
    autottl_delta: int | None = None
    ech_blocked: bool | None = None
    http_blocked: bool | None = None
    dead_foolings: list[str] = field(default_factory=list)

    # convenience flags for generator pruning

    @property
    def requires_window_clamp(self) -> bool:
        """Stream stall → window-size desync (wsize/wssize) may help."""
        return self.stall_phase in (
            FailPhase.DATA_STALL_7K,
            FailPhase.DATA_STALL_16K,
            FailPhase.DATA_STALL_42K,
            FailPhase.DATA_STALL_64K_PLUS,
            FailPhase.DATA_STALL_FIRST_REQ,
            FailPhase.DATA_STALL_TLS_CERT,
            FailPhase.ZERO_WINDOW_STALL,
        )

    @property
    def prefer_quic(self) -> bool:
        """Bandwidth throttle or QUIC-friendly → push QUIC/HTTP3 families first."""
        return self.bandwidth_throttled or (not self.quic_drop and not self.udp_blocked)

    @property
    def bypassable(self) -> bool:
        """True if desync strategies have any chance (not L3/IP-blocked)."""
        return not self.unbypassable_l3 and not self.dns_sinkhole

    @property
    def l7_impersonate_sufficient(self) -> bool:
        """Fingerprint-blocked but a browser impersonation alone bypasses."""
        return self.is_tls_fingerprint_blocked

    @property
    def prefer_contextual_split(self) -> bool:
        """Post-quantum ClientHello (2 TCP segments) → avoid static numeric splits."""
        return self.requires_postquantum_awareness

    def to_dict(self) -> dict[str, Any]:
        return {
            "dns_hijacked": self.dns_hijacked,
            "dns_sinkhole": self.dns_sinkhole,
            "unbypassable_l3": self.unbypassable_l3,
            "l3_phase": self.l3_phase.value if self.l3_phase else None,
            "handshake_phase": self.handshake_phase.value if self.handshake_phase else None,
            "rst_at_sni": self.rst_at_sni,
            "silent_drop_after_sni": self.silent_drop_after_sni,
            "stall_phase": self.stall_phase.value if self.stall_phase else None,
            "stall_at_bytes": self.stall_at_bytes,
            "bandwidth_throttled": self.bandwidth_throttled,
            "read_rate_bps": round(self.read_rate_bps or 0.0, 1),
            "quic_drop": self.quic_drop,
            "udp_blocked": self.udp_blocked,
            "voice_ok": self.voice_ok,
            "client_hello_len": self.client_hello_len,
            "is_tls_fingerprint_blocked": self.is_tls_fingerprint_blocked,
            "requires_postquantum_awareness": self.requires_postquantum_awareness,
            "fingerprint_pass": dict(self.fingerprint_pass),
            "requires_window_clamp": self.requires_window_clamp,
            "prefer_quic": self.prefer_quic,
            "bypassable": self.bypassable,
            "l7_impersonate_sufficient": self.l7_impersonate_sufficient,
            "prefer_contextual_split": self.prefer_contextual_split,
            "domain_phases": dict(self.domain_phases),
            "viable_foolings": list(self.viable_foolings),
            "viable_blobs": list(self.viable_blobs),
            "split_mode": self.split_mode,
            "server_hops": self.server_hops,
            "dpi_hops": self.dpi_hops,
            "autottl_delta": self.autottl_delta,
            "ech_blocked": self.ech_blocked,
            "http_blocked": self.http_blocked,
            "dead_foolings": list(self.dead_foolings),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> TriageProfile:
        """Rebuild a profile from ``to_dict`` / triage.toml flattened dict."""
        if not data:
            return cls()
        phase = _fail_phase
        return cls(
            dns_hijacked=bool(data.get("dns_hijacked")),
            dns_sinkhole=bool(data.get("dns_sinkhole")),
            unbypassable_l3=bool(data.get("unbypassable_l3")),
            l3_phase=phase(data.get("l3_phase")),
            handshake_phase=phase(data.get("handshake_phase")),
            rst_at_sni=bool(data.get("rst_at_sni")),
            silent_drop_after_sni=bool(data.get("silent_drop_after_sni")),
            stall_phase=phase(data.get("stall_phase")),
            stall_at_bytes=data.get("stall_at_bytes"),
            bandwidth_throttled=bool(data.get("bandwidth_throttled")),
            read_rate_bps=float(data.get("read_rate_bps") or 0.0),
            quic_drop=bool(data.get("quic_drop")),
            udp_blocked=bool(data.get("udp_blocked")),
            voice_ok=bool(data.get("voice_ok")),
            client_hello_len=int(data.get("client_hello_len") or 0),
            is_tls_fingerprint_blocked=bool(data.get("is_tls_fingerprint_blocked")),
            requires_postquantum_awareness=bool(data.get("requires_postquantum_awareness")),
            fingerprint_pass=dict(data.get("fingerprint_pass") or {}),
            domain_phases=dict(data.get("domain_phases") or {}),
            viable_foolings=list(data.get("viable_foolings") or []),
            viable_blobs=list(data.get("viable_blobs") or []),
            split_mode=str(data.get("split_mode") or ""),
            server_hops=data.get("server_hops"),
            dpi_hops=data.get("dpi_hops"),
            autottl_delta=data.get("autottl_delta"),
            ech_blocked=data.get("ech_blocked"),
            http_blocked=data.get("http_blocked"),
            dead_foolings=list(data.get("dead_foolings") or []),
        )

    def to_context(self) -> dict[str, Any]:
        """Compact feature vector for the online bandit / S0 ranker."""
        return {
            "dns_hijacked": int(self.dns_hijacked),
            "dns_sinkhole": int(self.dns_sinkhole),
            "unbypassable_l3": int(self.unbypassable_l3),
            "rst_at_sni": int(self.rst_at_sni),
            "silent_drop_after_sni": int(self.silent_drop_after_sni),
            "stall": self.stall_phase.value if self.stall_phase else "",
            "throttled": int(self.bandwidth_throttled),
            "quic_drop": int(self.quic_drop),
            "client_hello_len": self.client_hello_len,
            "fp_blocked": int(self.is_tls_fingerprint_blocked),
            "pq_aware": int(self.requires_postquantum_awareness),
            "split_mode": self.split_mode,
            "n_foolings": len(self.viable_foolings),
        }


def disable_ech_from(args: Any, triage: Any) -> bool:
    """CLI ``--disable-ech`` or triage proving ECH uniquely fails."""
    return bool(getattr(args, "disable_ech", False)) or (
        getattr(triage, "ech_blocked", None) is True
    )
