"""TriageProfile — deterministic DPI/provider interference profile.

Built BEFORE the strategy scan (preflight) so generators can prune provably
useless branches and the online bandit / S0 ranker get a contextual vector.
Fields are deliberately coarse flags + per-domain detail, all JSON-safe.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from blockchecks.engine.fail_phase import FailPhase


@dataclass
class TriageProfile:
    """Interference profile derived from preflight probes (Phase 1-5)."""

    # Phase 1 — DNS / L3-L4
    dns_hijacked: bool = False
    dns_sinkhole: bool = False
    unbypassable_l3: bool = False  # L4 SYN drop / ICMP block / IP blackhole
    l3_phase: FailPhase = FailPhase.UNKNOWN

    # Phase 2 — handshake / early DPI
    handshake_phase: FailPhase = FailPhase.UNKNOWN
    rst_at_sni: bool = False
    silent_drop_after_sni: bool = False

    # Phase 3 — stream stall
    stall_phase: FailPhase = FailPhase.UNKNOWN
    stall_at_bytes: int | None = None

    # Phase 4 — QoS
    bandwidth_throttled: bool = False
    read_rate_bps: float = 0.0

    # Phase 5 — UDP/QUIC
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

    # ── convenience flags for generator pruning ──

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
            "read_rate_bps": round(self.read_rate_bps, 1),
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
        }

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
        }
