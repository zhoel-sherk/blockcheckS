"""Typed models for the run-state store."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Checkpoint:
    tcp_idx: int
    udp_idx: int
    timestamp: str
    note: str
    fingerprint: str
    tcp_label: str
    udp_label: str
