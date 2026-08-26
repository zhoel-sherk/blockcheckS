"""Namespace-scoped NFQUEUE iptables with tracked -D cleanup.

Never ``iptables -F OUTPUT``. Rules are attached once per namespace (idempotent
``attach``) and removed with matching ``-D`` on teardown.
"""

from __future__ import annotations

import logging
import subprocess
import threading
from dataclasses import dataclass

log = logging.getLogger(__name__)

_REGISTRY_LOCK = threading.Lock()
_REGISTRY: dict[str, NsFirewall] = {}


class IptablesError(RuntimeError):
    """NFQUEUE rule missing — probes would bypass nfqws2 (false PASS)."""


@dataclass(frozen=True, slots=True)
class _RuleSpec:
    proto: str
    dport: str
    queue: int
    multiport: bool = False
    bypass: bool = True


class NsFirewall:
    """Track OUTPUT NFQUEUE rules inside one network namespace."""

    def __init__(self, ns_name: str) -> None:
        self.ns_name = ns_name
        self._rules: dict[_RuleSpec, list[str]] = {}
        self._dirty = False

    def _cmd_prefix(self) -> list[str]:
        return ["sudo", "-n", "ip", "netns", "exec", self.ns_name, "iptables"]

    def _run(self, *args: str, check: bool = False) -> subprocess.CompletedProcess:
        cmd = self._cmd_prefix() + list(args)
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"iptables timeout in {self.ns_name!r}: {' '.join(args)}"
            ) from exc
        if check and result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise IptablesError(
                f"{self.ns_name}: iptables {' '.join(args)} failed rc={result.returncode}"
                + (f" ({detail[:200]})" if detail else "")
            )
        return result

    @staticmethod
    def _rule_body(spec: _RuleSpec) -> list[str]:
        body = ["OUTPUT", "-p", spec.proto]
        if spec.multiport:
            body.extend(["-m", "multiport", "--dports", spec.dport])
        else:
            body.extend(["--dport", spec.dport])
        body.extend(["-j", "NFQUEUE", "--queue-num", str(spec.queue)])
        if spec.bypass:
            body.append("--queue-bypass")
        return body

    @property
    def dirty(self) -> bool:
        return self._dirty

    def mark_dirty(self) -> None:
        """Signal foreign or unknown rule state; next attach re-syncs tracked rules."""
        self._dirty = True

    def is_attached(
        self,
        *,
        proto: str,
        port: str,
        queue: int,
        multiport: bool = False,
        bypass: bool = True,
    ) -> bool:
        return _RuleSpec(proto, port, queue, multiport, bypass) in self._rules

    def attach(
        self,
        *,
        proto: str,
        port: str,
        queue: int,
        multiport: bool = False,
        bypass: bool = True,
    ) -> None:
        """Add one OUTPUT NFQUEUE rule; no-op when already tracked."""
        if self._dirty:
            log.debug("ns_firewall %s: dirty — detaching before attach", self.ns_name)
            self.detach()
            self._dirty = False

        spec = _RuleSpec(proto, port, queue, multiport, bypass)
        if spec in self._rules:
            return

        body = self._rule_body(spec)
        self._run("-A", *body, check=True)
        self._rules[spec] = ["-D", *body]

        verify = self._run("-C", *body)
        if verify.returncode != 0:
            log.warning(
                "  [iptables] %s: rule MISSING right after -A "
                "(rc=%s) — table may have been reset",
                self.ns_name,
                verify.returncode,
            )
            self._rules.pop(spec, None)
            raise IptablesError(
                f"{self.ns_name}: iptables -C NFQUEUE/{queue} failed after -A"
            )

    def detach_one(
        self,
        *,
        proto: str,
        port: str,
        queue: int,
        multiport: bool = False,
        bypass: bool = True,
    ) -> None:
        """Remove one tracked rule via ``iptables -D``."""
        spec = _RuleSpec(proto, port, queue, multiport, bypass)
        delete_args = self._rules.pop(spec, None)
        if delete_args is None:
            return
        try:
            self._run(*delete_args, check=False)
        except Exception as exc:
            log.warning(
                "ns_firewall %s: detach_one %s failed: %s",
                self.ns_name,
                " ".join(delete_args),
                exc,
            )

    def detach(self) -> None:
        """Remove only rules this instance added via ``iptables -D``."""
        for delete_args in reversed(list(self._rules.values())):
            try:
                self._run(*delete_args, check=False)
            except Exception as exc:
                log.warning(
                    "ns_firewall %s: detach %s failed: %s",
                    self.ns_name,
                    " ".join(delete_args),
                    exc,
                )
        self._rules.clear()

    def __enter__(self) -> NsFirewall:
        return self

    def __exit__(self, *_args: object) -> None:
        self.detach()


def get_ns_firewall(ns_name: str) -> NsFirewall:
    """Return the per-namespace firewall (created on first use)."""
    with _REGISTRY_LOCK:
        fw = _REGISTRY.get(ns_name)
        if fw is None:
            fw = NsFirewall(ns_name)
            _REGISTRY[ns_name] = fw
        return fw


def mark_ns_dirty(ns_name: str) -> None:
    """Mark namespace iptables state uncertain (e.g. after foreign classic probes)."""
    with _REGISTRY_LOCK:
        fw = _REGISTRY.get(ns_name)
    if fw is not None:
        fw.mark_dirty()


def drop_ns_firewall(ns_name: str) -> None:
    """Detach tracked rules and drop registry entry (netns destroy)."""
    with _REGISTRY_LOCK:
        fw = _REGISTRY.pop(ns_name, None)
    if fw is not None:
        fw.detach()


def reset_registry_for_tests() -> None:
    """Clear the module registry (unit tests only)."""
    with _REGISTRY_LOCK:
        _REGISTRY.clear()


__all__ = [
    "IptablesError",
    "NsFirewall",
    "drop_ns_firewall",
    "get_ns_firewall",
    "mark_ns_dirty",
    "reset_registry_for_tests",
]
