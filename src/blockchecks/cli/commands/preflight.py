"""Standalone preflight: DNS/L3/stall/JA4/QUIC + triage.toml/hosts, no matrix."""

from __future__ import annotations

import logging
from typing import Any

from blockchecks.checkers.dns_secure import prepare_dns_for_run
from blockchecks.cli.commands.pair_phases import (
    _resolve_pin_path,
    resolve_preset_domains,
)
from blockchecks.engine.config import SECURE_DNS_DEFAULT
from blockchecks.engine.domain_loader import load_domains
from blockchecks.engine.preflight import PreflightOptions, run_preflight_async
from blockchecks.terminal import CYAN, RED, RESET, YELLOW

log = logging.getLogger(__name__)


def _as_domain_list(raw: Any) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw] if raw.strip() else []
    return [d.strip() for d in raw if isinstance(d, str) and d.strip()]


def collect_preflight_domains(args) -> tuple[list[str], int | None]:
    """Merge -d / --preset / --domains-file; exit_code set on error or --list-presets."""
    if getattr(args, "list_presets", False):
        from blockchecks.cli.presets import list_presets

        list_presets()
        return [], 0

    preset_domains, preset_rc = resolve_preset_domains(args)
    if preset_rc:
        return [], preset_rc

    file_domains: list[str] = []
    path = getattr(args, "domains_file", None) or ""
    if path:
        try:
            loaded = load_domains(
                path,
                allow_unsafe=getattr(args, "allow_unsafe_domains", False),
            )
        except FileNotFoundError:
            log.error("%s", f"{RED}ERROR: domains file not found: {path}{RESET}")
            return [], 1
        file_domains = loaded.domains
        log.info("%s", f"  {CYAN}domains-file '{path}': {len(file_domains)} domains{RESET}")

    domains = list(
        dict.fromkeys(
            _as_domain_list(getattr(args, "domain", None)) + preset_domains + file_domains
        )
    )
    if not domains:
        log.error("%s", f"{RED}ERROR: --domain, --preset, or --domains-file required{RESET}")
        return [], 1
    return domains, None


async def cmd_preflight(args) -> int:
    """Run preflight only; write provider triage.toml + hosts."""
    domains, rc = collect_preflight_domains(args)
    if rc is not None:
        return rc

    from blockchecks.data_block.provider import provider_name

    provider_name(allow_detect=True)
    secure_dns = SECURE_DNS_DEFAULT and not getattr(args, "no_secure_dns", False)
    dns_cache, audits, dns_rc = prepare_dns_for_run(
        domains,
        secure_dns=secure_dns,
        skip_audit=getattr(args, "skip_dns_audit", False),
        allow_hijack=getattr(args, "allow_dns_hijack", False),
        doh_server=getattr(args, "doh_server", None) or None,
    )
    if dns_rc:
        return dns_rc

    pin_path = _resolve_pin_path(args)
    if pin_path and dns_cache is not None:
        from blockchecks.checkers.ip_pin import load_pins

        pins = load_pins(pin_path)
        if pins:
            dns_cache.set_pins(pins)
            log.info("%s", f"  {CYAN}[dns] pinned IPs from {pin_path}{RESET}")

    log.info("%s", f"  {CYAN}Preflight {len(domains)} domain(s), no strategy matrix{RESET}")
    report = await run_preflight_async(
        domains,
        PreflightOptions.from_args(args, dns_cache=dns_cache, dns_audits=audits),
    )
    if report.exit_code:
        log.error("%s", f"{RED}ERROR: preflight failed: {report.error}{RESET}")
        return int(report.exit_code)

    if report.skip_domains:
        log.info(
            "%s",
            f"  {YELLOW}Prolog skip (no bypass): {', '.join(sorted(report.skip_domains))}{RESET}",
        )

    if getattr(args, "data_block_sync", False):
        from blockchecks.engine.run_finalize import maybe_sync_data_block

        await maybe_sync_data_block(args)
    return 0


def run_preflight_cmd(args) -> int:
    import asyncio

    return asyncio.run(cmd_preflight(args))
