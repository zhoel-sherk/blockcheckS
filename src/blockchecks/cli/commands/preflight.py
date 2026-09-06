"""Standalone preflight: DNS/L3/stall/JA4/QUIC + triage.toml/hosts, no matrix."""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

from blockchecks.checkers.dns_secure import prepare_dns_for_run
from blockchecks.cli.commands.pair_phases import (
    _resolve_pin_path,
    resolve_preset_domains,
)
from blockchecks.engine.config import SECURE_DNS_DEFAULT
from blockchecks.engine.domain_loader import load_domains
from blockchecks.engine.preflight import PreflightOptions, PreflightReport, run_preflight_async
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


def _provider_store():
    from blockchecks.data_block.provider import get_provider_dir
    from blockchecks.data_block.store import ProviderStore

    return ProviderStore(get_provider_dir(allow_detect=False))


def preflight_json_payload(
    report: PreflightReport | None,
    *,
    exit_code: int,
    domains: list[str] | None = None,
) -> dict[str, Any]:
    """Machine-readable contract for orchestrators (stdout with ``--json``)."""
    from blockchecks.data_block.provider import provider_name
    from blockchecks.engine.triage import clustered_primary_domain

    store = _provider_store()
    triage = report.triage if report is not None else None
    reports = getattr(triage, "domain_reports", None) or {}
    fallback = (domains or [""])[0] if domains else ""
    primary = clustered_primary_domain(reports, fallback=fallback) if reports else fallback
    return {
        "ok": exit_code == 0,
        "exit_code": exit_code,
        "triage_path": str(store.triage_file),
        "hosts_path": str(store.hosts_file),
        "provider": provider_name(allow_detect=False),
        "skip_domains": sorted(report.skip_domains) if report else [],
        "voice_ok": getattr(triage, "voice_ok", None),
        "udp_blocked": getattr(triage, "udp_blocked", None),
        "primary_domain": primary,
        "triage": triage.to_dict() if triage is not None else None,
    }


def _emit_preflight(args, payload: dict[str, Any]) -> None:
    if getattr(args, "json", False):
        print(json.dumps(payload, ensure_ascii=False), file=sys.stdout)  # noqa: print
        return
    log.info("%s", f"  triage: {payload['triage_path']}")
    log.info("%s", f"  hosts:  {payload['hosts_path']}")


def _keep_json_stdout_clean(args) -> None:
    """Route console logs to stderr so ``--json`` leaves stdout as pure JSON.

    The CLI configures the console stream on stdout by default (parser main).
    Machine consumers (e.g. GP ``bs_engine/_triage.py``) parse stdout only when
    it starts with ``{``, so any INFO line emitted before the JSON object would
    break the contract. Reset handlers once and reconfigure on stderr.
    """
    if not getattr(args, "json", False):
        return
    from blockchecks.engine.log import LOGGER_NAME, configure_logging

    root = logging.getLogger(LOGGER_NAME)
    level = root.level if root.level != logging.NOTSET else None
    for handler in list(root.handlers):
        root.removeHandler(handler)
        try:
            handler.close()
        except Exception:  # noqa: BLE001
            pass
    configure_logging(level=level, console="stderr")


def _maybe_skip_fooling_for_lock(args) -> None:
    from blockchecks.service.run_control import read_active_run

    if read_active_run() is None:
        return
    log.warning(
        "%s",
        f"  {YELLOW}run.lock active — skipping live fooling grid (campaign owns netns){RESET}",
    )
    args.skip_fooling_grid = True


async def cmd_preflight(args) -> int:
    """Run preflight only; write provider triage.toml + hosts."""
    domains, rc = collect_preflight_domains(args)
    if rc is not None:
        if getattr(args, "json", False) and rc != 0:
            _emit_preflight(args, preflight_json_payload(None, exit_code=rc, domains=[]))
        return rc

    from blockchecks.data_block.provider import provider_name

    provider_name(allow_detect=True)
    _maybe_skip_fooling_for_lock(args)
    secure_dns = SECURE_DNS_DEFAULT and not getattr(args, "no_secure_dns", False)
    dns_cache, audits, dns_rc = prepare_dns_for_run(
        domains,
        secure_dns=secure_dns,
        skip_audit=getattr(args, "skip_dns_audit", False),
        allow_hijack=getattr(args, "allow_dns_hijack", False),
        doh_server=getattr(args, "doh_server", None) or None,
    )
    if dns_rc:
        _emit_preflight(args, preflight_json_payload(None, exit_code=dns_rc, domains=domains))
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
    exit_code = int(report.exit_code or 0)
    if exit_code:
        log.error("%s", f"{RED}ERROR: preflight failed: {report.error}{RESET}")
        _emit_preflight(args, preflight_json_payload(report, exit_code=exit_code, domains=domains))
        return exit_code

    if report.skip_domains:
        log.info(
            "%s",
            f"  {YELLOW}Prolog skip (no bypass): {', '.join(sorted(report.skip_domains))}{RESET}",
        )

    if getattr(args, "data_block_sync", False):
        from blockchecks.engine.run_finalize import maybe_sync_data_block

        await maybe_sync_data_block(args)
    _emit_preflight(args, preflight_json_payload(report, exit_code=0, domains=domains))
    return 0


def run_preflight_cmd(args) -> int:
    import asyncio

    _keep_json_stdout_clean(args)
    return asyncio.run(cmd_preflight(args))
