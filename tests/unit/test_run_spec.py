"""Unit tests for blockchecks.engine.run_spec (RunSpec & CampaignContext)."""

from __future__ import annotations

from types import SimpleNamespace

from blockchecks.engine.run_spec import CampaignContext, RunSpec


def test_run_spec_defaults(monkeypatch):
    monkeypatch.delenv("BLOCKCHECKS_ISP_IFACE", raising=False)
    monkeypatch.delenv("ISP_INTERFACE", raising=False)
    spec = RunSpec()
    assert spec.command == "full"
    assert spec.scan_level == "fast"
    assert spec.timeout == 3.0
    assert spec.use_adaptive is True
    assert spec.try_wssize is True
    assert spec.save_weights is True
    assert spec.no_preflight is False
    assert spec.quick is False
    assert spec.isp_interface == ""


def test_run_spec_isp_interface_from_env(monkeypatch):
    monkeypatch.delenv("ISP_INTERFACE", raising=False)
    monkeypatch.setenv("BLOCKCHECKS_ISP_IFACE", "wlp4s0")
    spec = RunSpec()
    assert spec.isp_interface == "wlp4s0"


def test_run_spec_from_args_preserves_empty_isp_interface():
    args = SimpleNamespace(isp_interface="")
    spec = RunSpec.from_args(args)
    assert spec.isp_interface == ""


def test_run_spec_from_args_isp_interface_fallback_env(monkeypatch):
    monkeypatch.delenv("BLOCKCHECKS_ISP_IFACE", raising=False)
    monkeypatch.setenv("ISP_INTERFACE", "eth0")
    args = SimpleNamespace()
    spec = RunSpec.from_args(args)
    assert spec.isp_interface == "eth0"


def test_run_spec_from_args_basic():
    args = SimpleNamespace(
        command="scan",
        domain="example.com",
        timeout=2.5,
        scan_level="fast",
        no_adaptive=True,
        no_wssize=True,
        disable_ech=True,
        max=50,
        preset="top",
    )
    spec = RunSpec.from_args(args)
    assert spec.command == "scan"
    assert spec.domain == "example.com"
    assert spec.timeout == 2.5
    assert spec.use_adaptive is False
    assert spec.try_wssize is False
    assert spec.disable_ech is True
    assert spec.max_strategies == 50
    assert spec.preset == "top"


def test_run_spec_from_args_fanout_curl_parallel():
    args = SimpleNamespace(
        fan_out=True,
        curl_parallel=1,
    )
    spec = RunSpec.from_args(args)
    assert spec.curl_parallel >= 4


def test_run_spec_from_args_reprobe_failed_zero_preserved():
    args = SimpleNamespace(reprobe_failed=0)
    spec = RunSpec.from_args(args)
    assert spec.reprobe_failed == 0


def test_run_spec_from_args_reprobe_failed():
    args = SimpleNamespace(reprobe_failed=3)
    spec = RunSpec.from_args(args)
    assert spec.reprobe_failed == 3


def test_run_spec_defaults_reprobe_failed():
    spec = RunSpec()
    assert spec.reprobe_failed == 0


def test_campaign_context():
    spec = RunSpec(domain="discord.com")
    ctx = CampaignContext(spec=spec, domains=["discord.com"], primary="discord.com")
    assert ctx.spec.domain == "discord.com"
    assert ctx.primary == "discord.com"
    assert len(ctx.domains) == 1
