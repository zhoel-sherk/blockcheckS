"""Unit tests for blockchecks.engine.run_spec (RunSpec & CampaignContext)."""

from __future__ import annotations

from types import SimpleNamespace

from blockchecks.engine.run_spec import CampaignContext, RunSpec


def test_run_spec_defaults():
    spec = RunSpec()
    assert spec.command == "full"
    assert spec.scan_level == "fast"
    assert spec.timeout == 3.0
    assert spec.use_adaptive is True
    assert spec.try_wssize is True
    assert spec.save_weights is True
    assert spec.no_preflight is False
    assert spec.quick is False


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


def test_campaign_context():
    spec = RunSpec(domain="discord.com")
    ctx = CampaignContext(spec=spec, domains=["discord.com"], primary="discord.com")
    assert ctx.spec.domain == "discord.com"
    assert ctx.primary == "discord.com"
    assert len(ctx.domains) == 1
