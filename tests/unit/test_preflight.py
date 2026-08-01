"""Unit tests for startup preflight (BC2-2, BC2-5, BC2-11)."""

from unittest.mock import patch

import pytest

from blockchecks.engine.preflight import (
    PreflightOptions,
    find_host_nfqws2_pids,
    run_preflight,
    run_prolog,
    run_unblocked_baseline,
)


@pytest.mark.unit
def test_find_host_nfqws2_pids_parses_pgrep():
    with patch("blockchecks.engine.preflight.subprocess.run") as mock_run:
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = "1234\n5678\n"
        assert find_host_nfqws2_pids() == [1234, 5678]


@pytest.mark.unit
def test_unblocked_baseline_ok():
    with patch("blockchecks.engine.preflight.check_tls") as mock_tls:
        mock_tls.return_value.success = True
        mock_tls.return_value.http_status = 200
        ok, _ = run_unblocked_baseline("iana.org")
    assert ok


@pytest.mark.unit
def test_prolog_returns_tls_success():
    with patch("blockchecks.engine.preflight.check_tls") as mock_tls:
        mock_tls.return_value.success = True
        assert run_prolog("discord.com") is True


@pytest.mark.unit
def test_preflight_aborts_on_baseline_fail():
    with patch("blockchecks.engine.preflight.run_unblocked_baseline", return_value=(False, "fail")):
        r = run_preflight(["discord.com"], PreflightOptions(skip_nfqws2_check=True))
    assert r.exit_code == 1


@pytest.mark.unit
def test_preflight_skips_domain_on_prolog():
    with (
        patch("blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "")),
        patch("blockchecks.engine.preflight.run_prolog", return_value=True),
        patch("blockchecks.engine.preflight.run_port_block_probe"),
        patch("blockchecks.engine.preflight.print_port_block_report"),
        patch("blockchecks.engine.preflight.run_ip_block_cross_test"),
        patch("blockchecks.engine.preflight.print_ip_block_report"),
    ):
        r = run_preflight(
            ["discord.com"],
            PreflightOptions(skip_nfqws2_check=True, skip_ip_block=True),
        )
    assert "discord.com" in r.skip_domains


@pytest.mark.unit
def test_preflight_force_keeps_domain():
    with (
        patch("blockchecks.engine.preflight.run_unblocked_baseline", return_value=(True, "")),
        patch("blockchecks.engine.preflight.run_prolog", return_value=True),
        patch("blockchecks.engine.preflight.run_port_block_probe"),
        patch("blockchecks.engine.preflight.print_port_block_report"),
    ):
        r = run_preflight(
            ["discord.com"],
            PreflightOptions(skip_nfqws2_check=True, skip_ip_block=True, force=True),
        )
    assert "discord.com" not in r.skip_domains
