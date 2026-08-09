"""Unit tests for UDP probe subprocess worker."""

import json
from unittest.mock import patch

import pytest

from blockchecks.engine._probe_worker import main, run_probe


@pytest.mark.unit
def test_run_probe_returns_json_shape():
    with patch(
        "blockchecks.checkers.udp_voice.voice_udp_probe", return_value=(True, 12.3, "ok", "stun")
    ):
        data = run_probe("1.2.3.4", 50004, 1.0)
    assert data == {
        "success": True,
        "latency_ms": 12.3,
        "detail": "ok",
        "method": "stun",
        "burst": False,
    }


@pytest.mark.unit
def test_run_probe_burst_flag_passed():
    with patch(
        "blockchecks.checkers.udp_voice.voice_udp_probe",
        return_value=(True, 20.0, "burst ok", "burst"),
    ) as probe:
        data = run_probe("1.2.3.4", 50004, 1.0, try_burst=True)
    assert data["burst"] is True
    assert data["method"] == "burst"
    probe.assert_called_once()
    kwargs = probe.call_args.kwargs
    assert kwargs.get("try_burst") is True


@pytest.mark.unit
def test_main_accepts_burst_flag(capsys):
    with patch(
        "blockchecks.engine._probe_worker.run_probe",
        return_value={"success": True, "burst": True},
    ):
        rc = main(["1.2.3.4", "50004", "1.0", "--burst"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["burst"] is True


@pytest.mark.unit
def test_main_prints_json(capsys):
    with patch("blockchecks.engine._probe_worker.run_probe", return_value={"success": True}):
        rc = main(["1.2.3.4", "50004", "1.0"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out.strip())
    assert out["success"] is True


@pytest.mark.unit
def test_main_usage_error():
    assert main([]) == 2
