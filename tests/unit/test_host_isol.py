"""Host-mode isolation (fwmark) unit tests — docs/hostmode.md, AUDIT §16."""

import pathlib
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from blockchecks.engine.config import DESYNC_MARK, resolve_probe_isol
from blockchecks.service import host_isol
from blockchecks.service.probe import _worker_cmd


@pytest.mark.unit
def test_build_queue_rules_scheme_b():
    rules = host_isol.build_queue_rules(skuid="bcprobe", qnum=220, probe_mark=0)
    assert len(rules) == 1
    r = rules[0]
    assert "meta skuid bcprobe" in r
    assert "tcp dport 443" in r
    assert f"meta mark and 0x{DESYNC_MARK:x} == 0" in r
    assert "ct original packets 1-15" in r
    assert "queue num 220 bypass" in r
    assert "meta mark set" not in r  # current binary: no --filter-mark


@pytest.mark.unit
def test_build_queue_rules_probe_mark_sets_mark():
    rules = host_isol.build_queue_rules(skuid="bcprobe", qnum=221, probe_mark=0x20000000)
    assert "meta mark set 0x20000000" in rules[0]


@pytest.mark.unit
def test_notrack_rule_matches_upstream_manual():
    assert (
        host_isol.build_notrack_rule(DESYNC_MARK)
        == f"mark & 0x{DESYNC_MARK:x} != 0x00000000 notrack"
    )


@pytest.mark.unit
def test_hostify_conf_text_rewrites_qnum_and_strips_marks():
    text = "--filter-tcp=443\n--qnum=200\n--fwmark=0x1234\n--filter-mark=0x99\n--daemon\n"
    out = host_isol.hostify_conf_text(text, qnum=220, desync_mark=0x40000000)
    lines = out.splitlines()
    assert "--qnum=220" in lines
    assert f"--fwmark={0x40000000:#x}" in lines
    assert "--fwmark=0x1234" not in lines
    assert "--filter-mark=0x99" not in lines
    assert "--daemon" in lines
    # exactly one qnum line
    assert sum(1 for line in lines if line.startswith("--qnum=")) == 1


@pytest.mark.unit
def test_hostify_conf_text_inserts_when_no_qnum():
    out = host_isol.hostify_conf_text("--bind-fix4\n", qnum=220, desync_mark=0x40000000)
    assert out.splitlines()[0] == "--qnum=220"
    assert out.splitlines()[1] == f"--fwmark={0x40000000:#x}"


@pytest.mark.unit
def test_worker_cmd_host_branch_uses_probe_uid():
    cmd = _worker_cmd("host-q220-12345", "/usr/bin/python3")
    assert "ip" not in cmd or "netns" not in cmd
    assert "netns" not in cmd
    assert "-u" in cmd and "bcprobe" in cmd
    assert "--mode" in cmd


@pytest.mark.unit
def test_worker_cmd_ns_branch_unchanged():
    cmd = _worker_cmd("bs-p-0001-0", "/usr/bin/python3")
    assert "netns" in cmd and "exec" in cmd and "bs-p-0001-0" in cmd


@pytest.mark.unit
def test_resolve_probe_isol_default_and_env(monkeypatch):
    assert resolve_probe_isol(SimpleNamespace(probe_isol=None)) == "netns"
    monkeypatch.setenv("BLOCKCHECKS_PROBE_ISOL", "host")
    assert resolve_probe_isol(SimpleNamespace(probe_isol=None)) == "host"


@pytest.mark.unit
def test_resolve_probe_isol_unknown_value_raises():
    with pytest.raises(ValueError, match="unknown value"):
        resolve_probe_isol(SimpleNamespace(probe_isol="bridge"))


@pytest.mark.unit
def test_resolve_probe_isol_host_requires_probe_uid(monkeypatch):
    from blockchecks.engine import config as cfgmod

    monkeypatch.setattr(cfgmod, "HOST_PROBE_USER", "no-such-uid-xyz")
    with pytest.raises(ValueError, match="probe uid"):
        resolve_probe_isol(SimpleNamespace(probe_isol="host"))
    monkeypatch.setattr(cfgmod, "HOST_PROBE_USER", "bcprobe")
    assert resolve_probe_isol(SimpleNamespace(probe_isol="host")) == "host"


@pytest.mark.unit
def test_probe_uid_matches_rejects_nobody_and_overflow():
    assert host_isol.probe_uid_matches("bcprobe") is True
    assert host_isol.probe_uid_matches("no-such-uid-xyz") is False


@pytest.mark.unit
def test_self_check_collects_errors(monkeypatch):
    monkeypatch.setattr(host_isol, "nft_available", lambda: False)
    errs = host_isol.self_check()
    assert any("nft" in e for e in errs)


@pytest.mark.unit
def test_test_runner_host_mode_conflicts_with_ns():
    from blockchecks.service.test_runner import TestRunner

    with pytest.raises(ValueError, match="conflicts with --ns"):
        TestRunner(ns_name="bs-p-0001-0", probe_isol="host")


@pytest.mark.unit
def test_test_runner_host_slot_name():
    from blockchecks.service.test_runner import TestRunner

    runner = TestRunner(ns_name=None, probe_isol="host", host_qnum=220)
    assert runner.host_slot.startswith("host-q220-")
    assert runner.host_slot.split("-")[-1].isdigit()


@pytest.mark.unit
def test_nfqws2_start_host_mode_injects_fwmark(tmp_path):
    from blockchecks.service.nfqws2 import Nfqws2Manager

    captured: dict = {}

    def fake_launch(self, config_arg, *, stop_first=True):
        path = config_arg[1:] if config_arg.startswith("@") else config_arg
        captured["config"] = pathlib.Path(path).read_text(encoding="utf-8")

    with patch.object(Nfqws2Manager, "_launch", fake_launch):
        mgr = Nfqws2Manager(ns_name=None)
        mgr.start("fake:blob=stun", qnum=220, host_mode=True, desync_mark=DESYNC_MARK)
    assert f"--fwmark={DESYNC_MARK:#x}" in captured["config"]
    fw_idx = captured["config"].index(f"--fwmark={DESYNC_MARK:#x}")
    qnum_idx = captured["config"].index("--qnum=220")
    assert fw_idx > qnum_idx


@pytest.mark.unit
def test_nfqws2_start_no_host_mode_no_fwmark(tmp_path):
    from blockchecks.service.nfqws2 import Nfqws2Manager

    captured: dict = {}

    def fake_launch(self, config_arg, *, stop_first=True):
        captured["config"] = pathlib.Path(config_arg[1:]).read_text(encoding="utf-8")

    with patch.object(Nfqws2Manager, "_launch", fake_launch):
        mgr = Nfqws2Manager(ns_name=None)
        mgr.start("fake:blob=stun", qnum=200)
    assert "--fwmark" not in captured["config"]


@pytest.mark.unit
async def test_composite_teardown_host_branch(monkeypatch):
    import asyncio

    from blockchecks.engine.composite_runner import _teardown_composite

    proc = MagicMock()
    monkeypatch.setattr(host_isol, "teardown_host_queue", lambda **kw: True)
    released: list[str] = []
    monkeypatch.setattr(
        "blockchecks.engine.composite_runner.release_curl_probe_worker",
        lambda ns: released.append(ns),
    )
    await asyncio.ensure_future(
        _teardown_composite(True, proc, "host-q220-1", None, "", None)
    )
    proc.terminate.assert_called_once()
    assert released == ["host-q220-1"]


@pytest.mark.unit
def test_teardown_host_queue_missing_is_ok(caplog):
    class R:
        returncode = 1
        stdout = ""
        stderr = "Error: no such table"

    with patch.object(host_isol, "_nft", return_value=R()):
        assert host_isol.teardown_host_queue() is True


@pytest.mark.unit
def test_qnum_busy_detects_foreign_queue():
    ruleset = "add rule inet some_table output tcp dport 220 queue num 220 bypass\n"
    with patch.object(host_isol, "_nft", return_value=MagicMock(returncode=0, stdout=ruleset)):
        owner = host_isol.qnum_busy(220)
    assert owner is not None and "queue num 220" in owner


@pytest.mark.unit
def test_qnum_busy_ignores_our_table():
    ruleset = "table inet blockchecks_host { queue num 220 bypass }"
    with patch.object(host_isol, "_nft", return_value=MagicMock(returncode=0, stdout=ruleset)):
        assert host_isol.qnum_busy(220) is None


@pytest.mark.unit
def test_queue_bound_reads_proc(tmp_path):
    """Live-bind via /proc portid (AUDIT §16: stdout marker flushes on exit)."""
    class FakePath(str):
        def exists(self):
            return True

        def read_text(self, *a, **kw):
            return "220 1081018     0 2 65531     0     0        0  1\n"

    with patch.object(host_isol, "Path", FakePath):
        assert host_isol.queue_bound(220) is True
        assert host_isol.queue_bound(221) is False

    class DeadPath(str):
        def exists(self):
            return True

        def read_text(self, *a, **kw):
            return "220 0     0 2 65531     0     0        0  1\n"

    with patch.object(host_isol, "Path", DeadPath):
        assert host_isol.queue_bound(220) is False


@pytest.mark.unit
def test_hostify_conf_text_filter_mark_injection():
    """PROBE_MARK>0 (binary 1.0.5) adds --filter-mark mirroring the nft mark."""
    text = "--filter-tcp=443\n--qnum=200\n"
    out = host_isol.hostify_conf_text(text, qnum=220, desync_mark=0x40000000, probe_mark=0x20000000)
    assert "--qnum=220" in out
    assert "--fwmark=0x40000000" in out
    assert "--filter-mark=0x20000000/0x20000000" in out
    # no accumulation of foreign mark lines
    assert out.count("--filter-mark=") == 1
    # probe_mark=0 → no filter-mark line at all
    out_off = host_isol.hostify_conf_text(text, qnum=220, desync_mark=0x40000000, probe_mark=0)
    assert "--filter-mark" not in out_off


@pytest.mark.unit
def test_hostify_conf_text_replaces_foreign_filter_mark():
    text = "--filter-mark=0x1234\n--qnum=200\n"
    out = host_isol.hostify_conf_text(text, qnum=220, desync_mark=0x40000000, probe_mark=0)
    assert "--filter-mark" not in out


@pytest.mark.unit
def test_resolve_probe_isol_rejects_mark_overlap(monkeypatch):
    """PROBE_MARK & DESYNC_MARK != 0 → hard error (canon §6, no silent fix)."""
    from blockchecks.engine import config

    class Args:
        probe_isol = "host"

    monkeypatch.setattr(config, "PROBE_MARK", 0x40000000)
    monkeypatch.setattr(config, "DESYNC_MARK", 0x40000000)
    with pytest.raises(ValueError, match="overlaps DESYNC_MARK"):
        config.resolve_probe_isol(Args())


@pytest.mark.unit
def test_qnum_busy_matches_both_nft_renderings(monkeypatch):
    """Native rendering is "queue flags bypass to 220", compat is "queue num
    200" — both must count as busy; our own table never does (AUDIT §16)."""
    ruleset = "\n".join(
        [
            "table ip zapret_200 {",
            "	chain output {",
            "		tcp dport 443 counter packets 198902 bytes 137110534 queue num 200 bypass",
            "	}",
            "}",
            "table inet blockchecks_host {",
            "	chain output {",
            "		meta skuid 996 tcp dport 443 meta mark & 0x40000000 == 0x00000000 ct original packets 1-15 meta mark set 0x20000000 queue flags bypass to 220",
            "	}",
            "}",
        ]
    )
    monkeypatch.setattr(host_isol, "_list_ruleset", lambda: ruleset)
    # compat rendering of a FOREIGN table → busy
    assert host_isol.qnum_busy(200) and "zapret_200" in host_isol.qnum_busy(200)
    # native rendering in OUR table → not busy (attach/teardown own it)
    assert host_isol.qnum_busy(220) is None
    # native rendering in a foreign table → busy
    foreign = ruleset.replace("table inet blockchecks_host", "table inet foreign_host")
    monkeypatch.setattr(host_isol, "_list_ruleset", lambda: foreign)
    assert host_isol.qnum_busy(220) and "foreign_host" in host_isol.qnum_busy(220)
    # absent queue → None
    assert host_isol.qnum_busy(221) is None
