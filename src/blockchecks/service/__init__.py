"""Runtime services: nfqws2, netns pool, bridge IPC, batch probe, run lock."""

from __future__ import annotations

from blockchecks.service.batch_bridge_probe import run_tcp_check_bridge
from blockchecks.service.batch_models import (
    BatchContext,
    BatchProbeConfig,
    BatchProbeResult,
    ProbeBackend,
    RunnerProbeDeps,
)
from blockchecks.service.batch_scheduler import BatchJobAccumulator, BatchScheduler
from blockchecks.service.batch_service import ProbeBatchService, warn_fanout_bridge_once
from blockchecks.service.firewall import Firewall
from blockchecks.service.lua_bridge_ipc import BridgeEvent, BridgePaths, LuaBridge
from blockchecks.service.lua_conf import (
    blockchecks_lua_init_lines,
    build_bridge_conf,
    stage_blockchecks_lua,
    write_bridge_conf,
)
from blockchecks.service.lua_netns import NetnsGoneError
from blockchecks.service.lua_session import (
    BridgeSession,
    bridge_worker_session,
    chunk_strategies,
    strategy_text_from_item,
    teardown_all_bridge_shm,
)
from blockchecks.service.metrics import (
    MemoryMonitor,
    MemorySample,
    compute_leak_slope,
    find_nfqws2_pids,
    process_rss_bytes,
    process_vms_bytes,
)
from blockchecks.service.netns_pool import NetNsPool
from blockchecks.service.nfqws2 import Nfqws2Manager, inject_debug_and_daemon, start_daemon
from blockchecks.service.nfqws2_settle import (
    nfqws2_running_in_ns,
    wait_nfqws2_ready,
)
from blockchecks.service.probe import invoke_curl_probe_worker, probe_request_dict
from blockchecks.service.run_control import (
    ActiveRunInfo,
    clear_active_run,
    is_pid_alive,
    read_active_run,
    register_active_run,
    request_graceful_stop,
    run_session,
)

__all__ = [
    "ActiveRunInfo",
    "BatchContext",
    "BatchJobAccumulator",
    "BatchProbeConfig",
    "BatchProbeResult",
    "BatchScheduler",
    "BridgeEvent",
    "BridgePaths",
    "BridgeSession",
    "Firewall",
    "LuaBridge",
    "MemoryMonitor",
    "MemorySample",
    "NetNsPool",
    "NetnsGoneError",
    "Nfqws2Manager",
    "ProbeBackend",
    "ProbeBatchService",
    "RunnerProbeDeps",
    "blockchecks_lua_init_lines",
    "bridge_worker_session",
    "build_bridge_conf",
    "chunk_strategies",
    "clear_active_run",
    "compute_leak_slope",
    "find_nfqws2_pids",
    "inject_debug_and_daemon",
    "invoke_curl_probe_worker",
    "is_pid_alive",
    "nfqws2_running_in_ns",
    "process_rss_bytes",
    "process_vms_bytes",
    "probe_request_dict",
    "read_active_run",
    "register_active_run",
    "request_graceful_stop",
    "run_session",
    "run_tcp_check_bridge",
    "stage_blockchecks_lua",
    "start_daemon",
    "strategy_text_from_item",
    "teardown_all_bridge_shm",
    "wait_nfqws2_ready",
    "warn_fanout_bridge_once",
    "write_bridge_conf",
]
