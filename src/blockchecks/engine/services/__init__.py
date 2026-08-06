"""Runtime services — nfqws2 lifecycle, netns pool, bridge IPC, batch probe, run control.

Single public entry point for process/resource services; keeps ``engine`` root
for generators, runners, matrix, store and config.
"""

from __future__ import annotations

from blockchecks.engine.services.batch_probe import (
    BatchContext,
    BatchJobAccumulator,
    BatchProbeConfig,
    BatchProbeResult,
    BatchScheduler,
    ProbeBackend,
    ProbeBatchService,
    RunnerProbeDeps,
)
from blockchecks.engine.services.firewall import Firewall
from blockchecks.engine.services.lua_bridge import (
    BridgeEvent,
    BridgePaths,
    BridgeSession,
    LuaBridge,
    NetnsGoneError,
    blockchecks_lua_init_lines,
    bridge_worker_session,
    build_bridge_conf,
    chunk_strategies,
    stage_blockchecks_lua,
    strategy_text_from_item,
    teardown_all_bridge_shm,
    write_bridge_conf,
)
from blockchecks.engine.services.metrics import (
    MemoryMonitor,
    MemorySample,
    compute_leak_slope,
    find_nfqws2_pids,
    process_rss_bytes,
    process_vms_bytes,
)
from blockchecks.engine.services.netns_pool import NetNsPool
from blockchecks.engine.services.nfqws2 import Nfqws2Manager, inject_debug_and_daemon, start_daemon
from blockchecks.engine.services.nfqws2_settle import (
    nfqws2_running_in_ns,
    wait_nfqws2_ready,
)
from blockchecks.engine.services.probe import invoke_curl_probe_worker, probe_request_dict
from blockchecks.engine.services.run_control import (
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
    "stage_blockchecks_lua",
    "start_daemon",
    "strategy_text_from_item",
    "teardown_all_bridge_shm",
    "wait_nfqws2_ready",
    "write_bridge_conf",
]
