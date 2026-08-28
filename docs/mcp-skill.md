---
name: blockcheckS-mcp
description: "Use when working with blockcheckS (DPI strategy tester for zapret2/nfqws2): checking long-term campaign status, querying found strategies, triage, generating nfqws2 router configs, or using MCP tools get_series_status / query_strategies / triage_domain / dbg_* / generate_router_config."
---
# blockcheckS MCP — tools and workflows

blockcheckS is a mass DPI-strategy tester for zapret2/nfqws2. The MCP server
(`bs-mcp`) connects it to opencode / Claude / Cursor. This skill is a cheatsheet:
which tool to use when. For complete API and transport contracts, see [docs/api.md](api.md) and [docs/mcp.md](mcp.md).

## 1. MCP tools (22)

### No daemon required (always work, including during an A→F run)
| Tool | What it does |
|---|---|
| `get_series_status` | Campaign status from run.lock + state.db: pid, uptime, progress, `backend` (always `lua_bridge`), `adaptive`, `quarantined[]`, `live`, `domain_pass_counts` |
| `get_log_tail` | Disk tail of `python` / `campaign` / `nfqws2` (`LOG_SOURCES`) |
| `get_live_events` | Live probe journal (`applied` per event) + `current_probe.json` |
| `query_strategies(domain, status, limit)` | Top strategies: latest PASS/THROTTLED with `bridge_applied IS NULL OR = 1` |
| `get_campaign_domains_summary` | PASS/FAIL/attempts per domain (PASS counts skip `bridge_applied=0`) |
| `get_presets(kind)` | List strategy/domain presets from presets/ |
| `dbg_validate_strategy_syntax(strategy)` | Offline validation; warns on digit blob ids; escaped lines rename `4pda`→`b4pda` |
| `get_nfqws2_status` | nfqws2 running? pids, binary, ELF arch vs host (read-only) |
| `get_zapret2_config` | Active /opt/zapret2/config profiles (read-only) |
| `list_zapret2_blobs` | Blobs under /opt/zapret2 + blockcheckS aliases |
| `get_ipset_status` | ipset scripts + live kernel tables |
| `get_provider_profile` | XDG `data_block/` provider snapshot |

### Hybrid
| Tool | What it does |
|---|---|
| `generate_router_config(target_os, domains)` | nfqws2 .conf via daemon if up; else offline PASS SQL (`bridge_applied IS NULL OR = 1`) |

### Require the `bs serve` daemon (root, netns)
| Tool | What it does |
|---|---|
| `get_service_status` | Daemon status (pool, uptime, active_run) |
| `triage_domain(domain)` | Preflight Triage: L3/DNS/TLS/QUIC + generator recommendations |
| `find_working_strategy(domain, profile, time_limit_sec)` | AQ search for working strategies (≤60s) |
| `dbg_probe_raw(domain, strategy)` | Single probe, `dry_run_db=True` by default |
| `dbg_inspect_lua_ipc(domain, strategy)` | Lua bridge event trace (APPLIED / rst_in / ttl) |
| `dbg_dump_pool_state` | netns pool, nfqws2 PIDs, stale run.lock |
| `stop_campaign(wait, force=False)` | `bs stop` via run.lock; if no campaign, stops **`bs serve`** |
| `set_debug_mode` | Python DEBUG + nfqws2 debug via daemon |
| `probe_strategy(domain, strategy)` | Alias for `dbg_probe_raw` (dry_run_db=True) |

## 2. Fair-exclusion rule (IMPORTANT)

While a long A→F run is active (`get_series_status.active == true`), the
`bs serve` daemon is NOT running (it refuses to start because of run.lock). So:

- **Daemon tools return** `Connection refused` — this is NOT an error, it is expected.
- **Use disk tools**: `get_series_status`, `get_log_tail`, `get_live_events`,
  `query_strategies`, `get_campaign_domains_summary`, `get_presets`,
  `dbg_validate_strategy_syntax`, Layer C host inspectors, `get_provider_profile`.
- Stop the campaign with **`stop_campaign`** or CLI **`bs stop`** (same `run.lock` path).
- Check run status via `get_series_status` (NOT `get_service_status`).

## 3. Workflow chains

### Run status (during A→F)
```
get_series_status → active/running/uptime_h/progress/tcp_pass/quarantined/live
get_live_events → recent probes (applied flag)
```

### Find strategies for a domain
```
triage_domain(domain) → generator recommendations
find_working_strategy(domain, profile="fast", time_limit_sec=30) → top
dbg_probe_raw(domain, strategy) → single check (dry_run_db=True)
```

### Export router config
- MCP: `generate_router_config(target_os="keenetic", domains=[...])` (PASS + APPLIED/NULL)
- CLI (strict APPLIED=1): `bs harvest-batch -d <db> --top 20`
- CLI (router files): `bc-nfconf --db <db> --out-dir <dir> --ipset` (same APPLIED/NULL filter as get_best_*)

## 4. Key paths

- Daemon socket: `$BLOCKCHECKS_STATE_HOME/blockcheckS/blockchecks.sock`
  (default `~/.local/state/blockcheckS/`)
- Campaign DBs: `<PROJECT_DIR>/logs/run_*.db`
- Strategy presets: `<PROJECT_DIR>/presets/strategies/` (`-M <name>`)
- Custom Lua: `<PROJECT_DIR>/lua/custom/` (dupfake, manifest.toml)
- Documentation: `<PROJECT_DIR>/docs/`

## 5. Gotchas

- `get_series_status` reads run.lock + state.db directly — no daemon, never writes the DB.
- `dbg_probe_raw` defaults to `dry_run_db=True` — does not pollute the production DB.
- MCP TCP ranking drops `PASS` with `bridge_applied=0`; harvest-batch still requires `=1`.
- `dbg_validate_strategy_syntax` is offline — use it before sending a strategy to netns.
- Strategy presets use protocol extensions: `.tls/.txt/.http/.quic/.udp` (`.tls` wins).
- Custom Lua functions are registered in `lua/custom/manifest.toml` (included/excluded params).
