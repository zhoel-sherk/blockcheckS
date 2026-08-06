# blockcheckS Changelog

## 1.2.1a — unreleased

### Added — Lua bridge (hot-swap nfqws2 per batch)

- **`--lua-bridge`** — persistent nfqws2 daemon per netns worker. Strategies hot-swapped
  via `/dev/shm` IPC (`strategy.id` + `strategy.gen` atomically published by Python,
  read by `scan_pick` Lua orchestrator on each ClientHello). Eliminates per-strategy
  `pkill`/`start_daemon`/`settle` cycle — amortized from 0.2s/test to 0.0004s/test.
- **`--bridge-batch N`** (default 500, max 2000) — strategies per bridge conf window
- **`--lua-bridge-compare`** — dual-run classic + bridge, log verdict drift
- **`--lua-extra`** — extra `--lua-init=@` paths for custom Lua hooks
- **`ProbeBatchService`** (`engine/batch_probe.py`, 484 lines) — unified batch-probing
  engine with two backends: `classic` (per-strategy daemon) and `lua_bridge`
  (persistent daemon with shm IPC)
- **Lua scripts** (`lua/blockchecks/`):
  - `init.lua` — 50ms timer fallback poll
  - `scan_bridge.lua` — `scan_pick` orchestrator (deterministic strategy-by-id)
  - `write_ipc.lua` — NDJSON event writer (`APPLIED`, future `STRATEGY_FAIL`)
- **Python IPC** (`engine/lua_bridge.py`, 413 lines):
  - `LuaBridge` — atomic publish/drain/teardown per netns
  - `BridgeSession` — boot → probe N strategies → shutdown lifecycle
- **Tests:** `test_lua_bridge.py` (96 lines), `test_lua_bridge_runner.py` (23 lines),
  `test_batch_probe.py` (169 lines), `test_batch_probe_runner.py` (54 lines)

### Changed

- `netns_pool.py` + `run_control.py` — teardown bridge shm on worker release / campaign stop
- `config.py` — `get_blockchecks_lua_scripts()`, `SHM_BASE`, `DEFAULT_BRIDGE_BATCH`
- `MANIFEST.in` — include `lua/blockchecks/*.lua`

### Fixed

- `async_runner.py` — `test_batch_tcp` delegates to `ProbeBatchService` (classic or bridge)
- `main_phases.py` — `_run_tcp_sequential_bridge()` for bridge path
- `generators/custom.py` — `UserMatrixGenerator` now supports `--user-matrix -` (read strategies
  from stdin), unblocking the `--lua-bridge-compare` integration tests (9/9 pass live)
- `cli/cliapp.py` — `SystemExit` carrying a string message (e.g. the active-run lock
  `bs stop` hint) is printed to stderr with rc=1 instead of crashing `int()` with a
  `ValueError` traceback; removed the shadowing local `import sys`

### Live-verified (this pass)

- `bs full` smoke: TCP 9 PASS / HTTP 123 PASS (flowseal, `--max-timem 2`), conf-export path ok
- `bench-settle`: 5×4 settle/curl grid all PASS, `settle_profile.json` written
- `bs stop` graceful (SIGTERM + wait, times out on in-flight subprocess probe →
  hints `--force`) and `bs stop --force` (SIGKILL, clears `run.lock`)
- Integration suite `tests/integration/ -m integration` — **9 passed** (requires a clean
  `run.lock`; leftover `bs scan` from an interrupted run makes tests fail fast)

---

## 1.1.0 — 2026-08-05

First stable release after alpha (`1.1.0a1`). Quality gates, CliApp CLI, baked blobs, Flowseal matrix expansion, `bs stop`, P0 perf defaults.

### Added (Flowseal unified + baked blobs)
- **Repo `blobs/`:** Flowseal+custom binaries committed; default `BLOB_DIR` prefers in-repo path (no download)
- **`FlowsealGenerator`:** full bat-technique axes (multi/split/fds/hf/md/syndata/tls_mod/QUIC/UDP); >1000 OK
- **`flowseal-fast`:** curated technique shortlist (not ALT2-branded)
- **Cookbook:** [docs/cookbook/blobs.md](docs/cookbook/blobs.md) — how to add a blob

### Added (todo debt close)
- **M8:** `bs full` default `--tcp-sources` includes `flowseal`
- **Matrix:** `repeats=4`; TTL overflow `256`/`512` on full axes; Flowseal multi-blob `r=4`
- **Phase 7:** ipfrag `disorder` / `next` / fuller pos; aliases `ipfrag_tcp`/`ipfrag_udp`; UDP multiline dual `--lua-desync`
- **V2-1:** pair/udp/full fan-out across discovered voice endpoints (`domain@ip:port` pair keys)
- **V2-3:** `scripts/voice_smoke.sh`
- **P5-1:** `python -m blockchecks.provider_import --seed-db PATH`

### Fixed (CLI / CliApp)
- **Short flags restored** on CliApp path (`-d`, `-M`, `-c`, …) via `cli_shortcuts` + `case_sensitive=True`
- **Bare `--generate`** again expands to `custom,configs` (argv preprocess before CliApp)
- **`bs --help`** shows one-line blurbs per subcommand (from argparse `help=`)
- **`write_secure_text`** moved to `engine.secure_io` (no longer dead in voice_discovery)

### Fixed (dpi-stack audit DS1)
- **Composite UDP qnum:** multiport `50000:50100` → `NFQUEUE_UDP` (Wave4 regression)
- **`test_batch_tcp` order:** `asyncio.gather` preserves strategy input order (pair filters)
- **curl_cffi hygiene:** `Session` + `with`, catch `RequestsError`; wire `read_timeout` via `LOW_SPEED_*`; DoH via Session
- **DAO latest-row:** `count_tcp_passes` / `domain_pass_stats` / `v_coverage` / `v_latest_run`; `get_best_udp` += THROTTLED; `get_best_pairs` dedupe
- **Generators:** `tls13` protocol metadata; `UserMatrixGenerator.protocol`; udp_quic/game/multiblob via `resolve_blob_path`
- **Keenetic circular scaffold:** `--out-range=-s34228` / `--in-range=-s5556` / `--in-range=x`
- **Voice:** Discord WS `match/case`; sing-box `@asynccontextmanager`; `--full-voice` messaging (gateway path)

### Changed (dpi-stack audit DS2)
- Shared `blob_cli_line` / `append_blob_cli_lines` / `extract_blob_names` in `blob_aliases`
- UDP family registry start (`udp_discord`/`quic`/`game`/`multiblob`)
- Status/verdict maps (tls/http3/dns audit); CLI dispatch maps; `PreflightOptions.from_args`
- `Nfqws2Manager` settle via `wait_nfqws2_ready`; `tls_clienthello` alias; user presets preferred

### Added
- **1.1.0a1 (alpha):** public `engine.probe.invoke_curl_probe_worker`; `--preset` / `-M` path jail; token refuse world-writable + `write_secure_text`
- **E3:** `engine.nfqws2.start_daemon` (+ `inject_debug_and_daemon`); async/composite use public API; `Nfqws2Manager` remains for sync/foreground
- **H2–H8 / migrate:** export reuses open store; AQ `filter_resume` gather; `--prolog-content`; DoH rotate; sing-box lock; `./state.db` → XDG migrate
- **Wave4:** `BLOCKCHECKS_POOL` / low-RAM soft-cap for `--parallel`; NFQUEUE_* in async+composite; `--queue-bypass` on composite; ELF arch check; `presets/domains/pi2.txt`
- Docs: architecture rewrite (DoH → preflight → AQ → curl subprocess → store; NetNsPool scale); B7 todo corrected (not required for netns parallel>4)

### Notes
- Xeon smoke (`-M gp-verified --max 24`, curl-parallel 1): `--parallel 4` ≈13.7s wall, `--parallel 8` ≈15.0s — with ≤8 strategies wall time is dominated by 5s FAIL timeouts + netns pool create; larger matrices benefit from more workers (architecture already isolates per-netns).

### Changed
- README: table of contents, badges, hero section, humor/jargon
- docs: presets README counts corrected; architecture module map expanded; database refs updated; glossary +15 terms; troubleshooting added to guide; blobs tier-1 clean-up

### Release polish (1.1.0 final)
- **`bs stop`** / `--stop`: graceful shutdown via `run.lock` (SIGTERM → flush → export)
- **VPS-2:** single CliApp subcommand dispatch (fixes accidental double `full` run)
- **P0 perf:** default `db_batch=500`, `settle_slack=3s`, nfqws2 foreground sleep 0.1s
- **Packaging:** repo `blobs/*.bin` included in sdist via `MANIFEST.in`

---

## 1.0.2 — 2026-08-03

### Fixed
- XDG: correct `settings.example.toml` priority docs; `finalize_store_args` always fills `out_dir`
- Export/shortlists defaults → `~/.local/share/blockcheckS/` (legacy `state/` still used if non-empty)
- `subprocess_env` preserves `PYTHONPYCACHEPREFIX` from caller `base`
- DAO: `flush()` uses `BEGIN IMMEDIATE` + rollback; `get_best_pairs` includes THROTTLED
- Removed dead `get_passing_pairs`; added indexes `(strategy_id,domain)` / `pair_results(domain)`

### Changed
- tmp-scripts cleanup: keep helpers in `dev/`, `strategy_debug_probe.py` → `scripts/`

## 1.0.1 — 2026-08-03

### Added
- **System deps check** (`engine/system_deps.py`): warn on missing `sudo`/`ip`/`iptables`; resolve nfqws2
- **Auto-fetch zapret2**: when nfqws2 missing, download official `bol-van/zapret2` release (sha256-verified)
  into `~/.local/share/blockcheckS/zapret2/` (+ `bin/nfqws2` symlink); lua + blobs seeded from the archive
- CLI: `--no-fetch-deps`, `--offline`, `--skip-deps-check`; env `BLOCKCHECKS_FETCH_DEPS`, `BLOCKCHECKS_LUA_DIR`

### Fixed
- nfqws2 daemon temp leak (`bs_nfq_*` unlink after settle)
- Campaign `chown_db` hardcoded user → `getpass.getuser()`
- `reclaim_sudo_ownership` now logs WARNING on chown OSError
- Hardcoded `/opt/zapret2/lua` paths → `LUA_INIT_DIR` / `get_lua_init_scripts()`
- Packaging: `requirements.txt` / `requirements-dev.txt` synced with `pyproject.toml` (incl. tomli)

### Docs
- Bilingual legal disclaimer in README
- Install contract: host `/opt/zapret2` **or** XDG auto-vendor

## 1.0.0 — 2026-08-03

Первый production-ready релиз: mass-scan DPI-стратегий для zapret2/nfqws2 с curl_cffi,
netns-изоляцией, adaptive queue и XDG layout.

### Added

- **CLI:** `bs` (tcp / udp / scan / pair / composite), `bs full`, `bc-nfconf`
- **AQ + time limit:** `--adaptive`, `--fan-out`, `--max-timeh` / `--max-timem`, graceful export on stop
- **BC2/GP curl repeats parity:** `--repeats` (1–10), `--parallel-repeats`, `--repeats-mode fast|stable`
- **B2 multi-domain fan-out:** `--curl-parallel` with googlevideo solo batches
- **Secure DNS + preflight:** DoH pre-resolve, DNS audit, IP-block cross-test (Phase 9)
- **Export:** keenetic + raw nfconf via `bs full` / `bc-nfconf`
- **Matrix M5–M7:** reverse/triple fake pairs, `http_tls_dual`, `udp_multiblob`
- **Global BC2 parity:** expanded foolings (`badsum`, IPv6), presets `bc2-parity-*`, fair-share `--max`
- **XDG layout:** `~/.config/blockcheckS/config.toml`, `~/.local/state/blockcheckS/` (state.db, export, logs, shortlists), `~/.cache/blockcheckS/`
- **DAO:** `engine/store/` — `RunStateStore` / `SqliteRunStore`; `db_logger.py` → deprecation shim
- **Docs:** `docs/cookbook/gp-bridge.md`, repeats glossary, `docs/package.md`, onboarding split
- **Scripts:** `scripts/release_smoke.sh` (Fryazino gate + B5 shortlist round-trip), `scripts/flag_campaign.py`

### Changed

- Version `0.3.0` → `1.0.0`
- `bs scan` — adaptive queue + time limit + optional `--out-dir` export
- `bs tcp` — `--repeats`, `--parallel-repeats`, `--repeats-mode`, `--max-timem`
- Runtime state moved from `~/.local/share/` to `~/.local/state/` per XDG spec
- Roadmap consolidated in `docs/todo.md` (removed root `research.md` / `GOALS.md` stubs)
- `--pair-max` applies to `bs full` only (not `bs pair`)

### Fixed

- Content validation redirect suffix match, curl timeout cap, HTTP/3 probe, CDN IP-block detect
- SQLite `busy_timeout=5000`, MANIFEST.in presets coverage, matrix default TCP sources
- DPI fake patterns single source; duplicate strategies/domains in presets
- `bs pair --adaptive`: run UDP pair matrix after AQ TCP (was TCP-only)
- Curl worker wall timeout scales with `--repeats` (`worker_wall_timeout`)
- AQ `pop_batch` solos googlevideo (match B2 `fanout_batches`)
- Pair resume: **completed-set only** from `pair_results` (idx skip removed — unsafe with parallel pairs)
- `bs full` pair phase passes `--resume` checkpoint + fingerprint
- `family_needs.finish_family` clears needs for `fakedsplit` / `fakeddisorder`
- THROTTLED counts as working for export / coverage / pair selection
- Pair rebuild preserves THROTTLED via `get_working_tcp_details` / `tcp_results_from_details`
- Removed orphan `pair_runner` / `pair_manager`; composite uses JSON curl worker
- Netns base allowlist; resolv.conf via `tee` (no `bash -c`)
- `ensure_strategy` sets `busy_timeout`; GV tiny 206 no longer auto-PASS
- SQLite views `v_working_tcp` / `v_coverage` / `v_latest_run` treat THROTTLED as working
- Sudo→user DB reclaim (`reclaim_sudo_ownership`); composite comma-domain normalize; deadline `stop_event`
- nfqws2 daemon copies config to temp before injecting `--daemon` (no mutate of `configs/*.conf`)

### Quality

- Unit tests via `pytest -m "not integration"`; `ruff check src tests` clean
- Fryazino release smoke + flag campaign product gates (BC2 parity markers, pair resume, shortlist/nfconf)
- Install contract: editable/checkout required for `configs/` (ONB-7); blobs on host `/opt/zapret2/blobs/`
