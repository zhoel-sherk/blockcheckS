# blockcheckS Changelog

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
