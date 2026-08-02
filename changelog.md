# blockcheckS Changelog

## Unreleased — audit fixes (post-1.0.0)

### Fixed
- `bs pair --adaptive`: run UDP pair matrix after AQ TCP (was TCP-only)
- Curl worker wall timeout scales with `--repeats` (`worker_wall_timeout`)
- AQ `pop_batch` solos googlevideo (match B2 `fanout_batches`)
- Pair resume: completed-set from DB + checkpoint `(tcp_idx, udp_idx)` (not lexicographic labels)
- `bs full` pair phase passes `--resume` checkpoint + fingerprint
- `family_needs.finish_family` clears needs for `fakedsplit` / `fakeddisorder`
- THROTTLED counts as working for export / coverage / pair selection
- Removed orphan `pair_runner` / `pair_manager`; composite uses JSON curl worker
- Netns base allowlist; resolv.conf via `tee` (no `bash -c`)
- `ensure_strategy` sets `busy_timeout`; GV tiny 206 no longer auto-PASS

## 1.0.0 — 2026-08-02

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
- **XDG layout:** `~/.config/blockcheckS/config.toml`, `~/.local/state/blockcheckS/` (state.db, export, logs, shortlists), `~/.cache/blockcheckS/`
- **DAO:** `engine/store/` — `RunStateStore` / `SqliteRunStore`; `db_logger.py` → deprecation shim
- **Docs:** `docs/cookbook/gp-bridge.md`, repeats glossary, `docs/package.md`, onboarding split
- **Scripts:** `scripts/release_smoke.sh` (Fryazino gate + B5 shortlist round-trip)
- **CI:** GitHub Actions unit job + optional `workflow_dispatch` integration placeholder

### Changed

- Version `0.3.0` → `1.0.0`
- `bs scan` — adaptive queue + time limit + optional `--out-dir` export
- `bs tcp` — `--repeats`, `--parallel-repeats`, `--repeats-mode`, `--max-timem`
- Runtime state moved from `~/.local/share/` to `~/.local/state/` per XDG spec
- Roadmap consolidated in `docs/todo.md` (removed root `research.md` / `GOALS.md` stubs)

### Fixed (audit)

- Content validation redirect suffix match, curl timeout cap, HTTP/3 probe, CDN IP-block detect
- SQLite `busy_timeout=5000`, MANIFEST.in presets coverage, matrix default TCP sources
- DPI fake patterns single source; duplicate strategies/domains in presets

### Quality

- **249** unit tests; `ruff check src tests` clean
- Fryazino release smoke: `logs/release_smoke_20260802_132958/` — 34 TCP PASS, AQ 61.8% first-pass-before-50%, shortlist + B5 round-trip OK
