## 1.4.1 — GP-contract: multi-domain scan, run-scoped summary, canonical args (2026-09-03)

Отправная точка связки с GP-control-plane (`discovery_engine=blockchecks`).
Никаких изменений движка пробы; только внешний контракт и версия.

### CLI: мульти-домен scan/pair

- `bs scan` / `bs pair`: `-d/--domain` **повторяемый** — тестируется весь
  набор (раньше оставался последний). Альтернативы: `--preset`. GP шлёт по
  `-d` на домен.
- Разрешение доменов сложено в единый preset-канал (dedupe `-d*` + preset),
  затем фильтр DoH/denylist работает по всему набору.

### Результаты / внешний контракт

- `run_summary_<ts>.json` для scan/pair теперь содержит `run_id` (`runs.id`) и
  полный `domains` список — оркестратор скоупит чтение либо через `run_id`,
  либо свежим `--db` на run.
- Зафиксирован канонический источник аргументов: `strategies.name` = слаг,
  `strategies.config_path` = строка nfqws2 (`SqliteRunStore.get_strategy_config`);
  GP-экспорт/harvest обязан брать args из `config_path`/`bc-nfconf`, не из name.
- Документация: `docs/api.md` §10a (GP-движок, карта «единица → вызов»),
  `docs/cookbook/gp-bridge.md` (мульти-домен, harvest, engine switch),
  `docs/database.md` (slug vs args, run_summary).

### Тесты / CI

- Новые unit: повторный `-d` (parser + fold в DNS-набор), канонический
  slug→config_path. Тест-файлы новые не добавлялись — шард-списки не менялись.

---

## 1.4.0 — campaign lua_bridge-only, CLI slim, run-scoped resume (2026-08-28)

Campaign TCP is **lua_bridge only**. Classic per-strategy nfqws2 restart is gone
from `scan`/`pair`/`full`. One-shot `bs tcp` / `composite` / fan-out still use
`start_daemon`. Harvest/smoke/`campaign_pass` require HTTP OK **and**
`bridge_applied=1`. Ranking (`get_best_*`, `v_coverage`, MCP
`query_strategies` / `generate_router_config`, `bc-nfconf`) keeps
`bridge_applied IS NULL OR = 1` (oneshot NULL stays; lua PASS without APPLIED
is dropped). Harvest is still the strict `=1` export.

### Campaign / CLI

- Removed `_run_classic_batch` / classic AQ. `--classic`, `--probe-backend classic`,
  `BLOCKCHECKS_PROBE_BACKEND=classic` warn and map to lua_bridge. `--lua-bridge`
  is a deprecated no-op. `--lua-bridge-compare` removed.
- Backend flags stripped from `bs tcp`/`udp` help. Series D retired (use A).
- `--no-settle-profile` alias for long runs. GP `--http-off`/`--http3-off` share
  dests with `--no-http`/`--no-quic`.
- `--reprobe-failed N` retries infrastructure FAIL on resume (not DPI FAIL).
- `--max-timem` / `--max-timeh` graceful stop (+ `--export-on-stop` on full/pair).
- `harvest-batch --exclude-quarantined`. `gc --db-days N` (opt-in row retention;
  skipped while `run.lock` exists).

### Integrity / IPC / quarantine

- Campaign PASS = `campaign_pass` (`http_ok ∧ bridge_applied`). Lua HTTP-200
  without APPLIED is stored as FAIL (`fail_phase=no_bridge_applied`).
- IPC: `mkdir` `/dev/shm/blockchecks/<ns>` uses sudo fallback (chmod-only was
  not enough when overflow-uid owned the parent). Heartbeat-fence / bind-retry /
  stdout capture unchanged from 1.3.9.
- Quarantine **seed_from_rows only with `--resume`**. Infra FAIL (`dev/shm`,
  `Permission denied`, …) does not count toward `quarantine_min`. Re-sync
  `queue.excluded_domains` after seed.

### MCP / export

- `stop_campaign` calls `bs stop` (`run.lock`) first; daemon socket stop only
  if no campaign.
- `dbg_validate_strategy_syntax` warns on digit blob ids and rewrites
  `4pda`→`b4pda` in escaped conf lines (`is_valid` follows errors, not warnings).

### Architecture

- `PairMatrixRunner`, probe executors, `BridgeWorkerPool`.
- `in_ns_workers` / `test_runner` live under `service/`.
- `nfqws2_launcher` + HostFirewall split from `Nfqws2Manager`.
- Store: long-lived writer, `runs`/`run_id`, `epoch_ms`/`settle_ms`, WAL checkpoint.
- Resume skip keys are **run_id-scoped** (matching fingerprint). Same file without
  `--resume` opens a new run and does not skip prior PASS keys.

### Tests / CI

- ~1938 unit + 165 quality; shards cover launcher/harvest-gate files.
- Live smoke tiers; `integration-safe` resume test uses `begin_run` + PASS keys.

## 1.3.9 — harvest-batch, host hygiene, bridge integrity (2026-08-25)

### Host hygiene (P0–P2)

- `bs gc` (default dry-run): prune aged `run_summary_*`, harvest dirs, zapret2-dl tarballs, `bs_voice_cache_old_*`; keep last 50 `nfqws2_*.log`. Never deletes `week_cov*`.
- `scripts/cleanup_env.sh --orphans-only [--exclude-prefix=…]`: rmdir `/etc/netns/<ns>` after `ip netns del`; skip `run.lock` pid. Full script remains between-campaigns only (host `pkill -9 nfqws2`).
- No silent legacy export fallback: `resolve_user_output_dir` stays on DATA; `[paths] legacy_export = true` to opt in. `ensure_dirs` no longer mkdir `STATE/export`, blob-cache, or `STATE/presets`.
- `./state.db` → XDG migrate is **off** unless `--migrate-cwd-db` / `BLOCKCHECKS_MIGRATE_CWD_DB=1` / `[paths] migrate = true`.
- Denylist auto-append writes `~/.config/blockcheckS/presets/domains/denylist.txt` (bundled file is seed-only).
- Single zapret2 root: `BLOCKCHECKS_ZAPRET2` / `ZAPRET2_ROOT` (`config.ZAPRET2_ROOT`). `BLOCKCHECKS_SETTINGS` has no implicit `../dpi-tester/settings.ini` default.
- Lua IPC prefers `setfacl u:nobody` + 0770/0660; logs a warning if it must fall back to 0777/0666. Do not chmod live `/dev/shm/blockchecks/bs-p-*` mid-campaign.
- Silent `except` in live_events / MCP offline nfconf / heartbeat now `log.warning`.

### GGC under selector control + nfqws2 stdout capture (2026-08-25, вечер)

- **SNI-пул googlevideo** (`engine/ggc_pool.py`, `BLOCKCHECKS_GGC_MODE`):
  `synthetic` (основной; точная мимикрия формата rrN---sn-<code>, вкл. дефисы
  `sn-1-ien4` и суффиксы `-30ze`, no-repeat окно), `real` (yt-dlp харвестер
  `dev/ggc_harvest_real.py`, TTL 6ч), `fixed` (legacy базлайн).
- **Цепочка IP** вместо мёртвого хардкода: per-host dns.db → `[google]
  fallback_ips`/`BLOCKCHECKS_GGC_IPS` → кэш `CACHE/ggc_ips.json` → legacy.
  Обнаружено: старые константы мертвы (`rr5---sn-5goeenes` = NXDOMAIN по
  Cloudflare DoH; `74.125.108.234` не отвечает) — детектор ходил в труп.
- `tcp_results.probe_host` (авто-миграция) — SNI каждой пробы для GROUP BY.
- **nfqws2 stdout capture** (#300): bind-ошибки печатаются в stdout, не в
  `--debug=@file`; оба пути запуска пишут `logs/nfqws2_out_<tag>_<ts>.log`
  (глоба gc keep-50). Живой репро: мгновенный рестарт на той же очереди →
  `nfq_create_queue(): Operation not permitted` в захвате. Итог дня: смерти
  демонов происходят ПОСЛЕ успешного bind, без вывода и без следов в ядре
  (не OOM/segfault) — гипотезы см. AGENTS.md.
- **bind-retry для nfqws2** (#300 финал): pkill освобождает NFQUEUE-сокет с
  задержкой >2с — ребут умирал с `nfq_create_queue(): Operation not permitted`
  (видно только благодаря stdout-захвату). start_daemon детектит причину по
  out-capture и ретраит бинд до 5 раз с backoff. Живой эффект: week-yt прогон
  после фикса 486/865 PASS (56%) против 0/11000 до него.
- Follow-up (аудит): `[google].mode` читается из config.toml; `~/` в `[paths]`
  под sudo → home SUDO_USER; classic `test_tcp()` пишет `probe_host`;
  `get_best_tcp` / MCP `query_strategies` отдают колонку; `test_ggc_pool.py` в CI S1.
- Follow-up (runtime): `_bridge_iptables_add` снова abort boot (`IptablesError`)
  если `-A`/`-C` NFQUEUE не встали — иначе heartbeat живой, а трафик queue-bypass.
- `paths._resolve_xdg`: под sudo (euid=0+SUDO_USER) XDG резолвится в home
  реального юзера — root-запуски больше не прячут run.lock/логи в /root.

### bs harvest-batch: strategy candidates → dpi-tester / GP-access-control-plane

New read-only CLI subcommand exporting the harvest of a finished campaign as
validation-ready material:

```
bs harvest-batch -d logs/week_cov.db --top 20 --min-domains 2 [--proto tcp] [--write-confs]
```

- `harvest_<ts>/batch.txt` — lines `dom1,dom2,… | <lua-desync-core>` in
  dpi-tester `run_batch()` format; `manifest.json` — schema
  `blockchecks.harvest/v1` with per-candidate coverage/latency and per-domain
  saturation metrics (`saturated >=85%` of top candidates pass a domain —
  informative for ranking, valuable anyway for router configs).
- `--write-confs` — self-contained raw nfqws2 `@file` bundles (conf +
  blobs/lua via `write_export_bundle`) per candidate for Tier-2 full
  validation of finalists.
- Core module `src/blockchecks/harvest_batch.py` is pure/read-only (stdlib
  sqlite3 `mode=ro`, window-function latest-row-per-pair), quarantine-aware,
  ranks by domain coverage then latency — same policy as
  `generate_router_config`. Digital-leading blob identifiers are renamed
  (4pda→b4pda) BEFORE validity filtering, so strategies like
  `multisplit:…seqovl_pattern=4pda` survive instead of being dropped
  (unresolved: 1823→0 on live week_cov.db). Intended seam for future move to
  GP-access-control-plane.
- CLI wiring in both layers (argparse dispatch + pydantic CliApp model).

### Bridge integrity: "PASS without APPLIED" root-caused & self-healing (2026-08-24)

During week_cov S1 ~50% of PASS rows carried `bridge_applied=false`
("bridge PASS without APPLIED event", ~11k of 22k). Investigation
(`dev/diag_bridge_boot.py`, instrumented mini-scans) found three independent
mechanisms, all fixed:

- **Silent blob drop in bridge confs** (root cause #1): custom/config strategies
  referencing blobs only via `seqovl_pattern=`/`--blob=` lines lost them at
  bridge-conf build when unresolvable (`p4da` alias missing) — nfqws2 died
  per-packet on the unknown blob, wrote no APPLIED, and the probe ran clean:
  false PASSes on baseline-open domains (discordcdn.com showed 62% "pass").
  Fix: `p4da`→`tls_clienthello_4pda_to.bin` alias; `append_blob_cli_lines` now
  logs loudly and returns unresolved names; `ConfigFileGenerator` static-validates
  every `.conf` and skips broken ones with a WARNING instead of poisoning batches.
- **IPC publish race** (root cause #2, minor): `strategy.id` was committed before
  `strategy.gen`, so Lua's fence could accept `(new id, stale gen)` — correct
  desync applied but APPLIED carried a stale gen and was filtered by
  `drain_events`. Fix: commit order is now gen → cmd → id → ready (any partial
  state fails the fence); `drain_events(expect_id=...)` additionally rescues
  events by strategy id.
- **Mid-batch daemon death** (root cause #3): settle waits for process
  visibility only; under load Lua init/NFQUEUE bind lags, and a daemon can also
  die on queue-bind conflict — remaining probes run queue-bypassed. Fixes:
  - **Readiness fence**: after each batch boot a synthetic probe must produce
    any bridge event, else the daemon reboots once;
  - **Zero-event retry**: a probe with zero bridge activity (live scan_pick
    always emits APPLIED) triggers one daemon reboot + probe retry;
  - `scan_pick` APPLIED events now carry `matched=N`; `matched=0` (nothing
    executed) no longer counts as applied.

Supporting changes:

- **`tcp_results.bridge_applied` column** (nullable; NULL=classic/legacy):
  suspicious PASSes are persisted, queryable, and distinguishable in exports.
  Plus previously dead columns `bridge_batch_id`/`bridge_gen` are now populated.
- **Domain quarantine** (new): domains with `0 PASS in >= N attempts` stop being
  scheduled mid-run (AQ exclude + fan-out/sequential filters), logged loudly,
  persisted to the new `quarantined` table, seeded from DB on `--resume`.
  Flags: `--no-quarantine`, `--quarantine-min N` (default 300),
  `--quarantine-auto-denylist` (appends to `presets/domains/denylist.txt`).
  MCP `get_series_status` exposes `quarantined[]`.
- **MCP fix**: `get_series_status.adaptive` reported False because it checked
  legacy `--adaptive/--fan-out` argv flags; AQ is default-ON — now reports True
  unless `--no-adaptive` is present.
- **Host safety**: `scripts/cleanup_env.sh` matched bare `^veth*` links (Docker's
  naming!) and flushed FORWARD — could tear networking off live containers
  (bitmagnet). Now restricted to `vh-/vn-` prefixes with targeted rule deletion,
  plus sweeps orphaned `10.200.x` MASQUERADE rules from SIGKILLed runs
  (68 duplicates found on the host); `netns_pool` NAT rules are `-C`-guarded.
- Diagnostics script: `dev/diag_bridge_boot.py` (boot-race harness), WARN lines
  carry raw-event tails for post-mortem.

### Quarantine ordering fix: seeded domains never reached the queue (2026-08-25, hotfix)

- `build_adaptive_queue` snapshotted `exclude_domains` BEFORE
  `seed_from_rows` filled the quarantine object — DB-seeded dead domains
  kept being probed (~40% of probes in week_cov S1 restart). Fixed by
  re-syncing `queue.excluded_domains` after seeding; verified live:
  quarantined-probe share dropped to 0, PASS attribution clean
  (0 "without APPLIED" in fresh window), all 4 daemons stable.

### Run-mechanics audit follow-up: heartbeat, live observability, curl_cffi 0.16.1 (2026-08-25)

Post-audit quality sprint (mechanics of the run itself):

- **Daemon heartbeat (Lua↔Python)**: `init.lua` timer writes `heartbeat`
  (epoch s) every 200ms; `LuaBridge.heartbeat_age()` + per-probe freshness
  check in `batch_service` — a dead/wedged nfqws2 is rebooted BEFORE burning
  a curl timeout on queue-bypassed clean traffic.
- **Honest wssize**: the lua_bridge "wssize retry" was a silent no-op
  (`strategy.cmd` is not parsed by Lua — extra desync never applied). Removed
  from the bridge path (classic retry with real conf injection stays).
  Remaining known gap: implement Mode-A cmd parsing or drop the file entirely.
- **Live observability without restart**:
  - `service/live_events.py`: per-probe NDJSON journal
    (`~/.local/state/blockcheckS/logs/events_live.jsonl`, auto-rotate @32MB)
    + atomic `current_probe.json`; written by both batch backends.
  - MCP: new **`get_live_events(tail, domain)`** tool (disk-based, works
    during A→F) and `get_series_status` → `live` field.
  - `tail -f events_live.jsonl` = physical run view in real time.
- **curl_cffi 0.15.0 → 0.16.1** (vendored wheel; PyPI unreachable via pip on
  this network — direct download): studied new API first. Findings:
  - `impersonate="chrome"` now resolves to chrome150 (auto-latest);
    ExtraFingerprints gained `http3_sig_hash_algs`/`http3_tls_extension_order`
    (QUIC ClientHello fingerprint knobs); http/3 fingerprints + UDP SOCKS5
    proxy since 0.15; `curl-cffi update` refreshes fingerprints in place.
  - New env knob `BLOCKCHECKS_IMPERSONATE` (default stays pinned `chrome124`
    for cross-run comparability). A/B mini-scan critical preset:
    chrome124 46 PASS vs chrome150 42 PASS (~100 probes each — parity within
    noise; latency mixed). Keep pin, override for experiments.
  - QUIC reality check on Fryazino: NO real QUIC egress — curl reports
    `http_version=3` (ALPN offer) while zero UDP:443 hits the wire, and
    forced v3-only times out everywhere including Cloudflare. The earlier
    "discord.gg works over h3" reading was this false positive.
- **`dev/capture_quic_blob.sh`**: capture a REAL QUIC v1 Initial from any
  impersonate target into an nfqws2 UDP fake blob (Electron-like Chromium QUIC
  fingerprint for the Discord preset). Host-mode (temporary /etc/hosts pin +
  tcpdump + built-in Initial extractor, self-tested). On Fryazino run it on
  the Selectel VPS (clean QUIC path) and copy the blob back — recipe inline.

---

## 1.3.8 — TLS bypass classification, Discord redirect handling, MCP tools overhaul (2026-08-23)


- **TLS bypass classification fix**: Added `_TLS_BYPASS_PROOF_STATUSES` (401, 403, 404)
  for TLS probes with small/empty bodies so valid server responses through TLS
  are classified as PASS instead of false-positive DPI drops.
- **Discord family redirect handling**: Added `_DISCORD_FAMILY_APEXES` to
  `tcp_tls.py` and `_hosts_related` to correctly treat redirects across Discord
  domains (e.g. `dl.discordapp.net` → `discord.com`, `discord.gg` → `discord.com`)
  as valid bypasses.
- **MCP server enhancements**:
  - Universal log path resolution `_latest_run_logpath` supporting any campaign (`week_cov`, etc.).
  - Robust `_resolve_db_path` resolving across `info.cwd`, `PROJECT_DIR`, and `cwd`.
  - Added `proto="tcp"|"udp"` support in `query_strategies`.
  - Added new `get_campaign_domains_summary` tool for real-time per-domain stats.
  - Added offline fallback in `generate_router_config` when daemon is busy.
  - Added new `get_provider_profile` tool for inspecting `data_block/` profiles and DNS caches.
- **IP/CIDR catalogs** (`presets/ipset/*.txt`): sinkhole, CGNAT, CDN families,
  expect, fallbacks. User overlay `~/.config/blockcheckS/presets/ipset/`.
  Config `[ipset]` in `settings.example.toml`. Distinct from `bc-nfconf --ipset`.
- **XDG-only provider store**: runtime writes go to
  `~/.local/share/blockcheckS/data_block/providers/<slug>/` (one-time migrate
  from the git submodule). `bs data-block [--out] [--git]` materializes
  a git-ready snapshot; `--data-block-sync` uses the same path.
- Bump 1.3.8.

---

## 1.3.7 — CLI modernization, Discord-UDP, Cursor MCP, preflight (2026-08-22)

### CLI Modernization & Simplification

- **Strict inversion convention**: protective features are ON by default; disable
  explicitly with `--no-adaptive`, `--no-preflight`, `--no-ech`, `--no-wssize`.
  `--quick` keeps prolog-only preflight (skips deep baseline/IP-block/port-block).
- **Adaptive queue (AQ)**: default ON for `scan` / `pair` / `full`; sequential
  matrix only with `--no-adaptive`. `--adaptive` kept as alias (no-op when default).
- **ECH**: `--no-ech` replaces `--disable-ech` (alias retained); ECH ON by default.
- **Wssize fallback**: ON by default; `--no-wssize` skips TLS 1.2 wssize retry.
- **Run profiles** (`--profile smoke|fast|20h`) in `scan`, `pair`, `full`:
  `smoke` = max 20 + fast + quick preflight; `fast` = max 100 + fast;
  `20h` = full scan-level + resume + no-preflight + no-wssize + fan-out
  (long-term series A→F bundle).
- **Centralized terminal output** (`blockchecks.terminal`): `NO_COLOR`,
  `FORCE_COLOR`, `CLICOLOR_FORCE`, `TERM=dumb`; colorama init at CLI boundary;
  `error()` / `warn()` on stderr.
- **Typed execution spec** (`engine/run_spec.py`): `RunSpec` + `CampaignContext`
  replace untyped `argparse.Namespace` propagation across campaign phases.
- **Unified campaign parser** (`add_campaign_args()`): single flag builder for
  `scan` / `pair` / `full` — removes duplicate definitions and syncs defaults.

### Discord-UDP coverage, MCP, variant G

- Discord-voice UDP vs QUIC/game: `generate_udp` retags `udp_voice`; pair
  defaults `--udp-sources custom,standard_udp`; `--udp-sources game` is explicit.
- Netns UDP probe: filter covers probe port, iptables `--dport` matches, no early
  `--queue-bypass`, coexist waits for two nfqws2 (q200+q201), pair writes `log_udp`.
- `udp_discord` full scan expands repeats/TTL; cores include `--filter-udp=50000-50100`.
- Cursor MCP: `~/.cursor/mcp.json` / `.cursor/mcp.json` → `.venv/bin/bs-mcp`.
- `dev/smoke_20min.sh` step 7: host pinned EP PASS + netns `udp_results` PASS.
- Variant G: `scripts/run_variant.sh G 20` (`bs pair` Discord-UDP loop, 20h);
  not part of sequential A→F.
- Bump 1.3.7.
- **DNS**: UDP:53 ≠ DoH is a warning, not a hard abort. Probes already use
  DoH IPs + auto-pin (`CURLOPT_RESOLVE`); `--allow-dns-hijack` remains only
  for sinkhole/bogon answers. Google anycast ranges include `173.194.0.0/16`
  so `googleapis.com` 172.217 vs 173.194 is not a false HIJACK.

### Preflight CLI, prune, `--dpi-diag`

- `bs preflight`: standalone triage (no strategy matrix); DNS audit reused once
  via `PreflightOptions.dns_audits`; CDN/Fastly prefixes are not `ip_blocked`.
- `--no-preflight` / `--quick` skip UDP 16KB so prior `udp_blocked` is kept;
  `--no-preflight` also skips L3 persist.
- Prune: `viable_foolings` is an AQ boost, not an exclusive gate. `dead_foolings`
  only from explicit SSL **35** / `wrong_version` (not a generic handshake
  timeout). Empty dead list persists as `[]` — no invented `badsum`/`send`.
- `--dpi-diag` (opt-in on `preflight` / `scan` / `pair` / `full`): SNI whitelist,
  FAT keepalive, l4-25 (pin IP), Siberian, CIDR-WL, AS/CGNAT notes. Overlay
  writes `[dpi_diag]` / `viable.hosts`; **does not** set `dns_sinkhole`. Without
  the flag, prior `viable.hosts` are not loaded into generators. FAT/l4-25 need
  a successful first HEAD/handshake before DETECTED.

### Packaging / container (2026-08-21)

- Wheel install smoke in `podman` `python:3.12-slim`: `PROJECT_DIR=/usr/local/blockchecks`,
  configs/blobs resolve (PKG-C1).
- Local GitHub CI via act + rootless podman socket: `lint-and-quality` and
  unit shards S1/S2/S3 (PKG-C2/C3). Do not run monolithic `pytest tests/` in CI.
- README: Docker/Podman microguide; wheel data-files are self-contained (1.2.1a+).
- CI S3 includes `test_cli_modernization`, `test_profiles`, `test_run_spec`,
  `test_terminal`.

### Backlog harvest

Closed checklists formerly duplicated in `docs/todo.md` (1.0.x–1.3.7 CLI,
lua_bridge L-batch, serve SVC-1…10, VPS-1/2, A→F scripts, memory P0/P1 slots)
already live in the version notes below. `docs/todo.md` kept only open work:
lua/host-mode/GP, Pi2 RSS/CPU, research ideas, RL/ML.

### Fixes after bump

- `--no-voice` skips UDP generation and the pair phase (`main_phases`). Previously
  `bs full --no-voice` still built ~50 UDP strategies and ran `--pair-max` (default
  200) — `test_e2e_full_smoke` hit the 180s wall.
- `find_strategy` workers come from the serve netns pool size, not a missing
  `runner.pool_size` default of 4.
- Export ranking keeps `latency_ms=0` (was treated as missing → worst rank).
- Silent provider/blob fallbacks log a warning instead of swallowing errors.
- `data_block` providers on disk: `default` + `llc_trc_fiord`.
- GitHub `USER_AGENT` follows `blockchecks.__version__`.

### scripts / dev split

- `scripts/`: campaign runners (A→F/G), systemd install, blobs, presets, host
  `cleanup_env.sh`. See `scripts/README.md`.
- `dev/`: smokes, `gate_all` / `mutmut_gate`, benches, debug probes. See
  `dev/README.md`. Not packaged, not run by CI.

## 1.3.6 — GP integration, probe fixes, smoke (2026-08-18)

- `bs serve --http-port`: authenticated HTTP bridge (Bearer token; `--http-token`
  / `BLOCKCHECKS_HTTP_TOKEN` / `config.toml [http]`) + routes `/api/status`,
  `/api/telemetry`, `/api/results`, `/api/probe`, `/api/triage`,
  `/api/find-strategy`, `/api/generate-config`, `/api/stop`, `/api/events` (SSE).
- `GET /api/results`: best PASS strategies from a run DB (TCP/UDP/QUIC).
- Fix: TLS 401/403/404 now classify as PASS (TSPU bypass proven by real server
  answer); live bridge progress (no frozen `[0/N]`); TSPU stub markers `eais`,
  `warning.rt.ru`; GGC `Server: Bandaid`; custom label collision.
- MCP LAYER C: zapret2 host status tools.
- `scripts/smoke_20min.sh`: 20-min functional test (~90% run paths).
- Bump 1.3.6.

# blockcheckS Changelog

## 1.3.5 — hotfix: mutmut double -m + family expander guard (2026-08-17)

**Hotfix.**

- `[tool.mutmut].pytest_add_cli_args_test_selection` no longer passes `-m`
  (it collided with `[tool.pytest.ini_options].addopts`' `-m`, producing a
  duplicate `-m` usage error → `BadTestExecutionCommandsException`). addopts
  is auto-applied by pytest, so a bare `tests/unit` selection is enough.
- `test_mutmut_no_survivors`: targeted error message when mutmut exits 4
  (usage error) instead of a raw traceback.
- `test_family_expanders_all_have_methods`: every `_FAMILY_EXPANDERS` entry
  resolves to a real `_fam_*` method (Jules/vulture flag them as unused, but
  they are called via `getattr` in `_expand_family` — all 31 verified).
- Bump 1.3.5.

## 1.3.4 — hotfix: wheel presets on Debian/Ubuntu (2026-08-17)

**Hotfix.** On Debian/Ubuntu system Python `sys.prefix` is `/usr` but distutils
installs wheel data-files under `/usr/local/blockchecks` — `_resolve_project_dir`
only probed `sys.prefix/blockchecks`, so strategy/domain presets and configs
were unreachable in wheel installs (e.g. fresh VPS).

- `_resolve_project_dir`: also probe `sys.prefix/local/blockchecks`.
- Test: `_resolve_project_dir` finds the `/usr/local/blockchecks` data dir.
- Bump 1.3.4.

## 1.3.3 — hotfix: vendor blobs symlinks (2026-08-17)

**Hotfix.** On machines without `/opt/zapret2` (e.g. a fresh VPS), the
auto-fetched zapret2 vendor created blob symlinks pointing at the staging
directory, which is deleted after the atomic move — every blob dangled and
nfqws2 failed with "cannot access file .../blobs/stun.bin".

- `_seed_blobs_from_fake` now creates **relative** symlinks
  (`../files/fake/...`) so they survive `staging.rename(VENDOR_ROOT)`.
- Test: symlinks valid after the rename; missing fake dir → 0.

## 1.3.2 — ipset export + RPi2 support + LLC Fiord (2026-08-16)

**Release 1.3.2.** Features:

- **`bc-nfconf --ipset`**: add nfqws2 IP filter from data_block DNS cache,
  provider-agnostic (all providers under `data_block/providers/`). Small sets
  inline via `--ipset-ip`, large as `user.ipset` + `--ipset=@`; IPs aggregated
  to CIDR via ip2net when available. Uses nfqws2-native flags (no zapret2
  scripts).
- **Raspberry Pi 2+ (armv7l) installable without gcc**: dropped `psutil`
  (no armv7l wheels) → stdlib `/proc` readers (`metrics.py`: VmRSS/VmSize,
  `/proc/*/ns/net`), race-safe. `scripts/setup-standalone.sh` + CI
  `armv7l-smoke` (docker linux/arm/v7) + `docs/install-rpi.md`.
- **Public naming**: replaced `Fryazino.net` references with public
  "LLC Fiord" (preset filenames `fiord-*`, manifest, docs, changelog).

## 1.3.1 — hotfix + refactor (2026-08-16)

**Hotfix + structural refactor.** Alpha→master merge (8 commits). Verified:
1155 unit, 118 quality, 22 integration (sudo E2E), ruff + vulture clean;
clean-venv wheel install (version 1.3.1).

### Fixed
- **run:** incremental `TcpProgress` (main_phases) — a long bridge run no longer
  shows a frozen `[0/N]`; stream-triage context-manager bug — curl_cffi >=0.15
  `Response` has no context-manager protocol (`run_stream_triage_probe` now uses
  plain `get()` + `iter_content` + `close()`).
- **audit:** `sqlite_store.flush` race — rows drained atomically under
  `_flush_lock` before any await (a concurrent `log_tcp` from a parallel worker
  can no longer be erased by `clear()` mid-commit); `last_err` cleared on
  successful retry; failed flush re-queues rows. curl_probe False PASS closed
  (same-host blockpage 30x, 304 without conditional, text/html on binary-API
  probes). preflight triage phase casing fixed (`FailPhase._value2member_map_`).
  CliApp now applies `config.toml` `[paths] db/out_dir` + `[run]` and calls
  `finalize_store_args` — nfconf export works on the main `bs` path.
- **bridge:** nfqws2 drop-privilege (nobody/65534) writable dir `0777` +
  `strategy.*` files `0666` (was root-only 0755/0644 → daemon died / APPLIED
  never written); pkill/start race drain (`_wait_nfqws2_gone`) before binding a
  replacement nfqws2.

### Refactor (behavior-preserving)
- **conf:** single-source nfqws2 arg sanitization in `engine/conf_builder.py`
  (`split_cli_args`, `escape_conf_lt`, `sanitize_arg_for_conf`,
  `build_filter_lines`, `add_blobs_from_strategy`); `nfqws_config.py` and
  `service/lua_conf.py` import from it. The `<` escape (audit S3) now applies in
  the classic/sync path too.
- **generators:** `standard.py` decomposed 1583 → ~880 LOC facade +
  `engine/generators/families/{split,fake,tamper}.py` + `_helpers.py`
  (`StrategyParams` typed axes). Output byte-identical (parity verified).
- **workers:** new `engine/base_worker.py` (`Worker` ABC +
  `BaseInNsWorker` + `WorkerContext`); subprocess entries `_probe_worker` /
  `_curl_probe_worker` folded into `in_ns_workers.py` as
  `python -m blockchecks.engine.in_ns_workers --mode curl|udp` (old modules kept
  as back-compat proxies).

### Chore / Test
- **presets:** `presets/manifest.toml` registry (27 strategies + 11 domains) +
  `scripts/gen_presets_manifest.py` + `tests/unit/test_presets_integrity.py`.
- **integration:** `tests/integration/test_sqlite_concurrency.py` (8 concurrent
  writers, 0 row loss) + `test_netns_leak.py` (netns/veth/nfqws2/run.lock
  cleanup).

### Upgrading from 1.3.0
```bash
pip install -U blockchecks
# No DB migration; same CLI. Bridge IPC dirs auto-fix permissions on boot.
```

---

## 1.3.0 — stable (2026-08-15)

**Stable release.** Branched from `alpha` (99 commits). Verified: 1097 unit,
113 quality, 17 integration (sudo E2E), ruff clean; clean-venv wheel install.

### Release highlights

- **Preflight Triage (Wave 1 + Wave 2)** — deterministic DPI interference
  profile built before the strategy scan:
  - `FailPhase` enum (32 tokens) + `TriageProfile` (dns/sinkhole, unbypassable
    L3, stream-stall 7-42KB, QoS throttle, QUIC drop, TLS fingerprint block,
    post-quantum awareness) — feeds generators (branch pruning) + bandit/S0
    context vector.
  - L3/L4 SYN/ICMP probe (`checkers/l3_probe.py`), raw QUIC Initial probe
    (`checkers/quic_raw.py`), streaming stall probe, multi-profile TLS
    fingerprint (chrome/firefox/safari/bare), Lua TTL-RST feedback.
- **`bs serve`** — resident on-the-fly probe server (Unix socket core + HTTP
  bridge), fair exclusion via run_control (423 busy when campaign active).
- **Memory: adaptive queue RSS 442MB → ~82MB** (slots + lazy traits + shared
  keys); sqlite WAL + flush retry (no "database is locked"); AQ weights
  persist on crash/deadline.
- **Domain isolation** for sequential bridge scan (no all-youtube false
  positives); long-term series A→F + boot-resume systemd.
- **Blobs: +8** from Flowseal 2026 (5ka, rutube, funpay, cloudflare, alfabank,
  rzd) — verify_blobs 31 OK.
- **XDG hardening:** state/logs/blob-cache dirs 0700; legacy `state.db`
  migration to XDG.
- **pytest-xdist + pytest-timeout** (`-n 2 --dist loadfile`) — full unit in
  ~40s.

### Breaking / migration
- `classify_fail_phase` moved from `service/probe_service.py` to
  `engine/fail_phase.py` (single source; service re-imports).
- `tcp_results` gained `fail_phase` column (auto-migration via schema).

### Upgrading from 1.2.1a
```bash
pip install -U blockchecks
# run state auto-migrates (state.db → XDG); existing DBs get fail_phase column.
```

---

## 1.2.1a — unreleased (alpha history)

### Wave 2 — Lua TTL-RST feedback + raw QUIC Initial probe

**Lua TTL-RST (structured feedback):** scan_bridge already emitted
`STRATEGY_FAIL {reason=rst_in, ttl=...}` but it was dropped. Now:
- `BridgeEvent.ttl` parsed + `is_rst_in()`.
- `batch_bridge_probe` attaches `bridge_rst_in` / `bridge_rst_in_ttl`.
- `_tcp_result_from_data` classifies → `TcpTestResult.fail_phase=TLS_RST_AT_SNI`
  + `rst_in_ttl` (in-memory; no schema change).

**Raw QUIC Initial probe (`checkers/quic_raw.py`):** one-shot UDP :443 probe
with real baked QUIC Initial blob (fallback synthetic RFC 9000). Classifies
PASS (server replied) / QUIC_DROP (silent TSPU drop) / UDP_BLOCKED (ICMP port
unreachable). Integrated into preflight → `TriageProfile.quic_drop/udp_blocked`.
Verified live: cloudflare.com→PASS, youtube.com→QUIC_DROP (LLC Fiord fact).

**Blobs:** +8 from Flowseal repo (2026) — `tls_5ka`/`quic_5ka` (5ka.ru,
PR #16589), `quic_rutube` (rutube.ru), plus `quic_funpay`/`quic_cloudflare`/
`quic_alfabank`/`tls_funpay`/`tls_rzd` (PR #16591, Hellcat-95, closed — taken
from commit 8c35287). Aliases added, `verify_blobs` 31 OK. New QUIC/TLS blobs
wired into flowseal pools (full tls12 6493→10183, quic 168). `blobs/README.md`
rewritten with per-blob description + PR sources.

Tests: 1095 unit (+9), 113 quality, ruff clean.


### Preflight Triage (Wave 1) — deterministic DPI interference profile

- `engine/fail_phase.py`: `FailPhase` enum (32 tokens) — single source of
  truth for probe failure phase (DNS/L3/SNI/stream-stall/QoS/QUIC). Dynamic
  `http_<code>` members. `classify_fail_phase()` moved here from probe_service.
- `engine/triage.py`: `TriageProfile` (dns_hijacked/sinkhole, unbypassable_l3,
  stall_phase, bandwidth_throttled, quic_drop, TLS fingerprint block,
  post-quantum awareness) + `to_dict`/`to_context` (bandit feature vector).
- `checkers/dns_secure.py`: sinkhole/bogon answer filter (RFC1918/loopback/
  RKN-stub) → verdict `sinkhole`.
- `checkers/l3_probe.py`: L3/L4 classification — L4_SYN_DROP / L4_RST_AT_SYN /
  ICMP_BLOCK (raw ICMP receiver + TCP-connect fallback).
- `checkers/curl_probe.py`: `run_stream_triage_probe` (streaming 7-42KB stall
  + QoS plateau detection) and `run_tls_profile_probe` (chrome124/firefox_120/
  safari_17/bare — fingerprint-block + ClientHello size estimate).
- `preflight.py`: builds `TriageProfile` in `run_preflight_async` (L3 + stream
  + TLS-profile on first domain).
- Generators: `generate(..., triage=None)` — prunes unbypassable L3 (→[]),
  post-quantum ClientHello (drops static numeric splits, keeps markers).
  Round-robin interleave bug fixed (idx increment placement).
- DB: `fail_phase` column in tcp_results (migration) + `log_tcp` persists it;
  `TcpTestResult.fail_phase` classified on failure.
- Tests: fail_phase, l3_triage, stream_triage, triage pruning (+18). pytest-
  xdist + pytest-timeout added (`-n 2 --dist loadfile`, `--timeout=90`).
  1086 unit pass.


### Service layer: `bs serve` — resident on-the-fly probe server

Unix-socket core (`asyncio.start_unix_server`, 0 deps) + thin HTTP bridge
(stdlib) for external apps (gp-control-plane). Holds a warm NetNsPool.

- `service/probe_service.py`: `ProbeService(pool_size)` — start/probe/stop,
  `busy()` via run_control; `ProbeResult` contract with `fail_phase`
  classifier (`classify_fail_phase`: connect_timeout / tls_handshake_reset /
  dns_resolve / http_redirect / http_<code> …).
- `service/server.py`: `ProbeServer` — Unix socket JSON-line server +
  optional HTTP bridge (`serve_http`); POST /probe, GET /status, POST /stop.
- CLI `bs serve` (`--pool/--bridge-batch/--classic/--http-port`).
- **Fair exclusion**: serve registers run.lock as "serve" (campaigns refuse to
  start while it holds the pool); if a campaign owns the lock, /probe returns
  423 `{status: busy, reason: campaign_active, active_run}` (fail-fast). E2E
  verified both directions.
- systemd `blockcheck-serve.service` (long-running) + install/uninstall
  updated for both units.
- Tests +7 (probe_service/server handlers). 1037 unit pass, ruff clean.


### Ops: boot-resume systemd + long-run recovery

City power outage killed the run series (SIGKILL → no persist). Recovery plan:
- `--resume` verified across reboot: +13 399 resume skip, DB 13 510→17 014,
  PASS 588→728, adaptive re-accumulating weights.
- `scripts/boot_resume_series.sh`: boots the series ONLY when a non-empty run
  DB exists (no-op otherwise); guarded against double-start.
- `scripts/install_systemd.sh` / `uninstall_systemd.sh` + `systemd/`
  `blockcheck-series.service` (oneshot, boot resume). Installed & enabled.
- Next outage: series auto-resumes on boot.


### Fix: sqlite "database is locked" crash + lost adaptive weights

Long run A crashed at the end with `sqlite3.OperationalError: database is
locked` in `_bridge_worker.flush`, so `persist_adaptive_weights` never ran →
`scan_weights` empty → `--resume` lost the genetic boost and adaptive queue
fell back to sequential pool order (new strategies probed without priority,
0 additional PASS in 8h).

Fixes:
- `_apply_pragmas`: `PRAGMA journal_mode=WAL` + `busy_timeout=30000` (writers
  don't block readers; parallel flushes no longer race).
- `flush()`: retry ×5 on "database is locked" with backoff.
- `_run_tcp_adaptive`: persist weights in `finally` — saved even on crash /
  deadline, so resume keeps the genetic boost.
- `_apply_provider_weights`: pass `strategy_traits(strat)` instead of the
  cluster string as traits (garbage trait-dict entries).
- `MEM_MONITOR_PY_MAX_MIB` 2048 → 512 (config.py).

1030 unit pass, ruff clean. P2 chunking + heartbeat RSS-guard deferred (P0+P1
already 82-286MB stable).


### Fix: run_variant.sh geneva.lua env not reaching tmux session

`export BLOCKCHECKS_LUA_EXTRA` inside the case block did not propagate into
the `tmux new-session` child (tmux server does not inherit parent env) — so
variant B ran without `geneva.lua` (85 `fool=bs_*` strategies probed
blindly). Fixed by embedding the actual value into the tmux command line
(and `sudo -E env`) instead of `\${VAR}` placeholders. Verified: START log now
shows `lua_extra=/home/zhoel/workspace/blockcheckS/lua/blockchecks/geneva.lua`.

**Long-term series A (adaptive, timeout 2) results:** 16 517 probes, 12
domains isolated, **878 PASS** (vs 0 PASS at timeout 1 — LLC Fiord needs ≥2s).
64 PASS from new families (tcp_ack=-66000:tcp_ts_up + TTL, rst, synack,
wssize, gva). data_block 295 → 1 123 PASS.

**--resume verified:** mid-run stop → restart skipped 42 already-tested
(strategy,domain) pairs, tested remaining 69 (11 PASS / 58 FAIL).


### Perf: adaptive queue memory 442MB → ~82MB RSS (P0+P1)

`bs full` held the full strategy×domain matrix (367 932 `AdaptiveJob`) at
start: ~330MB of 419MB RSS. Fixed:
- `@dataclass(slots=True)` on `AdaptiveJob` / `_HeapEntry` / `StrategyItem`
  (dropped `__dict__`, 586→88 B/job, 176→56 B/heap entry).
- `blobs`/`traits` lazy `property` + `functools.cache` keyed on strategy string
  (shared tuple across all 12 domains, immutable) — was per-job lists, now one
  per strategy. Removed dead `cluster` field.
- Shared cached `key` tuple on the job.
- `_rebuild_heap` → list-comp + `heapq.heapify` (2.5× faster rebuild).

E2E smoke: RSS 442 → 82 MB (81% cut) with full 290k-job matrix, 12 domains
isolated, no probe slowdown (queue ops are μs vs s-scale network probes).
1030 unit pass, ruff clean. P2 chunking + heartbeat RSS-guard remain open in
docs/todo.md (now less critical: process fits comfortably in 20h runs).


### Fix: domain isolation for sequential bridge scan (false-positive risk)

`_run_tcp_sequential_bridge` (used by `bs full` without `--adaptive/--fan-out`)
probed **one domain across all 4 netns simultaneously** — the same all-youtube
false-positive pattern we fixed for AQ earlier. Rewritten to parallel workers
with an `active_domains` set: each netns batch is filled strategy-major
(s1×all domains, then s2×…), so parallel netns always probe **distinct
domains**. Gated by `[run] domain_isolate` / `BLOCKCHECKS_AQ_DOMAIN_ISOLATE`
(default on); prints a WARNING when disabled.

Also enables real parallelism for the sequential bridge path (previously 1
netns at a time round-robin).

E2E verified: benchmark.txt 6 domains → 24 probes each (was: 1 domain only).
Unit tests: +2 (isolation overlap check + isolation-off warning). 1030 pass.

Long-term run series A→F now uses this isolation (A uses `--adaptive`).


### Strategy audit: Geneva + nfqws2 + Flowseal coverage (day-5 follow-up 2)

**Research completed** (see AGENTS.md): Geneva CCS'19 strategies.md (24
strategies), nfqws2/zapret2 lua desync catalog (25 functions), blockcheck2
standard (13 scripts), Flowseal zapret-discord-youtube (21 .bat, 186 profiles,
downloaded from Win11 SMB).

**New TCP strategy families (standard.py):**
- `rst_fake` — Geneva 10-15: ACK→RST/RA duplicate on empty ACK
  (`--payload=empty --out-range=s1<d1\nrst[:rstack][:badsum|:ip_ttl|:tcp_md5]`)
  + exotic flag fakes (Geneva 16-18 ≈ FRAPUEN/FREACN/FRAPUN via
  `send:tcp_flags_set=...`). 12 items.
- `synack` — Geneva 23: SYN→SYN+ACK split handshake
  (`synack`, `synack_split:mode=syn|synack|acksyn`). 6 items.
- `wssize` — blockcheck2 companion `wssize:wsize=1:scale=6` (+multisplit combo).
- `geneva_fool` — escape-hatch for non-expressible Geneva tampers via custom
  `fool=` Lua hooks (`lua/blockchecks/geneva.lua`): bs_dataofs, bs_iplen,
  bs_corrupt_load, bs_corrupt_wscale, bs_corrupt_uto. Requires
  `BLOCKCHECKS_LUA_EXTRA=/…/blockcheckS/lua/blockchecks/geneva.lua` (colon-joined
full paths). 18 items.

**Flowseal gap-fix (flowseal.py):**
- badseq-increment 2/1000/10000000 → `tcp_seq=N` (ALT4/ALT8/FTA_ALT2)
- `tls_mod=none` (ALT8/ALT10)
- hostfakesplit-mod `altorder=1` (ALT3)
- `syndata\nmultidisorder` link (ALT5)
- `fake\nmultisplit` without split params + badseq (ALT4)
- split-pos `2,sniext+1` (ALT7)
- pool: 6338 → 6493 tls12 items

**Numeric axes synced with def.inc + Flowseal:**
- `FAST_FOOLINGS_TCP` += tcp_seq=-3000, tcp_seq=1000000, tcp_flags_unset=ACK,
  tcp_flags_set=SYN (Geneva seq/flag fools promoted from full-only to fast)
- `ALL_REPEATS`/`FAST_REPEATS` += 14 (Flowseal ALT5 UDP-game)
- `ALL_BLOBS_TCP` reordered: 0x00000000 null blob first (capped scans reach it)
- `StandardGenerator` full scan: no per-type budget sharing (full pool now
  emits every family completely; 12 015 → 24 210 tls12 items)

**Tests:** +8 (test_geneva_audit.py) covering all new families + Flowseal gaps.

**Round-robin interleave (standard.py generate):** capped scans now emit one
strategy per family round-robin, so every technique (incl. the new families)
is represented at any `--max` instead of letting the huge `fake` family eat
the budget. Full pool (max≥pool size) still emits everything: 24 210 tls12
items (was 12 015).

**E2E verified (LLC Fiord, --max 30, timeout 2s):** rst_fake (`rst:badsum`),
synack and wssize all produced PASS on youtube.com; no nfqws2 errors across
the 30-strategy scan.


### Architecture: AQ strategy genetics + domain isolation + tuning (day-5 follow-up)

**Adaptive queue works on strategy genetics, not domains.**
- Removed cluster (domain) weight boost from `ScanWeights`. A PASS now boosts
  the strategy's `family` (+1.0), `blob` (+0.5) and extracted **traits**
  (+0.4): repeats / fooling / ttl-bucket / pos / desync technique
  (`strategy_traits()`). Sibling strategies of the same genetics are tested
  next regardless of which domain they target — Geneva-style evolution,
  decoupled from the domain. Previously cluster boost made one domain (e.g.
  youtube) dominate: all parallel netns probed the same domain → false
  positives.
- `AdaptiveJobQueue.pop(exclude_domains=...)` + shared active-domain tracker in
  `_bridge_worker`: with `parallel=N`, the pool always probes **N distinct
  domains** simultaneously (isolated, no all-youtube). Configurable via
  `BLOCKCHECKS_AQ_DOMAIN_ISOLATE` / `[run] domain_isolate` (default on).

**Tuning knobs — all hardcoded timeouts moved to config.**
- New config constants (env `BLOCKCHECKS_*` or `[run]` in config.toml):
  `RETRY_IP_TIMEOUT` (1.0), `PIN_TIMEOUT` (3.0), `YTDLP_TIMEOUT` (20.0),
  `DOH_TIMEOUT` (5.0), `SUDO_WALL_TIMEOUT` (15.0), `HTTP3_TIMEOUT` (3.0),
  `PROBE_DEFAULT_TIMEOUT` (5.0).
- `[run]` now maps: timeout, bridge_batch, adaptive_epsilon, max_timeh/m,
  retry_ip_timeout, domain_isolate. `settings.example.toml` documents all.

**Bridge retry-on-IP removed.** nfqws2 bridge applies the strategy by domain
(scan_pick via shm `strategy.id`); the destination IP does not affect desync
selection. Single IP per probe (was: 2× per-IP timeout on every FAIL).

**Proxy is optional.** Default `SOCKS5_PROXY`/`settings.proxy` is now empty —
probes go **direct** (standard: the strategy must get a legitimate answer from
the server). Enable via env `BLOCKCHECKS_PROXY=...` or `[tools] proxy` in
config.toml. No CLI flag.

**Speed.** `--timeout 1` + no retry-on-IP → FAIL ~1-2s instead of ~7s; E2E
12× faster (~114 jobs/min vs ~9), 4 netns stay isolated across domains.



### Refactor + coverage — v1.2.2 day-5 (85%+ target, pre-release)

- **async_runner god-file split** (1764 → ~330 lines): moved to
  `engine/results.py` (models), `engine/nfqws_config.py` (config builders),
  `engine/in_ns_workers.py` (netns probe workers). async_runner keeps
  AsyncTestRunner + `__all__` re-exports so external imports and monkeypatch
  paths keep working.
- **Coverage 73% → 85%** across 18 core modules: added test_tcp_tls (13),
  test_lua_session (7), test_batch_bridge_probe (6), test_async_runner_methods (7),
  test_in_ns_workers (5), plus retry/config/multi/quic/udp coverage. pytest-cov
  and pytest-randomly added to dev deps (randomly required by mutmut).
- mutmut scoped to 15 modules; mutmut run requires test fixes for mutants/
  cwd (tests reading non-mutated sources) — documented, gate stays
  workflow_dispatch.

### Fixed — v1.2.2 test-plan findings (days 1-4)

- **netns_pool `_get_iface` picked a leftover veth/peer as the out-interface**:
  a leftover UP veth (`vh-bs-p-*-N@ifNNN`) from a prior pool or a concurrent
  `bs` is the first non-lo UP iface, so `iptables -o vh-...@ifNNN` failed with
  "interface name must be shorter than IFNAMSIZ (15)" and netns creation
  aborted (found by the day-4 stress run). `_get_iface` now excludes
  `veth*`/`vh-*`/`vn-*` and any `@`-suffixed (peer) names. +1 unit test.
- **CliApp `--no-*` flags were silently ignored**: pydantic-settings 2.14
  parses `--no-<field>` as a *negation*, so fields literally named `no_*`
  (no_wssize, no_http, no_quic, no_voice, no_secure_dns, no_auto_pin,
  no_settle_profile, …) could never be set True through the CLI — both
  `--no-x` and `--no-no-x` parsed to False. smoke_scan/release_smoke with
  `--no-*` did not actually disable their phases. Fix: `cliapp.main` captures
  `--no-*` flags and `_dispatch_subcommand` re-applies them to the parsed
  subcommand. Verified `--no-quic/--no-voice/--no-http/--no-wssize` → True;
  +1 unit test.
- **Settle profile auto-load could break `bs full`**: a stale
  `/root/.cache/blockcheckS/settle_profile.json` with `curl_timeout=0.5s`
  (from an earlier bench on a faster network) turned every TCP probe into a
  500ms FAIL on throttled LLC Fiord. `auto_load_profile` now rejects profiles
  whose defaults demand `curl_timeout < 2.0` (AUTO_LOAD_MIN_CURL) with a
  warning; explicit `--settle-profile` still forces. +3 unit tests.
- **`--data-block-sync` committed but never pushed**: `maybe_sync_data_block`
  called `sync_commit()` without `push=True`, and under sudo git could not
  find the user's credentials. Now `sync_commit(push=True)` and git runs via
  `sudo -u $SUDO_USER`. Verified live push (origin 58ff6b2). +1 unit test.
- `ProviderStore.write_hosts` merged with the existing hosts file instead of
  overwriting: a run that DNS-audits only a few domains (e.g. benchmark.txt)
  previously wiped unrelated pinned entries (googleapis, googlevideo, youtu.be,
  discordapp, discordcdn). Found via v1.2.2 day-2 E2E when the data_block hosts
  shrank from 13 to 7 domains. +1 unit test.
- `bs tcp --protocol http`: `Nfqws2Manager.start()` always injected
  `--payload=tls_client_hello` + wrapped the whole strategy in `--lua-desync=`.
  For full CLI strategy lines from custom list_http.txt (e.g.
  `--payload=http_req --lua-desync=http_hostcase`) this produced a duplicate
  `--payload` and nfqws2 exited immediately. Now full `--`-prefixed strategies
  are split via `lua_conf._split_cli_args` and not re-wrapped; plain
  `fake:...` strategies keep the default TLS wrap. Verified `bs tcp -d ya.ru
  --protocol http --test custom` → 3/3 PASS; +2 unit tests.

- `--fixed-ip` / `--no-auto-pin` moved to scan/pair only (`add_ip_pin_args`);
  tcp/udp are single-shot sync commands without the AsyncTestRunner auto-pin
  path, so declaring the flags there tripped the dead-CLI-flags gate.
- Integration `test_lua_bridge_compare`: wall timeout 300→500s, per-strategy
  `--timeout 5` (FAIL paths stay short on throttled LLC Fiord), child runs in
  its own process group and `killpg` cleans the whole sudo→bs→nfqws2 tree on
  timeout (no leaked procs / stale run.lock / PID-reuse false conflict);
  `test_lua_bridge_single_strategy` now probes 1 strategy (was silently 10).

### Added — IP pinning (hosts-analog) + retry-on-next-IP vs LLC Fiord per-IP throttling

- **`--fixed-ip <path>`** (env `BLOCKCHECKS_FIXED_IP`): hosts-analog pin file
  (`domain IP` or `IP domain` per line, `#` comments). Default (no flag) is
  **`data_block/providers/<provider>/hosts`** — the same Windows anti-hijack
  hosts file, so one file feeds both blockcheckS and a hand-copied Windows
  hosts. Pinned IPs override DoH order, so the Cloudflare DoH rotation can no
  longer land on a LLC Fiord-throttled discord IP (e.g. `162.159.136.232`).
  See `byedpi_engine.md` §5 Phase 6 diagnosis.
- **Auto-pin at startup**: unless `--no-auto-pin`, the runner probes each
  cached domain's candidate IPs with `fake:blob=stun` (PIN_STRATEGY) and pins
  the first PASS. The provider hosts file is loaded, its *other* domains kept,
  and only **changed** IPs are written back atomically — git stays clean when
  nothing moved. Verified: pin `136.232` (throttled) → auto-swap to `135.232`
  → 3/3 PASS; non-active hosts entries (discord.gg, discordcdn.com, …) kept.
- **Retry-on-next-IP**: on a failed probe, `_run_tcp_check`, `_run_tcp_check_multi`
  and `run_tcp_check_bridge` retry the curl worker against the remaining
  candidate IPs with a short `RETRY_IP_TIMEOUT` (2s) budget; nfqws2/daemon is
  started once. The used IP is recorded in `data["used_ip"]` / `TcpTestResult.used_ip`
  and logged to the DB.
- New `blockchecks.checkers.ip_pin` (bidirectional parse/load/dump/save,
  Windows `IP\tdomain` output); `DnsRunCache` gained `_pins`,
  `set_pins/add_pin/pinned_ip/pins/candidates/domains`.
- Covered by `tests/unit/test_ip_pin.py` (13 tests); full unit suite passes.

### Added — byedpi (ciadpi) install + first selection-speed benchmark

- Installed byedpi v0.17.3 (`ciadpi`) into `~/workspace/byedpi/` — SOCKS5
  proxy, no root. Verified: curl through `socks5h://127.0.0.1:port` → HTTP 200.
- Added `dev/byedpi_bench.py` — standalone benchmark (not the full `--engine
  byedpi`): translates the working nfqws2 slice (fake/blob/hostfakesplit) to
  ciadpi argv, runs curl_cffi through the per-strategy SOCKS proxy, measures
  test/sec; compares with `bs scan --classic` baseline.
- First results (discord.com, 5 strategies): nfqws2 15.19s / 0.33 t/s / 3-5
  PASS vs byedpi 10.72s / 0.47 t/s / 3-5 PASS → **1.19× speedup**, stable;
  nfqws2 classic flaky on LLC Fiord. Documented in `byedpi_engine.md` §5 Phase 6.
- Note: ciadpi `-l <file>` (no `@` prefix, unlike nfqws2 blob syntax).

### Docs — refresh `docs/custom_lua.md` (paths + done/backlog markers)

- Fixed stale module paths after the service-layer refactor:
  `engine/lua_bridge.py` → `service/lua_bridge_ipc.py` (+ lua_conf/lua_session/
  lua_netns), `engine/batch_probe.py` → `service/batch_probe.py`,
  `engine/nfqws2.py` / `engine/netns_pool.py` → `service/…`.
- Marked implemented sections `✅ done` (scan_pick hot-swap §7, smart-fallback
  §6, ProbeBatchService/build_bridge_conf/BridgeSession §9, circular answer §13)
  and ideation `— backlog` (§3–§5, §14). Status banner now reflects reality.
- `lua/README.md` — notes custom_lua.md as the idea source (done + backlog).

### Added — QUIC/HTTP3 via Lua bridge + backend map in lua/README.md

- **QUIC bridge**: `bs full` QUIC phase now groups strategies into a
  `lua_bridge` batch when the backend is lua_bridge (default):
  - `lua_conf._strategy_filter_lines` — new `protocol="quic"` branch:
    `--filter-udp=443 --filter-l7=quic --payload=quic_initial` (UDP qnum).
  - `lua_netns._bridge_iptables_add` — protocol-aware: UDP/NFQUEUE_UDP for quic.
  - `lua_session.BridgeSession.boot` — passes protocol to iptables.
  - `batch_bridge_probe.run_tcp_check_bridge` — `protocol=="quic"` probes via
    `check_http3` in the netns subprocess (was curl-only).
  - `scan_bridge.lua` `bs_l7_ok` accepts `quic_initial`.
- **Classic QUIC fallback unchanged** (`fake→badsum→ip_ttl` in `test_quic`);
  bridge QUIC uses the base strategy (no fallback chain yet).
- **`lua/README.md`** — full backend map: what runs via Lua bridge vs classic
  (TCP batch, QUIC batch vs single TCP, fan-out, pair, UDP voice).
- Tests: `build_bridge_conf` quic branch, `scan_bridge.lua` accepts
  `quic_initial`.

### Fixed — `--classic`/`--probe-backend` accepted on tcp/udp

- `--classic` / `--probe-backend` are now valid on `bs tcp` and `bs udp`
  (previously `unrecognized arguments` — they were only wired into
  scan/pair/full). Extracted `add_backend_args()` (classic + probe-backend)
  shared by all commands; `add_lua_bridge_args()` keeps lua-specific flags
  (bridge-batch/compare/extra) on scan/pair/full only.
- Verified live: `bs tcp --classic` → HTTP 200 PASS; `bs udp --classic` → 30ms
  PASS; `bs scan --classic` → `backend=classic` PASS.
- **Trottling confirmation**: GP control-plane standard discovery on
  discord.com shows pervasive `code=28` timeouts across dozens of strategies
  (LLC Fiord throttling), while fake+tls_mod strategies (`fake_default_tls +
  tls_mod rnd`, `luaexec patmod`) succeed — the same pattern blockcheckS finds
  (`fake:blob=...:tcp_ts=-1000`). Not a blockcheckS bug.
- dead_cli_flags now covers tcp/udp for the new backend dests.

### Changed — QUIC fallback timing + iptables hygiene

- **Fallback variants use a shorter timeout** (`min(timeout, 3.0)`): a TSPU
  drop happens immediately, so waiting a full 5s on each already-dropped
  fallback tripled QUIC wall-time (15s/strategy) under systematic drops.
  Base strategy keeps the full timeout; only fallbacks are quick drop-checks.
- **`_run_quic_check` flushes OUTPUT iptables** before adding the NFQUEUE rule,
  so fallback re-entry in the same netns no longer stacks duplicate rules.
- Tests: `test_quic_http3.py` — fallback uses short timeout for variants (base
  5.0, fallbacks 3.0).

### Added — QUIC fallback chain when the base strategy is dropped

- `test_quic` now tries a fallback chain when a QUIC strategy times out (TSPU
  drop): base `fake:blob=X` → `+badsum` → `+ip_ttl=1`. Disable with
  `BLOCKCHECKS_QUIC_FALLBACK=0`.
- Live diagnosis (2026-08): fake injections **bypass the TSPU** for QUIC — the
  QUIC Initial reaches the CDN (`ngtcp2_conn_writev_*` / `SSL: no alternative
  certificate`, NOT timeout), while `send:ipfrag` (split/disorder) is dropped
  (timeout). `_is_quic_dropped()` distinguishes a full drop from reached-CDN
  errors; `_quic_fallback_variants()` builds the fallback list.
- Tests: `test_quic_http3.py` — fallback variants (+badsum/+ip_ttl, skips
  existing, config/disabled), `_is_quic_dropped` (4).
- `docs/guide.md` QUIC fallback section added.

### Investigated — QUIC/HTTP-3 blocking mechanism on LLC Fiord (2026-08)

- **QUIC as a protocol is NOT blocked**: `check_http3('cloudflare.com')` → 301;
  raw QUIC Initial to a Cloudflare IP gets a reply; QUIC reaches `vk.com` and
  bare `googlevideo.com`.
- **Blocking is by SNI, not by IP**: the same Google rr-range IP
  `74.125.108.234` passes `cloudflare.com` / `cdn.example.com` / bare
  `googlevideo.com` (reach the CDN → certificate error) but **drops**
  `youtube.com`, `www.youtube.com`, `rr*.googlevideo.com` (timeout) on any IP.
  TSPU inspects the SNI inside the first QUIC Initial UDP packet and applies
  per-site rules; blocked SNI → whole UDP session dropped.
- Consequence: GGC-style IP substitution does not help for QUIC; masking the
  SNI to a white domain yields no CDN content. Needs SNI masking or a tunnel,
  not IP substitution. Documented in `docs/guide.md`.

### Added — voice-traffic >16KB preflight check + provider-result → AQ weights

- **Preflight UDP >16KB check** (`preflight.check_udp_16kb`, `PreflightReport.
  udp_16kb_blocked`): during startup, sends a >16KB UDP media burst to a
  discovered Discord voice endpoint to detect whether the TSPU drops the voice
  stream (dpi-detector analogue). Result feeds strategy selection.
- **Provider → AQ weight orchestration** (`adaptive_runner._apply_provider_weights`):
  `build_adaptive_queue` now reads `data_block` pass_strategies
  (`approved_only`) and boosts family/blob/cluster weights for strategies the
  provider already saw pass on the scanned domains — the adaptive scan tests
  the most promising candidates first. Wired into `bs full` AQ path.
- Tests: provider-weight boost + cross-domain skip (`test_adaptive_runner.py`).

### Added — Discord voice region endpoints + UDP >16KB media-burst probe

- **`--voice-region`** / `BLOCKCHECKS_VOICE_REGION` — select a Discord voice
  region for endpoint discovery (`finland`/`russia`/`frankfurt`/…). `discover_dns_alive`
  seeds region IPs from Maks-gaming; when a region is not published under
  `regions/` (russia/frankfurt 404), it falls back to the **global**
  `data/voice-ip-list.txt` (all regions) + region-host DNS resolution.
  Verified live: `bs udp --discover-dns 3 --voice-region russia` → 3/3 PASS.
- **`--voice-burst`** — `voice_burst_probe()` sends a **>16KB UDP media burst**
  (RTP-shaped, Opus-like chunks) to trigger the TSPU "voice traffic" heuristic
  (dpi-detector's 16-20KB drop). `voice_udp_probe` now tries STUN →
  IP-Discovery → burst. Wired through `_probe_worker` (`--burst`) and the
  async inline probe (`BLOCKCHECKS_VOICE_BURST`).
- `checkers/voice_dns.py`: `fetch_maks_region_ips()` (region via global domain
  list + DNS), `MAKS_GLOBAL_IP_LIST_URL`, `REGION_HOST_PREFIXES`.
- Tests: `test_udp_voice_probes.py` burst success/timeout/try_burst (4),
  `test_probe_worker.py` burst flag (2).

### Changed — googlevideo always uses the deterministic GGC probe (auto-fallback)

- **`config.ggc_enabled(domain)`** replaces the `GGC_ENABLED` constant: any
  googlevideo host is automatically probed via the GGC detector (no yt-dlp
  signature, valid beyond the 6-hour signed-URL TTL). `BLOCKCHECKS_GV_GGC=0`
  opts out (signed yt-dlp URL), `=1` forces GGC for any domain.
- **`domain_loader.auto_enable_gv_ggc(domains)`**: when a domain list contains
  googlevideo, sets `BLOCKCHECKS_GV_GGC=1` so subprocess curl workers (which
  read env, not the in-process function) use the GGC detector too. Wired into
  `load_run_domains` (`bs full`) and `resolve_preset_domains` /
  `prepare_dns_and_preflight` (`bs scan`/`bs pair`).
- Verified live: `bs tcp -d googlevideo.com` with **no** env → `HTTP 403`
  (GGC applied, PASS); `bs tcp -d discord.com` → `HTTP 200` (normal path).
- Tests: `test_gv_ggc.py` (10) — ggc_enabled precedence + auto_enable env
  behavior; `test_curl_probe.py` auto-fallback + signed-path (env=0) coverage.

### Added — deterministic GGC probe (bypass-detector, no 6h signed-URL TTL)

- googlevideo signed URLs expire in exactly 6h (21600s). New deterministic
  detector `BLOCKCHECKS_GV_GGC=1` hits a live Google cache (GGC) IP with
  SNI=`rr*.googlevideo.com` and `Range: bytes=0-1048575` (1MiB) to trigger the
  TSPU "video download" heuristic — valid indefinitely, no yt-dlp signature.
- **Bypass vs block detection**: a genuine Google CDN answer carries the unique
  `Server: gws | scone | gvs 1.0` header; the TSPU stub replies `Server: nginx |
  nts` or none. On 302/307 the `Location` must stay inside
  `*.googlevideo.com`/`*.google.com`, otherwise it is a TSPU regional redirect.
- `checkers/curl_probe.py`: `prepare_ggc_probe()`, `_ggc_redirect_is_google()`,
  PASS logic (CDN answered + Google Server header + Google-only redirect).
  `ggc` flag plumbed through `probe_request_dict` / `_curl_probe_worker` /
  `test_runner` payloads.
- Config: `GGC_HOST`, `GGC_FALLBACK_IP`, `GGC_RANGE_SIZE` (1MiB),
  `GGC_ENABLED` (`BLOCKCHECKS_GV_GGC`).
- Verified live: `bs tcp -d googlevideo.com` with GGC returns `HTTP 403` +
  `Server: gvs 1.0` → PASS (bypass), while direct egress is blocked (timeout).
- Tests: `test_curl_probe.py::TestGgcProbe` (6) — Server gws pass, nginx fail,
  no-header fail, Google redirect pass, TSPU redirect fail, `_ggc_redirect_is_google`.

### Fixed — googlevideo CDN probe via SOCKS proxy (2026-08-09)

- `checkers/curl_probe.py` — googlevideo videoplayback probes now route through
  `SOCKS5_PROXY` (`BLOCKCHECKS_PROXY`, default `socks5://127.0.0.1:11080`).
  Direct egress to the googlevideo CDN is DPI-blocked on LLC Fiord, so without a
  proxy every GV probe timed out / 403'd even though yt-dlp had a fresh signed
  URL. The proxy is passed per-request via the `proxy=` kwarg as
  `socks5h://…` (DNS through proxy); the `CurlOpt.PROXY` setopt path does not
  map `socks5h` correctly and yields 403.
- Verified live end-to-end: fresh rr-URL fetched through sing-box (SOCKS
  127.0.0.1:11080) and `bs tcp -d googlevideo.com` now returns
  `[OK] HTTP 206` (was 403 / timeout). Direct `curl --proxy socks5h://…` on the
  same URL returns HTTP 206, 300 KB range body.
- sing-box config updated to a fresh VLESS UUID
  (`9b175962-…`, Riga `94.158.219.192:31237`) and migrated to sing-box 1.13
  config schema (legacy inbound `sniff` fields removed); daemon runs via nohup.

### Changed — scripts audit + repeatable functional-test entry points (2026-08-09)

- **Removed obsolete/one-off scripts** from `scripts/`: `flag_campaign.py`,
  `retest_failed.py`, `b2_smoke_benchmark.sh`, `export_shortlist.sh` (dup of
  `bc-nfconf`), `export_shortlist_json.sh`, `gv5_quic_smoke.sh` (QUIC blocked
  on LLC Fiord), `gv_e2e_smoke.sh`. Removed `dev/oc_*` OpenCode API smokes
  (unrelated to testing).
- **Added repeatable functional-test scripts** in `scripts/`:
  - `smoke_scan.sh` — quick `bs scan` on a known-good matrix; backend selectable
    (default/classic/bridge/compare).
  - `smoke_full_quick.sh` — time-boxed `bs full`; verifies deadline-stop,
    nfqws2 export + run_summary.
  - `smoke_backend_matrix.sh` — functional test of backend selection
    (default→lua_bridge, `--classic`, `--probe-backend`, env, compare no-drift).
  - `gate_all.sh` — one-shot unit + quality + ruff + vulture (+ optional
    `--integration`).
  - `cleanup_env.sh` — reset netns / nfqws2 / shm / run.lock between runs.
- **Added `dev/functional_smoke.sh`** — end-to-end test of every `bs`
  subcommand (tcp/udp/composite/scan classic+bridge/pair/bench-settle/full/
  stop) + `bc-nfconf` export + shortlist round-trip. Live result: **11/11 PASS**.
- `dev/README.md` updated to document the remaining dev helpers + the smoke
  suite.

### Changed — lua_bridge is the standard backend, `--classic` opt-out (T-L3/T-L4/T-L5)

- **Default probe backend flipped to `lua_bridge`** (T-L3): `bs scan`/`pair`/
  `full` now use the persistent nfqws2 + `/dev/shm` IPC bridge without a flag.
  Verified live: `bs scan` (no flag) → `backend=lua_bridge`, 3/3 PASS.
- **`--classic`** (T-L4): force the legacy per-strategy nfqws2 restart backend.
  Verified live: `bs scan --classic` → `backend=classic`, 3/3 PASS.
- **`--probe-backend {classic,lua_bridge}`** (T-L4): explicit backend selection.
  Verified live: `--probe-backend classic` → `backend=classic`.
- **`BLOCKCHECKS_PROBE_BACKEND` env** (T-L5): backend override for scripts/CI.
- Backend precedence (single resolver `config.resolve_probe_backend`):
  `--classic` > `--probe-backend` > `--lua-bridge` > `BLOCKCHECKS_PROBE_BACKEND`
  > default `lua_bridge`.
- Unchanged invariants: pair **UDP bootstrap** and **fan-out waves** always use
  classic; `--lua-bridge-compare` dual path still logs drift (verified live:
  classic + bridge batches, 0 drift).
- Tests: `tests/unit/test_probe_backend.py` (10 cases) — precedence, env,
  CliApp parsing, always-classic paths.

### Added — wheel self-contained data + runtime nfqws2 debug (2026-08-09)

- **Wheel now ships baked data** (`[tool.setuptools.data-files]`): `blobs/*.bin`
  (23), `configs/*.conf` (28), `lua/blockchecks/*.lua` (3), `presets/strategies`,
  `presets/domains`, `presets/voice`. A plain `pip install` wheel is
  self-sufficient — no editable install required.
- `engine/config.py` — `_resolve_project_dir()` falls back to
  `sys.prefix/blockchecks` (where PEP 427 data-files land) so `PROJECT_DIR`,
  `BLOB_DIR`, `REPO_LUA_DIR` and presets resolve from the installed package.
  Verified: wheel installed in a clean venv resolves blobs/configs/lua/presets.
- **Runtime nfqws2 --debug toggle (SIGUSR1)** — must-have for multi-hour scans:
  `SIGUSR1` toggles `BLOCKCHECKS_NFQWS2_DEBUG` and restarts the bridge daemon on
  the next probe (reuses `BridgeSession.boot()` / recycle path). `bs full` and
  `bs scan`/`pair` both handle SIGUSR1. Verified live: SIGUSR1 ON → daemon
  restarts with `--debug`, `nfqws2_*.log` written (3337 B, zhoel-owned); second
  SIGUSR1 → debug OFF. Works without stopping the campaign.
- Tests: debug-env toggle forces lua daemon restart.

### Fixed (logging + XDG audit 2026-08-09)

- `cli/cliapp.py` — **`--nfqws2-debug` was silently ignored on the main CliApp
  path**: the env var `BLOCKCHECKS_NFQWS2_DEBUG` was only set by argparse's
  `dispatch()` (legacy path). Added `_apply_nfqws2_debug_env()` in
  `_dispatch_subcommand` and `expand_bare_nfqws2_debug()` so both `--nfqws2-debug 1`
  and bare `--nfqws2-debug` work. Verified live: `bs tcp --nfqws2-debug 1` now
  produces a debug log.
- `engine/paths.py` — **application logging was never configured**: module
  loggers (paths, presets) wrote to a root logger with no handlers, so
  `log.warning` was silently dropped in production. Added `configure_logging()`
  (FileHandler under `RUNTIME_LOGS_DIR/blockchecks.log` + stderr, level from
  `BLOCKCHECKS_LOG_LEVEL`, default WARNING), called from `cliapp.main()` and
  `parser._main_argparse`.
- `engine/paths.py` — `reclaim_sudo_ownership()` now also repairs **`.log`
  files** (single and inside directories). nfqws2 debug logs are created by the
  dropped-privilege daemon (overflow-uid) and stayed root/`UNKNOWN`-owned.
- `service/nfqws2.py` — after daemon start, the nfqws2 `--debug` log is
  reclaimed to `SUDO_UID/GID` (verified live: `nfqws2_q200_*.log` → zhoel).
- `engine/run_finalize.py` + `nfconf.py` — `run_summary_*.json` and exported
  `nfqws2_*.conf`/`user.list` are reclaimed when running as root.
- Tests: cliapp debug-flag propagation + bare form, logging configured under
  state/logs, reclaim of .log (single + directory), run_summary reclaim.

### Fixed (service-layer audit 2026-08-09)

- `service/lua_bridge_ipc.py` — **events.ndjson must be world-writable (0666)**:
  nfqws2 drops privileges (setuid overflow-uid) after init, so a root-owned
  0644 `events.ndjson` made Lua's `io.open("a")` return nil and `APPLIED` /
  `STRATEGY_FAIL` events were silently lost. Strategy selection tracking was
  broken — PASS recorded without confirmation that the strategy was picked up.
  Verified live: bridge batch PASS previously emitted "bridge PASS without
  APPLIED" warnings for every strategy; after fix 0 warnings at same PASS.
- `service/probe.py` — `invoke_curl_probe_worker` now catches `TimeoutExpired`
  and returns a failure dict instead of killing the whole batch (a hung worker
  lost all per-strategy results + DB logging).
- `service/batch_service.py` — `run_batch` catches **any** exception from the
  sync probe loop (not just `NetnsGoneError`) and emits per-item failure
  results, so a mid-batch crash can no longer drop unlogged strategies.
- `service/batch_service.py` — wssize retry no longer fires for config
  strategies (`is_config=True`); the old check inspected the config *path* for
  the substring "wssize", which is meaningless → spurious retry on every config.
- `service/batch_bridge_probe.py` + `engine/async_runner.py` — bridge probe
  surfaces `bridge_applied` (was an APPLIED event drained?) and warns on
  PASS-without-APPLIED instead of silently trusting the HTTP 200.
- Unit tests: TimeoutExpired dict, generic batch exception → fail results,
  wssize config skip, `bridge_applied` flag, events 0666 perms, publish
  consistency, probe-gen monotonicity, dead-pid `Nfqws2Manager.stop`,
  recycle preserves strategy id, settle `min_wait` floor.

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
- **Scripts:** `scripts/release_smoke.sh` (LLC Fiord gate + B5 shortlist round-trip), `scripts/flag_campaign.py`

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
- LLC Fiord release smoke + flag campaign product gates (BC2 parity markers, pair resume, shortlist/nfconf)
- Install contract: editable/checkout required for `configs/` (ONB-7); blobs on host `/opt/zapret2/blobs/`
