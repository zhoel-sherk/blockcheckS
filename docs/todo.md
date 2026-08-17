# Backlog — blockcheckS

Открытые задачи после **1.0.2**. Закрытые фазы и release notes: [changelog.md](../changelog.md).

Приоритеты: **P1** = matrix/speed/protocol gaps; **P2** = voice/GP integration; **P3** = learned bandit + service layer.

### Closed in 1.0.2

- [x] XDG audit: paths priority docs, out_dir finalize, DATA_DIR export/shortlists, subprocess_env
- [x] DAO: flush transaction, get_best_pairs THROTTLED, indexes, remove get_passing_pairs
- [x] tmp-scripts → `dev/` + `scripts/strategy_debug_probe.py`

### Closed in 1.0.1

- [x] system deps warnings + zapret2 auto-fetch (`engine/system_deps.py`)
- [x] C1 nfqws2 temp unlink; C2 portable chown; C3 chown warn
- [x] requirements sync; `BLOCKCHECKS_LUA_DIR` / `apply_tool_paths`
- [x] README legal disclaimer

### Closed in 1.0.0 audit / campaign (see changelog)

- [x] adaptive pair matrix after AQ TCP
- [x] repeats-aware worker wall timeout
- [x] AQ googlevideo solo batches
- [x] pair resume completed-set only (idx skip removed)
- [x] THROTTLED pair metadata via `get_working_tcp_details`
- [x] family_needs fakedsplit finish
- [x] THROTTLED ∈ working set
- [x] delete pair_runner/pair_manager; composite JSON worker; netns allowlist

### Still open (follow-up)

_(none — E3 closed in Wave2)_

### Closed in 1.1.0a1 (alpha Wave1–2)

- [x] Unify `_nfqws2_daemon` ↔ `Nfqws2Manager` (E3 → `nfqws2.start_daemon`)
- [x] Docs architecture rewrite (DoH/GV-1 as current + NetNsPool scale)
- [x] `--preset` path jail + token file modes
- [x] composite_runner: public `engine.probe.invoke_curl_probe_worker`

### Closed in 1.1.0a1 (dpi-stack audit DS1–DS2)

- [x] Composite UDP qnum → `NFQUEUE_UDP` (Wave4 regression)
- [x] `test_batch_tcp` input-order via `asyncio.gather`
- [x] curl_cffi Session/`RequestsError`/`read_timeout` + DoH Session
- [x] DAO latest-row stats/views; `get_best_udp` THROTTLED; pair dedupe
- [x] Generator `tls13` protocol + blob path via `resolve_blob_path`
- [x] Keenetic circular `--in-range`/`--out-range` scaffold
- [x] Voice discovery `match/case` + sing-box async CM; `--full-voice` UX
- [x] Shared blob CLI helpers; UDP family registry start; CLI/preflight DRY; settle unify

### Closed in 1.1.0a1 (todo debt close, no ML)

- [x] Phase 7: `ipfrag_tcp` / `ipfrag_udp` axes (`ipfrag_disorder`, `ipfrag_next`, fuller pos) + UDP multiline dual `--lua-desync`
- [x] **M8** `flowseal` in default `bs full --tcp-sources`
- [x] TTL > 255 (`256`/`512`) + `repeats=4` matrix axes
- [x] **V2-1** multi-endpoint pair/udp/full fan-out (`domain@ip:port` resume keys)
- [x] **V2-3** `scripts/voice_smoke.sh`
- [x] **P5-1** `provider_import --seed-db` → `seed_state_db`

---

## P1 — Matrix, protocols, speed

### Phase 7 — QUIC / HTTP3

- [x] `ipfrag_udp` / `ipfrag_tcp` (`send:` dual-call) — generator gap

### Phase 10 — Matrix coverage

- [x] **M8** `flowseal` в default `bs full --tcp-sources` или merge combos в `standard`
- [x] TTL > 255, `repeats=4` generator — matrix gap

### Phase 11 — Speed / throughput

#### L-bridge — lua_bridge + ProbeBatchService (batch N strategies / one nfqws2)

**Статус:** `lua_bridge` + ProbeBatchService в 1.1.x (opt-in `--lua-bridge`); flip default — L-transition-*.

**Сделано (1.1.0):**
- [x] **L-bridge-1** `service/lua_bridge_ipc.py` + `lua_session.py` — shm IPC, `build_bridge_conf`, `BridgeSession`, `scan_pick` Lua (`lua/blockchecks/`)
- [x] **L-bridge-2** CLI `scan`/`pair`: `--lua-bridge`, `--bridge-batch`, `--lua-bridge-compare`, `--lua-extra`
- [x] **L-bridge-3** `AsyncTestRunner._test_batch_tcp_bridge` (batch hot-swap для `test_batch_tcp`)
- [x] **L-bridge-4** Unit tests (`test_lua_bridge.py`, `test_lua_bridge_runner.py`); `netns_pool` + `run_control` shm cleanup

**ProbeBatchService (текущий спринт):**
- [x] **L-batch-1** `service/batch_service.py` — `BatchScheduler`, `ProbeBatchService`, backends `classic` | `lua_bridge`
- [x] **L-batch-2** `AsyncTestRunner.test_batch_tcp` → делегирует в сервис (убрать `_run_bridge_batch` из runner)
- [x] **L-batch-3** `bs full` sequential + AQ: batch service при `--lua-bridge`; CLI flags на `full`
- [x] **L-batch-4** Fan-out: classic per-strategy + one-time warning при `--lua-bridge` (bridge внутри fan-out wave не совместим)
- [x] **L-batch-5** Тесты `test_batch_probe.py`, dead_flags для `full`; docs `custom_lua.md` §9

**Статус:** ProbeBatchService готов (1.1.x); T-L1 короткие прогоны на LLC Fiord — в работе.

**Поэтапный переход default → lua_bridge (1.3.4 — переключён):**

С 1.3.4 **default = lua_bridge** (`DEFAULT_PROBE_BACKEND`); `--classic` /
`--probe-backend {classic,lua_bridge}` выбирают явно. Classic path сохранён
(pair UDP bootstrap, fan-out, отладка).

| Этап | Gate | Действие |
|------|------|----------|
| **T-L1** | ProbeBatchService + full sequential/AQ на LLC Fiord | `--lua-bridge` на `scan`/`full`; `--lua-bridge-compare` без drift |
| **T-L2** | smart-fallback (§6 custom_lua) или P0-2 inline curl | снизить FAIL timeout wall на full matrix |
| **T-L3** | 2× full run PASS rate ±1% vs classic baseline | **flip default:** `probe_backend=lua_bridge` без флага |
| **T-L4** | после T-L3 | CLI `--classic` / `--probe-backend classic` — явный legacy; deprecate `--lua-bridge` (alias) |
| **T-L5** | optional | env `BLOCKCHECKS_PROBE_BACKEND`; CI gate только `--lua-bridge-compare` на subset |

- [x] **L-transition-1** (T-L1) LLC Fiord: `bs scan --lua-bridge --max 200` + `bs full --lua-bridge` subset, compare green — smoke 2026-08-05: scan/compare/full OK, 0 PASS на random custom (ожидаемо); drift 0 — DONE (1.3.4)
- [ ] **L-transition-2** (T-L2) smart-fallback NDJSON poll → early curl abort в `ProbeBatchService`
- [x] **L-transition-3** (T-L3) Flip default backend to `lua_bridge` — DONE (1.3.4, `config.DEFAULT_PROBE_BACKEND`)
- [x] **L-transition-4** (T-L4) Добавить `--classic` и `--probe-backend {classic,lua_bridge}` — DONE (1.3.4, `add_backend_args`)
- [ ] **L-transition-5** (T-L5) Убрать `--lua-bridge-compare` из user path; оставить в `scripts/release_smoke.sh` / CI

**Не смешивать с `--classic`:**
- `classic_persistent` (daemon без shm) — отдельный backend, низкий ROI; не alias для `--classic`
- UDP voice q201, T3-4 unix socket — отдельные треки ([custom_lua.md](custom_lua.md), T3-4)

### YouTube / External

_(see Deferred)_

---

## P2 — Voice & GP bridge

- [x] **V2-1** multi-endpoint pair matrix по всем discover EP
- [x] **V2-2** `--full-voice` gateway WS path (discovery via gateway; messaging fixed in DS1)
- [x] **V2-3** `scripts/voice_smoke.sh`
- [x] **P5-1** GP JSON import в `state.db` (`provider_import --seed-db`; NDJSON candidates still deferred)

---

## Deferred (parked)

| ID | Why |
|----|-----|
| **M10** circular *scan* mode | L; export scaffold already exists |
| **A4** | GP-side multi-domain defaults (BS B2 done) |
| **B3** persistent nfqws2 | High risk; after B7 |
| **B6** blockcheckw | External / removed reference |
| **B7** nftables vmap | Optional host-shared POC; not needed for netns parallel |
| **GV-2** Playwright | Optional yt-dlp alternative |
| **unblock-pro** | External heuristics port |
| **ipset-lists** | Независимость от zapret2/ipset (antifilter/antizapret/reestr IP-листы для внешнего nfqws2-хостинга). Сейчас не требуется: LLC Fiord-стратегии не зависят от IP-листов, в blockcheckS ipset не используется. Скрипты-референс: `/opt/zapret2/ipset/` (create_ipset.sh, get_*.sh). Реализовать при необходимости внешнего деплоя с IP-блокировками. |

---

## P3 — Learned bandit + service layer (replaces old ML1–ML5 / H1–H10)

**2026-08-14 пересмотр:** AQ+AR — уже contextual bandit (`ScanWeights.get` = линейная
модель `1.0 + Σ_family + Σ_blob + Σ_trait`, ε-greedy = exploration, heap = argmax,
fanout = transfer, provider-preflight = cold-start prior). Цель старых ML/H-пунктов
достигнута эвристикой без sklearn. Оставлены только пункты, реально нужные для
скорости подбора. sklearn-ранкер / progressive-builder закрыты как избыточные.

### S0 — Offline strategy ranker (cold-start prior, высокий ROI)
- [x] **FailPhase enum** (`engine/fail_phase.py`, 32 токена) — единая таксономия фаз
      (DNS/L3/SNI/stream-stall/QoS/QUIC) + динамические http_<code>. (2026-08-15, Wave 1)
- [x] **TriageProfile** (`engine/triage.py`) — профиль вмешательства, контекст-вектор для
      бандита/S0; строится в preflight. (2026-08-15, Wave 1)
- [x] **L3/L4 + sinkhole** (`checkers/l3_probe.py`, bogon-фильтр в dns_secure) (2026-08-15)
- [x] **Stream stall + TLS fingerprint** (`run_stream_triage_probe` 7-42KB, `run_tls_profile_probe`
      4 профиля) (2026-08-15)
- [x] **Генераторы**: `triage` в `generate()`, отсечение L3/postquantum. (2026-08-15)
- [x] **fail_phase** колонка в tcp_results + миграция. (2026-08-15)
- [ ] **S0-1** export `state.db` tcp_results → features (domain_class × strategy_features) → parquet
- [ ] **S0-2** fit PASS-probability model (logistic/GBDT) над `(domain_features × strategy_features)`
- [ ] **S0-3** `--ranker model.json` → top-K кандидатов → seed в AQ (`_apply_provider_weights` point)
- [ ] **S0-4** retrain policy: после mass scan / provider change / drift (по аналогии старого ML5)

### S1 — Learned feature weights (upgrade bandit AQ)
- [ ] **S1-1** выучить `w_family/w_blob/w_trait` коэффициенты из state.db вместо hard-coded 1.0/0.5/0.4
- [ ] **S1-2** Thompson sampling / LinUCB вместо (или поверх) ε-greedy
- [ ] **S1-3** выученная axis order (контекст: domain_class) — бывший H3/H7
- [ ] **S1-4** интерфейс `ScanWeights` не менять; веса сохраняются в `scan_weights` (уже есть)

### KPI / fallback (оставшиеся H-пункты)
- [ ] **H9** benchmark vs full matrix на 10 доменах: Recall(best strategy found)
- [ ] **H10** fallback: AQ 0 PASS → expand beam / RF top-K / full family scan

### Дистилляция на слабые устройства (бывший S3 — упрощено)
- [ ] **S3** результат S0/S1 = плоская таблица коэффициентов (w_family/w_blob/w_trait) →
      JSON-конфиг или sqlite3-таблица, вычисляемая чистым Python/C без ONNX/ML deps.
      Носим на MIPS/ARM роутеры с 64-128 MB RAM. (2026-08-14: уточнено — ONNX не нужен.)

### Far-Future R&D (R&D backlog)
- [ ] **RL-1** Gymnasium Env `DpiBanditEnv` (Discrete action, one-step episodes) — bandit-форма,
      не MDP (DPI реагирует per-flow, нет агентных переходов)
- [ ] **RL-2** DPI-эмулятор на сервере: Geneva-style NFQUEUE+scapy censors / nDPI / TSPU-rules
      (IMC'22) — обучение PPO (sb3) vs GA/CMA-ES параллельно; gate на LLC Fiord holdout
- [ ] **RL-3** PPO vs GA: GA sample-efficient для discovery (Geneva precedent); PPO только если
      нужна context-conditional policy и есть дешёвый эмулятор. SAC не подходит (discrete).
- [ ] **RL-4** деплой: дистиллированный tree/JSON как AQ priors; sim2real = emulator только как
      prior-generator, никогда как ground truth (LLC Fiord ≠ модель)

---

## Service layer — `bs serve` (on-the-fly probing)

**2026-08-14:** единый фоновый сервис оправдан — netns pool + bridge boot дорогая часть,
спроектирована для reuse (`netns_pool.acquire/release`). Это тонкая обёртка над
`AsyncTestRunner`/`ProbeBatchService`, не новый движок.

### Архитектура
- [x] **SVC-1** `service/probe_service.py`: `ProbeService(pool_size=4)` — `start()/probe()/stop()`,
      busy() через run_control. (2026-08-14)
- [x] **SVC-2** Ядро строго `asyncio.start_unix_server` на `STATE_DIR/blockchecks.sock` (0 deps).
      `service/server.py` ProbeServer. (2026-08-14)
- [x] **SVC-3** лёгкий HTTP bridge поверх сокета (stdlib, `serve_http` на 127.0.0.1). (2026-08-14)
- [x] **SVC-4** CLI `bs serve` (--pool/--bridge-batch/--classic/--http-port). (2026-08-14)

### Fair Exclusion (взаимная блокировка через run_control)
- [x] **SVC-5** единый `run_control.lock` — serve регистрирует "serve", кампании блокируются. (2026-08-14)
- [x] **SVC-6** активная кампания → `/probe` `423` `{"status":"busy","reason":"campaign_active","active_run":...}` (fail-fast, E2E подтверждено) (2026-08-14)
- [x] **SVC-7** серии нет → сервис держит пул прогретым, обслуживает on-the-fly (E2E: /probe ripe.net → FAIL connect_timeout) (2026-08-14)

### Контракт
- [x] **SVC-8** `POST /probe` → `[{domain, strategy_id, status, fail_phase, latency_ms, http_code, fingerprint_matched}]`
      — fail_phase классификатор (`classify_fail_phase`), E2E подтверждено. (2026-08-14)
- [x] **SVC-9** `GET /status` → `{status, active_run, pool_size, started, uptime_s}`; `POST /stop`. (2026-08-14)
- [x] **SVC-10** systemd unit `blockcheck-serve.service` + install/uninstall (по образцу series) — DONE (1.3.4, `systemd/blockcheck-serve.service`)

### Интеграция GP
- [ ] **SVC-11** GP root-helper runner POST'ит на socket вместо exec `blockcheck2.sh`;
      контракт `start-run` сохраняется
- [ ] **SVC-12** MVP = TCP/TLS/HTTP; QUIC через bridge subprocess; UDP-voice отдельные аргументы
- [ ] **SVC-13** только 4 netns → контенция guard через run_control lock namespace

---

## 1.1.0 — tech debt (audit backlog)

- [x] **H2** `run_finalize` / `export_configs(store=)` — reuse open DAO; flush before count
- [x] **H3** `adaptive_queue.filter_resume` — `asyncio.gather`
- [x] **H4** preflight `--prolog-content` / `verify_content`
- [x] **H6** `DnsRunCache` rotates DoH server on failure
- [x] **H8** `voice_discovery` sing-box under threading.Lock
- [x] **E3** `nfqws2.start_daemon` (Wave2)
- [x] `[paths.migrate]` — `./state.db` → XDG on first run (`migrate = true` in example)

---

## P0 — Performance regression (alpha → 1.1.0)

> **Диагноз (deepseekv4pro_audit + subagent, 2026-08-04):**
> `bs full --max-timeh 20 --parallel 4 --fan-out` даёт 0.20 тест/сек
> (4,100 тестов за 5.7ч, ETA 22 дня на 379K тестов). Причина —
> **не изменение per-test hot path** (он идентичен 1.0.2), а комбинация
> факторов, главный из которых — **wssize retry** удваивает время каждого
> FAIL-теста (каждый FAIL → второй полный цикл: nfqws2 + subprocess + curl + DB).
> Остальные факторы — сабпроцесс на каждый тест, per-test DB-коннект,
> settle-оверхед — добавляют ещё 1.2-1.5× замедления.

### Бюджет времени на один FAIL-тест (TLS 1.2, wssize active)

| Фаза | Время | Cumulative |
|------|-------|------------|
| nfqws2 daemon start + settle | 0.15–0.25s | 0.25s |
| iptables NFQUEUE rule | 0.05–0.10s | 0.35s |
| Python subprocess + import chain | 1–3s | 2.35s |
| curl probe (timeout 5s на blocked host) | 5.0s | 7.35s |
| **wssize retry:** nfqws2 + settle | 0.20s | 7.55s |
| **wssize retry:** Python subprocess | 1–3s | 9.55s |
| **wssize retry:** curl probe timeout | 5.0s | 14.55s |
| DB write (`log_tcp`, ×2 с retry) | 0.2–0.5s | 15.05s |
| Netns cleanup (`pkill` + `iptables -F`) | 0.1–0.2s | 15.25s |
| **Total** | **~15–18s** | |

С 4 параллельными воркерами: **4 / 16 = 0.25 тест/сек** — совпадает с наблюдаемыми 0.20.

### Fixes (priority order)

#### P0-1 — Disable wssize retry by default for full scans
**Файл:** `src/blockchecks/engine/async_runner.py:821-845`  
**Влияние:** **1.7–2.0×** (каждый FAIL-тест идёт один раз, а не два)  
**План:**
- [x] Добавить `--no-wssize` / `--wssize` флаг в CLI parser (оба `pair` и `full`)
- [x] В `async_runner.py` guard: `if try_wssize and not args.no_wssize: ...`
- [x] В `main_phases.py:413` и `pair_phases.py:186`: `try_wssize = not getattr(args, "no_wssize", False) and protocol == "tls12"`
- [x] Дефолт для `bs full`: `--no-wssize` (без retry — full-скану важна скорость, wssize можно протестировать отдельным скан-левелом)
- [x] Дефолт для `bs pair` / `bs scan`: `--wssize` оставить (короткие сканы, качество важнее скорости)

#### P0-2 — Inline curl probe вместо subprocess
**Файлы:** `src/blockchecks/engine/probe.py:29-62`, `async_runner.py:444,576`  
**Влияние:** **1.2–1.5×** (убирает `sudo ip netns exec python -m ...` — 1-3s overhead per test)  
**План:**
- [ ] Заменить `invoke_curl_probe_worker()` subprocess на `asyncio.to_thread(run_curl_probe, ...)`
- [ ] `run_curl_probe` уже импортируется в main process (`curl_cffi` загружен)
- [ ] Graceful fallback: если inline не работает (падение curl_cffi в том же процессе), возвращать subprocess
- [ ] `_run_tcp_check()` вызывает probe напрямую, а не `sp.run(["sudo", "ip", "netns", "exec", ns, py, "-c", ...])`
- [ ] Netns isolation не нужна — `_run_tcp_check` и так вызывается через `asyncio.to_thread` внутри контекста netns (iptables уже настроен, nfqws2 уже запущен)

#### P0-3 — DB write batching по умолчанию
**Файл:** `src/blockchecks/engine/store/sqlite_store.py:167-232`  
**Влияние:** **1.05–1.10×** (убирает `connect → PRAGMA → COMMIT` per test)  
**План:**
- [x] Сменить дефолт `--db-batch` с `0` на `500` (parser + `DEFAULT_DB_BATCH` fallback в full/pair)
- [x] При batch>0 внутри `flush()` уже есть `BEGIN IMMEDIATE` + rollback — атомарность сохранена
- [x] `flush()` вызывается в `run_finalize.py` при остановке по таймауту/SIGINT

#### P0-4 — Settle overhead
**Файл:** `src/blockchecks/engine/nfqws2_settle.py:29-53`, `config.py:224-226`  
**Влияние:** **1.02–1.05×** (убирает 0.05s sleep + 1-2 pgrep = 0.15-0.25s per test)  
**План:**
- [x] `BLOCKCHECKS_NFQWS2_SETTLE_MIN=0` (nfqws2 в daemon-режиме с `@config` стартует мгновенно)
- [x] `BLOCKCHECKS_NFQWS2_SETTLE_POLL=0.05` (вместо 0.1)
- [x] `wait_nfqws2_ready` при min_wait=0 корректно ждёт если nfqws2 ещё не запущен

#### P0-5 — Preflight skip флаги для повторных full-сканов
**Файл:** `src/blockchecks/engine/preflight.py:118-189`, `main_phases.py:182-204`  
**Влияние:** стартовое время (10-20 минут на 100+ доменах)  
**План:**
- [x] `--skip-prolog` уже есть ✅
- [x] `--skip-port-block` уже есть ✅
- [x] `--skip-ip-block` уже есть ✅
- [x] `--skip-dns-audit` уже есть ✅
- [x] `--skip-baseline` уже есть ✅
- [x] `scripts/run_full_20h.sh`: `--skip-prolog --skip-ip-block --skip-port-block`

#### P0-6 — Быстрый прогон после всех фиксов
**План:**
- [ ] `sudo bs full --max-timeh 8 --parallel 4 --fan-out --resume --skip-prolog --skip-ip-block --no-wssize --db-batch 500`
- [ ] Ожидаемая скорость: **0.6–1.0 тест/сек** (3-5× быстрее текущего)
- [ ] ETA для 379K тестов при 8ч лимите: ~72K тестов пройдено (19% coverage) — приемлемо для 8ч прогона

### Не-NOT-проблемы (проверено, не являются причиной замедления)

| Фактор | Почему не виноват |
|--------|-------------------|
| Preflight | Запускается **один раз** при старте скана, не per-test |
| CliApp / `build_parser()` ×3 | Только при старте, не per-test |
| Settings / TOML loading | `@lru_cache(maxsize=1)`, кешируется |
| DNS resolution | In-memory dict с TTL 3600s, не per-test |
| ThreadPool conflicts | `ThreadPoolExecutor` только при `repeats > 1 AND parallel_repeats=True` (не default) |
| Family gating | `skip_strategy()` = O(1) string checks |
| Settle profile | `_timing_for()` = dict lookup |
| Fan-out serialization | JSON ~200 байт, микросекунды |

---

## P0 — Tier 1: Hardcoded timeouts + SQLite прагмы (однодневные)

> **Цель:** понизить все завышенные таймауты и оптимизировать SQLite.
> **Ожидаемый эффект:** ~4.5 часов экономии на full-скане (100 стратегий × 6 доменов).
> **Трудозатраты:** ~20 строк кода, 1 час.
>
> Бюджет времени (исследование 2026-08-04, субагент `deepseekv4pro_audit`):
> `settle_slack=15s` — крупнейший единичный потребитель (2ч на full-скан).
> См. `docs/todo.md#P0-performance-regression` для контекста.

### T1-1 — `settle_slack` в `worker_wall_timeout` (15.0 → 3.0)
**Файл:** `src/blockchecks/checkers/curl_probe.py:320`  
**Текущее:** `def worker_wall_timeout(..., settle_slack: float = 3.0)`  
**Проблема:** Каждый сабпроцесс-проб получает +15s к таймауту «на всякий случай». Python стартует за 0.3-0.8s, nfqws2 селится за 0.05-0.5s. 15s — запас с пятикратным превышением.  
**Экономия:** 12s × 600 вызовов = **7200s (2ч)** на full-скан.  
**Что сделать:**
- [x] `settle_slack: float = 3.0` в сигнатуре
- [x] `max(3.0, float(settle_slack))` вместо `max(5.0, float(settle_slack))` в теле
- [x] `test_runner.py` settle_slack=3.0
- [x] `composite_runner.py` settle_slack=3.0
- [ ] Прогнать 10 стратегий на discord.com — убедиться что нет false-timeout

### T1-2 — nfqws2 settle + stop wait
**Файлы:** `src/blockchecks/engine/config.py:225-227`, `src/blockchecks/engine/nfqws2.py:260,264`  
**Текущее:**
```
NFQWS2_SETTLE_MAX  = 0.5
NFQWS2_SETTLE_POLL = 0.05
NFQWS2_SETTLE_MIN  = 0
# Stop: wait(timeout=1) + sleep(0.1) + wait(timeout=1)
```
**Проблема:** nfqws2 в daemon-режиме с `@config` стартует мгновенно (~50-200ms). 2s max + 5s stop wait = 7s оверхеда на каждый цикл стратегии.  
**Экономия:** 1.5s (settle) + 2.3s (stop) × 400 циклов = **~1520s** на full-скан.  
**Что сделать:**
- [x] `NFQWS2_SETTLE_MAX = 0.5` (вместо 2.0) — env override `BLOCKCHECKS_NFQWS2_SETTLE_MAX` сохранён
- [x] `NFQWS2_SETTLE_POLL = 0.05` (вместо 0.1)
- [x] `NFQWS2_SETTLE_MIN = 0.0` (вместо 0.05) — nfqws2 не нужен min wait
- [x] Stop: `wait(timeout=1)` + `sleep(0.1)` + `wait(timeout=1)` (вместо 3+0.3+2)
- [ ] Проверить на slow-машине (Pi/ARM) что nfqws2 успевает стартовать за 0.5s

### T1-3 — SQLite performance pragmas
**Файл:** `src/blockchecks/engine/store/sqlite_store.py` (все `_wrap_connection` и `async with connect` места)  
**Текущее:** `PRAGMA busy_timeout`, WAL в init, `_apply_pragmas`: synchronous=OFF, mmap, cache, temp_store  
**Проблема:** Без `synchronous=OFF` каждый INSERT ждёт fsync. Без `mmap_size` каждый read идёт через read(). Без `cache_size` страничный кеш tiny (2MB default).  
**Экономия:** **5-10×** на запись в SQLite при батч-режиме.  
**Что сделать:**
- [x] `_apply_pragmas()` в sqlite_store.py (synchronous=OFF, mmap 256MB, cache 64MB, temp_store=MEMORY)
- [x] WAL mode в `init()` через schema
- [x] `flush()` перед stop в run_finalize

### T1-4 — Probe timeout: CLI default 5.0 → 3.0
**Файл:** `src/blockchecks/cli/parser.py` (все `--timeout default=3.0`)
**Текущее:** `--timeout default=3.0` на всех командах — DONE (1.3.4)
**Проблема:** DPI-блокировка детектируется за 2-3s (SYN+ClientHello либо проходит, либо silent-drop). 5s — запас, который умножается на количество FAIL-тестов.
**Экономия:** 2s × 600 FAIL-проб = **~1200s** на full-скан.
**Осталось:**
- [ ] `default=3.0` в parser.py (4 места)
- [ ] Оставить `--timeout` флаг для ручного оверрайда (медленные сети, VPN)
- [ ] Проверить на гео-удалённых серверах (US из РФ через VPN): 3s хватает?

### T1-5 — Subprocess padding: QUIC +10→+5, TCP/UDP +5→+3
**Файлы:** `src/blockchecks/engine/async_runner.py:318,707`, `src/blockchecks/engine/test_runner.py:296`  
**Текущее:** QUIC: `timeout+5`, TCP/UDP: `timeout+3`  
**Проблема:** Python стартует за 0.3-0.8s. +10s для QUIC — двойной запас относительно 8s probe timeout. +5s для TCP/UDP при 3-5s probe — тройной запас.  
**Экономия:** 5s × 80 QUIC + 2s × 200 TCP/UDP = **~800s** на full-скан.  
**Что сделать:**
- [x] `timeout=timeout+5` для QUIC (вместо +10)
- [x] `timeout=timeout+3` для TCP/UDP (вместо +5)
- [x] `worker_wall_timeout` default settle_slack=3.0 перекрывает зазор

### T1-6 — Верификационный прогон после T1
- [ ] `sudo bs full --max-timeh 4 --parallel 4 --fan-out --resume --skip-prolog --skip-ip-block --no-wssize --db-batch 500`
- [ ] Замерить тест/сек (цель: 0.6-1.0 тест/сек — 3-5× быстрее текущих 0.20)
- [ ] Проверить что нет false-timeout на медленных стратегиях
- [ ] Записать результаты в `docs/todo.md` (строка с датой и скоростью)

---

## P1 — Tier 2: TLS-handshake-only + DPI aggression detector + byedpi (недельные)

> **Цель:** структурные ускорения без потери качества.
> **Ожидаемый эффект:** 10-20× общее ускорение (в комбинации с Tier 1).
> **Трудозатраты:** ~300 строк кода, 3-4 часа.

### T2-1 — `--head` / `--no-body` флаг: TLS-handshake-only probing
**Идея:** Для проверки DPI-обхода не нужно скачивать тело ответа. Достаточно TCP connect + TLS handshake + HTTP response headers.  
**Экономия:** 50-500ms на пробу (загрузка HTML-тела не нужна).  
**Реализация:**
- [ ] Добавить `--no-body` / `--head` флаг в CLI parser (scan, pair, full)
- [ ] В `curl_probe.py:CurlProbeRequest` добавить поле `head_only: bool = False`
- [ ] В `run_curl_probe()`: если `head_only=True` → `session.head(url)` вместо `session.get(url)`
- [ ] Content validation: для HEAD запросов `content_ok` всегда True (тела нет)
- [ ] `read_rate_bps` = 0 для HEAD (нет тела для измерения скорости)
- [ ] Статус-коды: HEAD возвращает те же 200/301/403 что и GET, проверка не меняется
- [ ] Совместимость с googlevideo: HEAD не работает для GV (нужен Range), авто-disable для `is_googlevideo_domain()`

### T2-2 — DPI aggression detector: rolling PASS rate + авто-пауза
**Файл:** новый модуль `src/blockchecks/engine/dpi_throttle.py` (~50 строк)  
**Идея:** Если DPI (ТСПУ) замечает слишком быстрый поток проб и включает агрессивный режим, ранее-PASS стратегии начинают FAIL'ить. Детектор отслеживает rolling PASS rate и при падении ниже порога — авто-пауза.  
**Реализация:**
- [ ] Класс `DpiThrottleDetector`:
  ```python
  @dataclass
  class DpiThrottleDetector:
      window_size: int = 50  # скользящее окно (последние N проб)
      pass_rate_threshold: float = 0.3  # порог: если <30% PASS — агрессия
      pause_seconds: float = 30.0  # пауза при детекте
      cooldown_multiplier: float = 2.0  # множитель паузы при повторном детекте

      _history: list[bool] = field(default_factory=list)  # True=PASS, False=FAIL
      _paused_until: float = 0.0
      _aggression_count: int = 0

      def record(self, passed: bool) -> bool:
          """Записать результат пробы. Вернуть True если нужна пауза."""

      def should_pause(self) -> bool:
          """Проверить текущее состояние."""
  ```
- [ ] Интеграция в `AsyncTestRunner.test_tcp()`: после каждого `log_tcp()` → `detector.record(success)`
- [ ] Если `detector.should_pause()` → `log.warning("[DPI AGGRESSION] pausing for %ds", pause)` → `await asyncio.sleep(pause)`
- [ ] Сброс детектора при ручном `--resume` (новая сессия = новый контекст)
- [ ] CLI флаг `--dpi-throttle` (bool, default=True) — можно отключить
- [ ] CLI флаг `--dpi-throttle-window` (int, default=50)
- [ ] CLI флаг `--dpi-throttle-pause` (float, default=30.0)

**Эвристика:** DPI-агрессия маловероятна на 1-4 проб/сек (см. исследование в T2-3). Детектор — safety net при экспериментах с повышенной скоростью.

### T2-3 — byedpi как опциональный движок (`--engine byedpi`)

> **Полный план:** [docs/byedpi_engine.md](byedpi_engine.md) — архитектура, маппинг, ByeByeDPI autotest, roadmap 8 фаз.

**Идея:** ciadpi — SOCKS5 без root/netns. Для **тестирования** — **process-per-strategy** (как ByeByeDPI autotest): один ciadpi на стратегию, curl через прокси, ~50ms старт. `--auto` chains — только production (§10 byedpi_engine.md).

**Архитектура:**
```
blockcheckS → для каждой стратегии:
              ByedpiManager.from_strategy() → ciadpi -p N -K tls …flags
              curl через socks5://127.0.0.1:N
              stop ciadpi
Параллельно: N стратегий = N ciadpi на разных портах.
```

**Что сделать:** см. Phase 1–8 в [byedpi_engine.md](byedpi_engine.md) (§5 Roadmap).

**Ограничения:** см. §7 byedpi_engine.md. `badsum`/`tcp_ts_up` — SKIP. UDP/QUIC — nfqws2. Не тестировался на LLC Fiord — нужен живой прогон.

---

## Исследовать (Research / Tier 3)

> **Цель:** долгосрочные идеи, требующие изучения, прототипирования или внешних зависимостей.
> **Не в спринте.** Может быть переведено в P2/P3 при появлении ресурсов.

### T3-1 — C raw-socket TLS probe (200 строк)
**Идея:** Вместо curl_cffi → TCP connect + TLS ClientHello + ServerHello detection на сырых сокетах.
- Без HTTP, без curl, без Python
- Скорость: **50-100×** на пробу (микросекунды вместо миллисекунд)
- Ограничение: только packet-level стратегии (fake). Split-based стратегии требуют полного TCP-потока.
- Язык: C (200 строк), компилируется в ~50KB бинарник
- Интеграция: subprocess как `probe_tcp_raw <ip> <port> <sni>`
- **Не сделано:** нужен прототип, замер скорости, сравнение с curl_cffi

### T3-2 — Rust rewrite probe engine (reqwest + tokio)
**Идея:** Заменить Python probe-слой на Rust.
- `reqwest` — HTTP-клиент с нативным TLS (rustls/openssl)
- `tokio` — async runtime
- Скорость: **50-200×** на пробу (нет GIL, нет интерпретатора)
- Интеграция: subprocess как `bs-probe --domain X --strategy Y`
- **Не сделано:** требует отдельного Cargo-проекта, CI интеграции, кросс-компиляции

### T3-3 — eBPF/XDP packet modification
**Идея:** Модификация пакетов на уровне драйвера (XDP) или TC (eBPF).
- Полностью в ядре, ноль userspace/kernel переключений
- Теоретический предел скорости — line rate (гигабиты в секунду)
- **Не сделано:** требует rewrite всей логики nfqws2 на eBPF (C-подобный, но ограниченный язык). Сложность: месяцы.

### T3-4 — nfqws2 hot-reload патч
**Идея:** Пропатчить nfqws2 для поддержки смены `--lua-desync=` без рестарта.
- Текущий SIGHUP перегружает только hostlists/ipsets
- Нужен Unix-сокет, HTTP API или file-watch для реконфигурации
- Устранил бы settle overhead per strategy целиком
- **Не сделано:** требует форка nfqws2, C-разработки, тестирования
- **Промежуточный путь без fork:** [custom_lua.md](custom_lua.md) — `/dev/shm` + `scan_pick` + timer poll (L1–L4)

### T3-5 — kernel module (youtubeUnblock kmod approach)
**Идея:** Встроить модификацию пакетов в kernel module.
- Все стратегии в одном модуле, переключение через /proc или /sys
- Полное устранение userspace overhead
- **Не сделано:** kernel-разработка, security review, поддержка разных ядер

### T3-6 — QUIC/HTTP3 probe через встроенный curl
**Идея:** Текущий QUIC probe использует отдельный сабпроцесс с curl_cffi. Можно ли использовать системный curl с HTTP/3 поддержкой напрямую?
- `curl --http3-only -o /dev/null -s -w '%{http_code}' https://domain`
- Без Python, без импорта curl_cffi, чистый subprocess
- **Не сделано:** проверить доступность `curl --http3` на системе, сравнить скорость

### T3-7 — Multi-queue nfqws2 (pipelining)
**Идея:** Пока стратегия S тестируется в netns с qnum=200, стратегия S+1 уже стартует в другом netns с qnum=200.
- Каждый netns изолирован — qnum'ы не конфликтуют между netns
- Текущая имплементация ждёт завершения ВСЕХ доменов для стратегии S перед стартом S+1
- Pipelining: overlap settle времени стратегии S+1 с curl-пробами стратегии S
- **Не сделано:** переписать `_run_tcp_fanout()` на конвейерную обработку

---

## Alpha VPS regressions (Selectel 111.88.227.92, 2026-08-04)

Обнаружено при установке и тестовых прогонах на чистом Ubuntu 24.04 x86_64.

### Fixed (in-tree)

- [x] **VPS-1** `MemAvailable` warning spam — `effective_default_pool_size()` печатал предупреждение при КАЖДОМ вызове (8-10 раз за `bs scan`). Добавлен `_mem_warned` флаг в `config.py`. Файл: `src/blockchecks/engine/config.py:158-168`.
- [x] **VPS-2** Scan/full duplication — `sub.cli_cmd()` + handler dispatch caused double `asyncio.run` via CliApp. Fix: subcommand models parse-only, `_dispatch_subcommand()` from root `cli_cmd`, `_FULL_RUN_ACTIVE` guard on `bs full`. Файл: `src/blockchecks/cli/cliapp.py`.

### Observations

- **curl-cffi 0.16.0** на VPS (новее локальной 0.15.0) — тесты зелёные, совместимость OK
- **python3-venv** на Ubuntu 24.04 требует `--upgrade-deps` флаг (иначе pip не ставится)
- **Selectel IP** — чистый, DPI не блокирует (youtube.com 3/3 PASS, discord.com 3/3 PASS)
- **web.telegram.org** — IP-блокировка (0/3 PASS, все timeout 8s)
- **460/465 тестов** зелёные на VPS (5 skipped — sudo/netns related)
- **zapret2 auto-fetch** — скачал `v1.0.4` с GitHub, установил в `~/.local/share/blockcheckS/zapret2/`

### Closed in 1.2.1a (lua bridge)

- [x] Version 1.2.1a bump
- [x] changelog: full lua bridge entry (1.1.0 feature documented)
- [x] T2.1 integration test: lua_bridge_compare_no_drift
- [x] T2.2 integration test: lua_bridge_batch_windows
- [x] T2.3 unit test: drift detection edge cases
- [x] T3: DB schema bridge_batch_id + bridge_gen in tcp_results
- [x] T4: smart_fallback Lua hook (retrans + inbound RST detector)
- [x] T4: build_bridge_conf adds smart_fallback before scan_pick
- [x] 14 new unit tests (lua_bridge_edge_cases.py)
- [x] 4 new integration tests (test_lua_bridge_compare.py)
- [x] Live smoke: 200 strategies × 6 domains via --lua-bridge (317s total)

---

## CRITICAL: Потребление памяти `bs full` (~419 MB RSS)

**Статус:** ОТКРЫТО — 2026-08-12 (обнаружено при long-term серии A→F, машина 7.5 GB RAM)

### Диагноз (подтверждён исследованием, субагенты 2026-08-12)

**Главный потребитель — адаптивная очередь (~330 MB из ~407 MB анонимной памяти).**

**Уточнённые замеры (CPython 3.12.3, sys.getsizeof/tracemalloc, масштаб до 367 932 jobs):**

| Структура | Без слотов | Со slots | Экономия ×367 932 |
|---|---|---|---|
| `AdaptiveJob` (obj + `__dict__` + blobs/traits) | ~500-590 B | ~88 B | ~94 MB |
| `_HeapEntry` (obj + `__dict__`) | ~232-344 B | ~56 B | ~66-106 MB |
| `StrategyItem` (×30 661) | ~344 B | ~64 B | ~8.6 MB |
| `dict _pending` entry | ~52 B (не 100!) | — | ~19 MB |
| `set _done` entry | ~42 B (план пропускал) | — | ~6-15 MB |
| key-tuple `(label, domain)` ×2 (dict+heap) | ~56 B/шт | — | ~40 MB (план занижал) |

- `AdaptiveJobQueue.build()` (`adaptive_queue.py:354-370`) материализует **всю матрицу** 30 661 стратегий × 12 доменов = **367 932 jobs сразу** при старте.
- За 20ч-прогон используется только ~38% (≈139k jobs) — остальные 61% висят в памяти впустую.
- **~316 B на job — списки `blobs`/`traits`**, вычисленные заранее на каждый job (одинаковы для 12 доменов одного item), но нужны только при `mark_done(passed=True)` и в `ScanWeights.get`. **Кэш должен возвращать tuples, не списки** (иначе мутация одного job испортит все 12 братьев).
- Dataclasses **без `__slots__`** → каждый объект несёт `__dict__` (~272 B оверхед у job, ~184-296 B у heap entry).
- **Пропущенный CPU-bottleneck:** `_rebuild_heap` на ε-ветке `pop()` (`adaptive_queue.py:294,298`) и в `pop_batch` — полный rebuild 367k = ~0.07 s (на Xeon ~0.2 s) на каждый pop; `pending_domains_for_strategy` O(n). Chunking чинит; `heapq.heapify` даёт 2.5× даже без него.
- **`_done` set растёт монотонно (~6-15 MB), тримить НЕЛЬЗЯ** — fanout-дедупликация (`enqueue:261`) зависит от него.
- **fanout при полной матрице — фактически no-op** (все `(label, sibling)` уже в pending/done) — не переусложнять связку с chunking.
- **`sys.intern` не нужен** — строки уже общие через StrategyItem; трата в tuple, не строках.
- **SQLite/WAL — НЕ проблема памяти:** wal-index ≤32 KiB, авто-чекпоинт ~4 MB, каждое батч-флаш открывает свежее aiosqlite-соединение (page cache не живёт в RSS).
- RSS стабилен (не растёт) — разовая аллокация при `build_adaptive_queue`.
- Второстепенное: `jobs`+`asyncio.Queue` в `_run_tcp_sequential_bridge` (`main_phases.py:690-705`) дублируют всю матрицу (~25-30 MB, варианты B/D/E/F).

### План оптимизации (safe-first) — итог: 419 → ~110-130 MB

**Очередь = микросекунды против сетевых проб в секунды → оптимизация НЕ замедлит подбор; slots даже ускоряют (~35%).**

#### P0 — БЕЗОПАСНЫЕ ПАТЧИ (в первую очередь, ~170 MB, ~0 риск) — DONE 2026-08-12
- [x] `@dataclass(slots=True)` на `AdaptiveJob` (`adaptive_queue.py:200`) — 88 B вместо 344, экономия ~94 MB.
- [x] `@dataclass(order=True, slots=True)` на `_HeapEntry` (`adaptive_queue.py:229`) — 56 B вместо ~232-344.
- [x] `@dataclass(slots=True)` на `StrategyItem` (`generators/base.py:9`) — 64 B.
- [x] Удалить мёртвое поле `cluster`.
- [x] `_rebuild_heap` → list-comp + `heapq.heapify`.
- [x] E2E smoke: RSS 442 → 82 MB (полная матрица 290k jobs), 12 доменов изолированы.

**Питфоллы slots:** нет подклассов без slots (иначе вернётся `__dict__`); dataclass(slots=True) кидает TypeError если slots уже объявлен; pickle работает на protocol≥2.

#### P1 — ЛЕНИВЫЕ blobs/traits + shared key (~60-100 MB) — DONE 2026-08-12
- [x] `extract_blob_hints`/`strategy_traits` → `@functools.cache` (tuple), не считаются в `from_item`.
- [x] `blobs`/`traits` lazy `property` на `AdaptiveJob` (одна tuple на стратегию, разделяется 12 доменами).
- [x] Разделяемый lazy `_key` tuple (слот).
- [x] `cluster` удалён.
- [x] Измерено: per-job 88 B (было 586), blobs/traits/key общие 5 MB на 30 661 стратегию (было ~110-170 MB).

#### P2 — CHUNKING очереди (устраняет причину, ~300 MB: пик 419→110-130)
- [ ] `build_chunked(chunk_size=256)` — 1 чанк = 256 items × 12 доменов ≈ 3 072 jobs ≈ 1 MB.
- [ ] `queue.refill()` при `pop() is None`: сортирует следующие 256 items по текущим весам, resume-skip per-chunk против загруженного `completed_tcp` (`main_phases.py:498-500`).
- [ ] Интеграция в `_bridge_worker` (`adaptive_runner.py:235`) и `run_adaptive_tcp` — после `job is None` звать `refill()`.
- [ ] **Веса `ScanWeights` и `_done` живут ГЛОБАЛЬНО между чанками** (генетический буст + дедупликация не теряются).
- [ ] Opt-in: `chunk_size=None` → старое поведение (тесты не ломаются). CLI `--aq-chunk-size`.
- [ ] Бонус: чинтит stale-priority bug (приоритеты heap замораживаются при build) + убирает O(n·log n) rebuild.
- [ ] Чанк обязан брать ВСЕ домены выбранного item (иначе ломается googlevideo solo, `test_audit_fixes_1_0_1.py`, и fanout).

#### Sequential-bridge (варианты B/D/E/F) — ~25-30 MB
- [ ] Заменить `jobs` list + `asyncio.Queue` (`main_phases.py:690-705`) на generator/index, чтобы не материализовать полную матрицу.

#### HEARTBEAT + динамический RSS checker + load/unload по batch
- [ ] Фоновый периодический heartbeat (по образцу `RunDeadline`, `run_deadline.py:91-117`), сэмплит `os.getpid()` RSS каждые 5-10 s независимо от режима (сейчас `memory_monitor=None` в classic, `async_runner.py:184-196`).
- [ ] При high-watermark: уменьшить `bridge_batch` (мутабелен, `async_runner.py:115`), форсить `flush()`, при критическом — `run_single` вместо батча.
- [ ] `BatchJobAccumulator.set_batch_size()` (`batch_scheduler.py:73-76`).
- [ ] В `_bridge_worker` (`adaptive_runner.py:235-263`) — точки RSS-чека между pop/flush.
- [ ] Слить `_tcp_pending` через `SqliteRunStore.flush()` при спайке.
- [ ] Снизить `MEM_MONITOR_PY_MAX_MIB` до ~512 MiB (`config.py:391`, сейчас 2048 — на 7.5 GB машине ~6% бюджета).

#### ФЛАГ `--pi2mode` (Raspberry Pi 2 — 1 GB RAM, ARM, слабый CPU)
- [ ] Агрессивный профиль: chunking ON (малый chunk), `--parallel 1-2`, `--bridge-batch 50`.
- [ ] Низкий RSS-порог, жёсткий RSS-guard.
- [ ] Отключение тяжёлых фич: wssize/settle/ECH; уменьшенные timeouts; уменьшенный `--max`.
- [ ] `__slots__` обязательно применены.

#### Бонус-баги (найдены субагентом)
- [x] `_apply_provider_weights` (`adaptive_runner.py:100-101`) передавал cluster-строку как `traits` → мусор в trait-dict. Исправлено: `strategy_traits(strat)`. (2026-08-14)
- [ ] Stale-priority bug: приоритеты heap не обновляются после `boost_pass` — чинтится chunking'ом (P2, отложен).
- [x] `MEM_MONITOR_PY_MAX_MIB` 2048 → 512 (`config.py:391`). (2026-08-14)

#### Wave 2 — Lua TTL-RST + raw QUIC (2026-08-15, DONE)
- [x] `BridgeEvent.ttl` + `is_rst_in()`; rst_in → `fail_phase=TLS_RST_AT_SNI` + `rst_in_ttl`.
- [x] `checkers/quic_raw.py`: raw QUIC Initial (реальный блоб + RFC9000 fallback);
      PASS/QUIC_DROP/UDP_BLOCKED. В preflight → `triage.quic_drop`.
      Live: cloudflare PASS, youtube QUIC_DROP (LLC Fiord).
- [x] Блобы +3 (tls_5ka/quic_5ka/quic_rutube) из Flowseal 2026; README с описанием.

#### Новые баги (найдены при long-term прогонах 2026-08-14)
- [x] **sqlite "database is locked"** в конце прогона → `persist_adaptive_weights` не выполнился, scan_weights пуста при resume. Фикс: `PRAGMA journal_mode=WAL` + `busy_timeout=30000` в `_apply_pragmas`, retry×5 в `flush()`.
- [x] **Веса терялись при ошибке/дедлайне**: persist перенесён в `finally` в `_run_tcp_adaptive` — теперь сохраняются даже при crash.
- [ ] **P2 chunking отложен**: P0+P1 дали 82-286MB (стабильно), chunking рискован для рабочих прогонов. Сделать при следующем спокойном окне.
- [ ] **Heartbeat RSS-guard отложен**: memory_monitor есть для lua_bridge, порог снижен до 512MB. Динамический RSS-checker — при следующем окне.

### Верификация
- [ ] Unit: 1030+ pass (без регрессий) — `chunk_size=None` по умолчанию.
- [ ] ruff clean.
- [ ] E2E smoke 3 мин.
- [ ] Замер RSS до/после: **419 → ~250 MB (P0), → ~195 MB (P1), → ~110-130 MB (P2)**. Floor = интерпретатор + SQLite + curl/nfqws2 + StrategyItems ~2 MB + `_done` ≤15 MB.
- [ ] Скорость проб не падает (очередь μs vs сетевые s; slots ~35% быстрее attr access; chunking убирает 0.07s rebuild).
- [ ] Данные data_block не терять.
- [ ] Тесты-стражи: `test_adaptive_queue.py` (build/pop/fanout/ε), `test_adaptive_runner.py` (resume/stop), `test_batch_probe.py:27-28`, `test_batch_scheduler.py:26-27`, `test_audit_fixes_1_0_1.py` (googlevideo solo), `test_wave3_audit.py:19-35` (resume per-chunk).

### Референсы исследования (2026-08-12, субагент + интернет)
- `@dataclass(slots=True)` с 3.10; `weakref_slot`; TypeError если slots предопределён — https://docs.python.org/3/library/dataclasses.html
- Slots: подкласс без slots вернёт `__dict__`; нет `__weakref__`; attr access быстрее — https://docs.python.org/3/reference/datamodel.html#object.__slots__
- Slots память+скорость: 440→248 B/объект, ~35% быстрее — https://realpython.com/python-data-classes/
- heapq pattern dict+heap+set (как здесь) — https://docs.python.org/3/library/heapq.html
- SQLite WAL: wal-index ≤32 KiB, auto-checkpoint 1000 стр — https://www.sqlite.org/wal.html

---

## Long-term run series A→F (2026-08-12)

- [x] Скрипты: `scripts/run_variant.sh`, `run_long_term_series.sh`, `run_coverage_new.sh`, `monitor_series.sh`, docs `long_term_runs.md`.
- [x] **Фикс доменной изоляции** (`_run_tcp_sequential_bridge` — false-positive all-youtube; параллельные worker'ы + active_domains, `[run] domain_isolate`). E2E: 6 доменов равномерно. Commit `ffb41e4`.
- [x] Очищены 911 ложных PASS из data_block (commit `a31fa0a`).
- [x] Вариант A → `--adaptive`.
- [ ] Прогон A (adaptive) в процессе: 12 доменов изолированы, ~1.9/s, 0 PASS при timeout 1s (LLC Fiord медленный — B с timeout 2 должен дать PASS).
- [ ] Автозапуск B→F оркестратором (`bs-series`).
- [ ] **--resume** протестировать (мягкая остановка + перезапуск, проверить skip-счётчик).
