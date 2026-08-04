# Backlog — blockcheckS

Открытые задачи после **1.0.2**. Закрытые фазы и release notes: [changelog.md](../changelog.md).

Приоритеты: **P1** = matrix/speed/protocol gaps; **P2** = voice/GP integration; **P3** = ML/hierarchy.

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

_(see Deferred)_

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
| **ML1–ML5** | Smart scan / sklearn — far corner |
| **H1–H10** | Progressive hierarchical scan — with ML |
| **M10** circular *scan* mode | L; export scaffold already exists |
| **A4** | GP-side multi-domain defaults (BS B2 done) |
| **B3** persistent nfqws2 | High risk; after B7 |
| **B6** blockcheckw | External / removed reference |
| **B7** nftables vmap | Optional host-shared POC; not needed for netns parallel |
| **GV-2** Playwright | Optional yt-dlp alternative |
| **unblock-pro** | External heuristics port |

---

## P3 — Smart scan (Phase 12) — deferred with ML

### ML ranker (sklearn)

- [ ] **ML1** optional-dep `scikit-learn` в `[project.optional-dependencies] ml`
- [ ] **ML2** `scripts/train_strategy_ranker.py` — export `state.db` → parquet → fit → `model.pkl`
- [ ] **ML3** feature parser: domain (TLD, cdn_class) + strategy (family/blob/repeats/fooling)
- [ ] **ML4** BS integration: `--ranker model.pkl` → top-K candidates
- [ ] **ML5** retrain policy: после mass scan / drift / provider change

### Hierarchical progressive scan

- [ ] **H1** спецификация «облака параметров»: оси (desync, blob, fooling, ttl, repeats, split…)
- [ ] **H2** `ProgressiveStrategyBuilder` — API: `add_axis()` → partial conf → test → branch
- [ ] **H3** default tree order из GP `family_rank` + Fryazino facts
- [ ] **H4** beam width B=3 — не только greedy
- [ ] **H5** интеграция в `bs scan --progressive` / `scan_level=progressive`
- [ ] **H6** лог partial results в DB (`partial_results`) для ML train
- [ ] **H7** learned axis order: contextual bandit / RF на domain_class
- [ ] **H8** provider template export из dpi-tester → A5
- [ ] **H9** benchmark vs full matrix на 10 доменах: Recall(best strategy found)
- [ ] **H10** fallback: progressive 0 PASS → expand beam / RF top-K / full family scan

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
- [ ] Добавить `--no-wssize` / `--wssize` флаг в CLI parser (оба `pair` и `full`)
- [ ] В `async_runner.py` guard: `if try_wssize and not args.no_wssize: ...`
- [ ] В `main_phases.py:413` и `pair_phases.py:186`: `try_wssize = not getattr(args, "no_wssize", False) and protocol == "tls12"`
- [ ] Дефолт для `bs full`: `--no-wssize` (без retry — full-скану важна скорость, wssize можно протестировать отдельным скан-левелом)
- [ ] Дефолт для `bs pair` / `bs scan`: `--wssize` оставить (короткие сканы, качество важнее скорости)

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
- [ ] Сменить дефолт `--db-batch` с `0` на `500` (или `200` для меньшей потери данных при краше)
- [ ] При batch>0 внутри `flush()` уже есть `BEGIN IMMEDIATE` + rollback — атомарность сохранена
- [ ] Проверить что `flush()` вызывается в `run_finalize.py` при остановке по таймауту/SIGINT

#### P0-4 — Settle overhead
**Файл:** `src/blockchecks/engine/nfqws2_settle.py:29-53`, `config.py:224-226`  
**Влияние:** **1.02–1.05×** (убирает 0.05s sleep + 1-2 pgrep = 0.15-0.25s per test)  
**План:**
- [ ] `BLOCKCHECKS_NFQWS2_SETTLE_MIN=0` (nfqws2 в daemon-режиме с `@config` стартует мгновенно)
- [ ] `BLOCKCHECKS_NFQWS2_SETTLE_POLL=0.05` (вместо 0.1)
- [ ] Проверить что `wait_nfqws2_ready` при min_wait=0 всё ещё корректно ждёт если nfqws2 ещё не запущен

#### P0-5 — Preflight skip флаги для повторных full-сканов
**Файл:** `src/blockchecks/engine/preflight.py:118-189`, `main_phases.py:182-204`  
**Влияние:** стартовое время (10-20 минут на 100+ доменах)  
**План:**
- [ ] `--skip-prolog` уже есть ✅
- [ ] `--skip-port-block` уже есть ✅
- [ ] `--skip-ip-block` уже есть ✅
- [ ] `--skip-dns-audit` уже есть ✅
- [ ] `--skip-baseline` уже есть ✅
- [ ] Все вместе при повторном full-скане: старт < 5 секунд

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
