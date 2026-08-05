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
**Файл:** `src/blockchecks/cli/parser.py:262,344,382,415`  
**Текущее:** `--timeout default=5.0` на всех командах (tcp, scan, composite, pair)  
**Проблема:** DPI-блокировка детектируется за 2-3s (SYN+ClientHello либо проходит, либо silent-drop). 5s — запас, который умножается на количество FAIL-тестов.  
**Экономия:** 2s × 600 FAIL-проб = **~1200s** на full-скан.  
**Что сделать:**
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

**Ограничения:** см. §7 byedpi_engine.md. `badsum`/`tcp_ts_up` — SKIP. UDP/QUIC — nfqws2. Не тестировался на Fryazino — нужен живой прогон.

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
