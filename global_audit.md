# Global Audit — blockcheckS 1.3.9

**Дата:** 2026-08-26 · **Ветка:** alpha (`12debb4..74d60ca`) · **Метод:** 5 ревизионных агентов (архитектура · движок · runtime · QA/MCP · perf) + добор покрытия по **всем 132** `src/blockchecks/**/*.py` (карта §10) + 5 gap-fill сабагентов (CLI · checkers · engine · service/MCP · scripts/lua). Карта: **132/132** файлов. Уникальные P0/P1 добора — §13 (дубли QA-1/ENG-6.5/GAP-CHK-* не переоткрывать).

**Статус-метки находок:** `TODO` — требует работы · `FIXED (коммит)` — исправлено в этой сессии, раздел 8 · `WONTFIX/NOTE` — осознанное решение или наблюдение.

**Severity:** P1 — влияет на корректность результатов / теряет данные / клинит прод · P2 — надёжность, эффективность, качество данных · P3 — гигиена, мелкие риски.

---

## 1. Executive summary — топ-10

| # | ID | Находка | Где | Sev |
|---|----|---------|-----|-----|
| 1 | ENG-1 | Карантин отключён в бою: `quarantine = None` затирает объект перед `run_adaptive_tcp` | `main_phases.py:697` | **P1** |
| 2 | RT-1 | SIGTERM-хуки очистки пула никогда не устанавливаются (signal из worker-потока) → `bs stop` оставляет все netns/veth/NAT | `netns_pool.py:80-88` | **P1** |
| 3 | QA-1 | Дедлок MCP-triage: замыкание probe повторно захватывает не-реентерабельный `_lock` → демон клинится; тест замаскирован моком | `service/server.py:280-290` | **P1** |
| 4 | ENG-2 | Resume хоронит пары навсегда: «stopped before probe» пишется как FAIL + skip по любому статусу (наш кейс: 14k битых пар) | `sqlite_store.py:595`, `batch_service.py:132` | **P1** |
| 5 | PERF-1 | Полный python-старт (~250мс) + sudo на каждую пробу, включая bridge-mode → −50–70 CPU-ч на кампанию | `service/probe.py:58` | **P1** |
| 6 | PERF-2 | `_rebuild_heap()` O(n) на каждый батч → O(n²) на 800k очереди в classic-AQ | `adaptive_queue.py:477` | **P1** |
| 7 | ST-1 | Нет run_id/uuid/условий пробы в БД → смешение кампаний, невоспроизводимые вердикты | `schema.py:16-31` | **P1** |
| 8 | ARC-2 | Циклы пакетов engine↔service↔checkers↔cli не покрыты archrule | множественные | **P1** |
| 9 | ARC-6 | wssize-retry: одна политика с РАЗНЫМИ таймаутами в трёх путях → разные вердикты для одинаковой пары | `async_runner.py:401 vs 696` | **P1** |
| 10 | ARC-3 | 6 копий iptables-логики с противоположной семантикой очистки; `-F OUTPUT` в четырёх местах вопреки контракту Firewall | множественные | **P1** |

Полный реестр — разделы 2–7 (~70 позиций) + §11–13 добор. Исправленное в этой сессии — раздел 8. План лечения — раздел 9.

**P0/P1 добора (верифицировано по коду, не было в топ-10):**

| ID | Находка | Sev |
|---|---|-----|
| GAP-OPS-1 | `--orphans-only` без `--exclude-prefix` удаляет **все** netns, включая живую кампанию | **P1** |
| GAP-XPORT-1 | `bc-nfconf` / `_keep_export_strategy` отбрасывает `blob=4pda` до rename | **P1** |
| GAP-CFG-1 | ConfigFileGenerator склеивает multi-`--lua-desync` реальным `\\n` → static_validator skip (в т.ч. simple_fake_alt2) | **P1** |
| GAP-PAIR-1 | Pair phase подставляет фейковый `status=PASS` для coverage-лейблов без пробы на primary | **P1** |
| GAP-SEED-1 | shortlist/provider `--seed-db` не `flush()` — до 500 PASS теряются | **P1** |
| GAP-LOCK-1 | `run.lock` check-then-replace без O_EXCL → два кампании | **P1** |

---

## 2. Архитектура и связность

### ARC-1. God-object `AsyncTestRunner` — P1
**Где:** `engine/async_runner.py:99-1057` (конструктор ~20 параметров `:104-137`).
**Проблема:** ≥8 ответственностей в одном классе: пул netns, auto-pin DNS с записью на диск (`:251-339`), одиночные пробы TCP/QUIC/UDP, fanout, батч-оркестрация classic/bridge/compare, pair-матрица с checkpoint, запись в БД/data_block, memory-monitor, консольный рендеринг. `__all__` (`:68-93`) реэкспортирует приватные функции чужих модулей. DI через 15 коллбеков `_make_probe_deps` (`:169-187`).
**Влияние:** каждый фикс политики пробы — правка файла на 1000+ строк; тесты вынуждены строить runner целиком.
**Фикс:** вырезать `DnsPinService`, `PairMatrixRunner`, `ProbeResultLogger`, исполнители Tcp/Udp/QuicProbeExecutor; runner = композитор. Убрать алиасы приватных имён из `__all__`.
**Статус:** Сделано, коммит f310dbc (DnsPin + ResultLogger; TODO PairMatrix/Executors)

### ARC-2. Циклы пакетов engine↔service↔checkers↔cli/main — P1
**Где:** engine→service: `async_runner.py:20-24`, `in_ns_workers.py:40-44`, `test_runner.py:11-12`, `adaptive_runner.py:19`; service→engine: `probe_service.py:12`, `batch_scheduler.py:7`, `lua_session.py:12-13`, `server.py:272-573`; engine→checkers: `async_runner.py:13`, `in_ns_workers.py:16-27`; checkers→engine: `composite_runner.py:15` (импорт AsyncTestRunner из checkers!), +15 файлов; cli↔main: `cliapp.py:424,504`, `main_phases.py:362` (оркестратор вызывает приватную функцию CLI `_resume_generate_triage`).
**Влияние:** слоистая модель декларирована (`engine/__init__.py:1`), но archrule (`pyproject.toml:234-281`) не запрещает эти направления — связность растёт незаметно.
**Фикс:** зафиксировать уровни `core(config/paths/results) ← checkers ← probe-core ← batch/runner ← phases ← cli/main`; перенести in_ns_workers/test_runner в service; поднять `_resume_generate_triage` в нейтральный слой; добавить archrule на запрещённые импорты.
**Статус:** TODO

### ARC-3. Мультипликация iptables/NFQUEUE-логики — P1
**Где:** `service/firewall.py:37-99` (класс Firewall с точным `-D`-cleanup; докстринг «Never -F OUTPUT») vs `lua_netns.py:63-135` vs `in_ns_workers.py:111-131,199-215,375-392,578-595` (сырой sudo -A) vs `composite_runner.py:95-132`; плюс `-F OUTPUT` независимо в 4 местах (`in_ns_workers.py:111,199`, `netns_pool.py:250,279`, `lua_session.py:62-70`) — вопреки контракту Firewall.
**Влияние:** расхождение семантики очистки между путями исполнения → остаточные правила/разные вердикты для одинаковой пары в разных режимах.
**Фикс:** единый `NsFirewall.attach(queue,proto,port)` + `flush_output()`, все пути через него.
**Статус:** коммит 64fa8e4 (in_ns_workers closed)

### ARC-4. wssize-retry: одна политика, три реализации с расхождением — P1
**Где:** `async_runner.py:395-415` (`min(timeout,1.5)`) vs `:693-710` (**полный** timeout!) vs `batch_service._maybe_wssize_retry:496-531` (`min(timeout_i,1.5)`); хардкод `"wssize:wsize=1:scale=6"` в 3 местах.
**Влияние:** одинаковая пара стратегия×домен получает разные вердикты в зависимости от режима запуска.
**Фикс:** `WssizeRetryPolicy` в одном модуле.
**Статус:** Сделано, коммит f636316

### ARC-5. Двойной CLI-фронтенд — P1
**Где:** argparse `build_parser:609` (184 add_argument) + legacy `dispatch:960` + CliApp рефлексия приватных атрибутов argparse (`cliapp.py:180-197`: `_actions`, `_SubParsersAction`, `_choices_actions`, `_StoreTrueAction`); env-переключатель `BLOCKCHECKS_ARGPARSE`; второй полный build_parser только ради дефолтов (`cliapp.main:690-692`); argv-пре-скан для `--no-*` (`_NO_FLAGS_CAPTURED :705-714`); глобальные `_CMD_HANDLERS`; parity-таблица в pyproject:292-300.
**Влияние:** каждое новое поле флага требует синхронизации двух систем + ручной parity; ломается от минорных апгрейдов argparse.
**Фикс:** один фронтенд (argparse как источник, pydantic — проекция Namespace через `model_validate(vars(ns))`); убрать `_NO_PREFIX_FIELDS/_NO_FLAGS_CAPTURED` через `BooleanOptionalAction`.
**Статус:** Сделано, коммит 240949e

### ARC-6. Расходящиеся дубли реализаций — P2
- Запуск nfqws2: bind-retry в `start_daemon:111+` и в `Nfqws2Manager._launch:231+` — **Сделано** (`nfqws2_bind_retry_should_continue` в `nfqws2_settle.py`).
- QUIC-subprocess f-string payload: `in_ns_workers.py:220-236` vs `batch_bridge_probe.py:172-215` — **Сделано, коммит de7a0db** (`quic_subprocess_result` в http3).
- curl-payload dict: канонический `probe.probe_request_dict` vs ручной в `test_runner._check_tls_in_ns:37-59` (P3).
- Bridge-worker паттерн ×2: `adaptive_runner._bridge_worker:187-298` vs `main_phases._run_tcp_sequential_bridge:859-976` **Сделано, коммит b99b26b** (`BridgeWorkerPool`).
**Статус:** коммит 623061d (BridgeWorkerPool b99b26b; bind-retry helper)

### ARC-7. Глобальное мутируемое состояние процесса — P2
`cliapp.py:33-37` (_CMD_HANDLERS растёт при каждом main(), _CLI_EXIT_CODE, _USER_CFG, _NO_FLAGS_CAPTURED); `conf_builder.py:61-69` global manifest; `settings.py:139` lru_cache(1) замораживает конфиг на процесс; `ipset_catalog.py:114,127,140,184,213,296` — шесть lru_cache(1) поверх живых файлов; `adaptive_queue.py:48,59` @cache без maxsize (рост за 20ч прогон); `batch_service.py:561-572` _FANOUT_BRIDGE_WARNED; `netns_pool.py:25-26,70-73` atexit/signal глобально; `log.py:140,202,208-220` мутация env из SIGUSR1-обработчика; `config.py:157-183` refresh_tool_paths мутирует константы и env (NFQWS2_DEBUG читается на импорте :437 vs геттер :451 — два источника истины); `curl_probe.py:385` _ech_warned; `youtube_url.py:77`; `voice_discovery.py:33`.
**Влияние:** порядок тестов влияет на результат; два процесса кампании на одном $STATE затирают live-journal друг друга; unbounded-кэши на long-run.
**Фикс:** RunContext-объект; lru_cache → инстансы с invalidate(); live_events с run-id суффиксом.
**Статус:** TODO

### ARC-8. Точки расширения: новая семья = правки в 9 местах — P2
`generators/standard.py:97-123,240+`; `generators/families/*`; `family_needs.py:14-36` (второй независимый словарь знаний!); `family_registry.py:16-27`; `static_validator.py:12-31`; `blob_filter.py:46-47`; `in_ns_workers.py:323,470,538` ветки protocol==; `batch_bridge_probe.py:81-83`.
Новый backend: Literal в `batch_models.py:11`, развилка `_run_batch_sync:153-158`, `test_batch_tcp:777-787`, `resolve_probe_backend:241`, **5 строковых сравнений `== "lua_bridge"` в main_phases** (:520,711,776,827,1115).
**Фикс:** FamilySpec-реестр вместо 5 параллельных словарей; backend как объект-стратегия.
**Статус:** TODO

### ARC-9. Остаточные сцепления с соседним репо ../dpi-tester — P2
`config.py:91` fallback интерпретатора `../dpi-tester/.venv/bin/python` для ВСЕХ netns-субпроцессов (чужие версии curl_cffi в измерениях!); скрипты кампаний экспортируют `BLOCKCHECKS_SETTINGS=$ROOT/../dpi-tester/settings.ini` (run_full_20h.sh:12, run_coverage_new.sh:17, run_week_coverage.sh:32-33, run_variant.sh:77, run_full_coverage.sh:16); `voice_discovery.py:75-120` читает Discord-токены оттуда же. Не зафиксировано ни submodule, ни pip — на чистой машине молча деградирует.
**Фикс:** удалить fallback из `_resolve_python`; перенести [discord]/settings в собственный settings.example.toml.
**Статус:** коммит b155c6c

### ARC-10. Мёртвый абстрактный слой — P3
`engine/base_worker.py` (74 строки): 0 импортов во всём репо. Удалить либо реализовать.
**Статус:** Сделано, коммит 1c8f328
---

## 3. Корректность движка

### ENG-1. Карантин отключён в AQ-фазе — P1 ✅ подтверждено вручную
**Где:** `main_phases.py:697` (`quarantine = None` + неиспользуемый импорт `quarantine_from_args` рядом — след старого кода), сравни `:638-686` (объект построен, засеян, `ctx.quarantine` установлен) и `:714` (`run_adaptive_tcp(..., quarantine=quarantine)` → всегда None).
**Сценарий:** любой full/scan прогон: `_bridge_worker._account` (`adaptive_runner.py:200-207`) никогда не вызывает `record()` → mid-run карантин не срабатывает, таблица quarantined не пополняется, excluded_domains не расширяется. Pre-seeded домены исключены (снапшот до бага), но прирост за сеанс нулевой.
**Влияние:** мёртвые домены жгут слоты netns до конца прогона; мусорные FAIL-строки. Функциональность заявлена docstring'ом (`domain_quarantine.py:1-12`) и фактически выключена.
**Фикс:** удалить строки 697-698; передавать `ctx.quarantine`. Тест: mid-run домен с 300+ FAIL попадает в quarantine/excluded.
**Статус:** Сделано, коммит 65d3866

### ENG-2. Resume хоронит пары навсегда + фиктивные FAIL при остановке — P1
**Где:** `sqlite_store.py:595-606` (get_completed_tcp_keys: любой статус), `batch_service.py:60-67,132-146` («stopped before probe» → FAIL всем элементам батча; TimeoutError пула неотличим от остановки), `pair_phases.py:702-704`; дополнительно `zip(jobs,results,strict=False)` в `adaptive_runner.py:234` молча теряет хвост батча при stop_event.
**Сценарий:** semaphore-wait пересёкся со стопом/таймаутом → FAIL без пробы → resume считает пару сделанной навсегда. Наш кейс: 14 246 битых пар потребовали ручной чистки БД.
**Фикс:** (а) статус SKIPPED для непроведённых проб, исключённый из latest-row вердикта и resume; (б) get_completed_tcp_keys → latest-row WORKING-семантика; (в) `--reprobe-failed N` / retry_after для инфраструктурных fail_phase; (г) zip strict=True + доучёт недостающих job.
**Статус:** Сделано, коммит 5659771 (store/resume keys) + f636316 (SKIPPED + zip strict); TODO: (в) `--reprobe-failed`

### ENG-3. В bridge-режиме веса не влияют на планирование; triage-сид удваивается на каждом resume — P2
**Где:** приоритет считается в `enqueue()` (`adaptive_queue.py:297`); `boost_pass()` мутирует веса, но `_rebuild_heap()` вызывается только из classic `pop_batch:459-479` — bridge `pop()` никогда. `seed_from_triage:165-190` выполняется ПОСЛЕ загрузки персистентных весов (`adaptive_runner.py:50-56`) и делает `family[fam]=get(fam,1)*2.0` без cap (cap 64 есть только в boost_pass) → 2^N расползание между рестартами; provider-бусты суммируются каждый запуск.
**Влияние:** обучение за прогон влияет только на fanout-джобы; исходная матрица выбирается по приоритетам до первого PASS; межсеансовый дрейф приоритетов.
**Фикс:** периодический rebuild (раз в N=bridge_batch джобов) в bridge-воркере; seed через setdefault/cap.
**Статус:** Сделано, коммит ebfeb16

### ENG-4. SIGKILL теряет до ~1000 результатов; timestamp сдвинут ко flush — P2
**Где:** `_tcp_pending/_udp_pending` (`sqlite_store.py:50-53`), порог DEFAULT_DB_BATCH=500 (`store/__init__.py:91`), таймерного flush нет; `ts = strftime(...)` один на батч в момент flush (`:147`).
**Влияние:** kill -9/OOM между append и flush → результаты исчезают (WAL защищает только записанное); временные ряды врут на минуты; чужой читатель (MCP) видит БД без хвоста.
**Фикс:** таймерный auto-flush 10–30 c + per-row ts в log_tcp (+ epoch-ms UTC колонкой).
**Статус:** коммит 4e2bd2d

### ENG-5. GGC-пул: гонки без локов при 4+ to_thread воркерах — P2/P3
**Где:** `_ROTATION["i"] += 1` (`ggc_pool.py:226-232`) read-modify-write без блокировки; `_STATE.last_codes` append+slice не атомарно (`:123-136`); `remember_ggc_ip`/`cached_ips` — read-modify-write JSON без atomic-replace (`:174-199`) → потеря записей/обнуление кэша при гонке; индекс сбрасывается при рестарте процесса.
**Влияние:** дубли synthetic-hosts, потерянные повороты ротации, обнуление кэша IP (само-восстанавливается). Вердикты PASS/FAIL не искажаются.
**Фикс:** threading.Lock вокруг ротации/state; кэш через tmp+os.replace; опционально per-worker offset.
**Статус:** Сделано, коммит acbd0b5

### ENG-6. Прочие подтверждённые дефекты движка
| ID | Где | Дефект | Sev |
|----|-----|--------|-----|
| ENG-6.1 | `adaptive_runner.py:347-352` | Classic: джобы, отфильтрованные карантином после pop_batch — **Статус: Сделано, коммит ebfeb16** | LOW |
| ENG-6.2 | `sqlite_store.py:386-392` | Сид карантина считает THROTTLED как неуспех — **Статус: Сделано, коммит 5659771** | MEDIUM-LOW |
| ENG-6.3 | schema/store (grep DELETE/VACUUM = 0) | strategies/tcp_results растут неограниченно, GC/retention БД нет (gc.py чистит только файлы) | MEDIUM |
| ENG-6.4 | `custom.py:44` label replace, `fake.py:73` [:20], `:243` [:40] | Возможные коллизии имён после replace/усечения → смешение результатов разных конфигов в latest-row (UNIQUE(name,proto)); межсемейного dedup нет | LOW |
| ENG-6.5 | `matrix_generator.generate_udp` | udp_game принудительно перемаркируется udp_voice — **Статус: коммит b4e24b8** | LOW |
| ENG-6.6 | `adaptive_queue.py:96-97` | @cache без maxsize на строках стратегий — память, не корректность | INFO |
| ENG-6.7 | `sqlite_store.py:60-90` | ensure_strategy гонка только между разными инстансами одного файла (IntegrityError вместо upsert) | INFO |

**Проверено корректным:** epsilon-pop fallback-цепочка; drain-under-lock с восстановлением порядка; re-sync excluded_domains после DB-сида; чанкование filter_resume против EMFILE.

---

## 4. Runtime-надёжность

### RT-1. SIGTERM-хуки очистки пула — мёртвый код — P1
**Где:** `netns_pool.py:80-88` (`signal.signal` внутри try/except ValueError:pass), вызов из `async_runner.py:246` — создание пула идёт через `asyncio.to_thread`, в не-main потоке signal.signal ВСЕГДА ValueError → глотается молча.
**Сценарий:** `bs stop` (run_control.py:117 os.kill SIGTERM), systemctl stop → дефолтная диспо́зиция: процесс умирает немедленно, ни finally/atexit/хуки не выполняются → ВСЕ netns/veth/NAT/shm остаются до ручного cleanup_env.sh.
**Фикс:** ставить хуки в главном потоке до asyncio.run, либо loop.add_signal_handler; логировать невозможность установки.
**Статус:** Сделано, коммит 1b15231

### RT-2. Частичный boot ns не откатывается — P2
**Где:** `netns_pool.py:270-307`: имя попадает в rollback-список только после полного успеха `_create_one`; сбой между шагами (netns add OK, veth/NAT упал) оставляет полусозданный ns навсегда.
**Фикс:** детерминированное имя известно до создания — включать в rollback ДО первой команды.
**Статус:** Сделано, коммит 20a1e36

### RT-3. destroy_all теряет список имён до разрушения — P2
**Где:** `netns_pool.py:320-334`: `_names.clear()` до цикла `_destroy_one` (вне локов); исключение на середине → остальные ns не уничтожены, имена утрачены, повторный destroy_all выйдет по `if not self._created and not self._names`. atexit-обёртка `:89-93` глотает всё.
**Фикс:** копия списка + try/except на элемент + лог; clear после цикла.
**Статус:** Сделано, коммит 20a1e36

### RT-4. Пути разрушения полностью «беззвучны» — P2
**Где:** `netns_pool.py:100-116` (_run timeout→synthetic rc=-1) + `:216-251` (_destroy_one: все команды check=False, ни одного лога).
**Влияние:** D-state ns делает delete неудачным — правило/ns/veth остаются НАВСЕГДА без единого сообщения; диагностика только внешним скриптом.
**Фикс:** логировать ненулевой rc всех destroy-команд; счётчик успеха; эскалация.
**Статус:** Сделано, коммит 20a1e36
**Системный паттерн (RT-1..4): асимметрия «шумный create / безмолвный destroy»** — пути создания логируются и ретраятся, пути разрушения — check=False+except-pass.

### RT-5. ip_forward=1 включается глобально и никем не восстанавливается — P2
**Где:** `netns_pool.py:195`; grep по src/scripts/systemd — других упоминаний нет, включая cleanup_env.sh.
**Влияние:** постоянный host-state drift после кампаний.
**Фикс:** сохранить прежнее значение, восстанавливать в destroy_all/последнем destroy_one; опция restore в cleanup_env.sh.
**Статус:** Сделано, коммит 20a1e36

### RT-6. Артефакты SIGKILL вне зон покрытия gc/cleanup — P2
Источники: `/tmp/bs_nfq_*.conf` (nfqws2.py:131), `/tmp/bs_hostlist_*.txt` (:359), `/tmp/bs_nfqws2_*.conf` (:390), `/tmp/bs_discover_udp_*` (voice_dns.py:412), `.staging.*` в `/dev/shm/blockchecks/<ns>/` (lua_bridge_ipc.py:169-207). gc.py знает только nfqws2_*.log/run_summary/harvest/export-conf/tar.gz; cleanup_env.sh чистит shm, но не /tmp.
**Фикс:** добавить в collect_gc скан /dev/shm (возраст + отсутствие живого run.lock) и /tmp-глобы; в cleanup_env full-reset добавить /tmp.
**Статус:** Сделано, коммит 6b18435

### RT-7. Fire-and-forget Popen демонов не реапятся — P3
**Где:** `nfqws2.py:158-166`: объект Popen не сохраняется → убитые демоны становятся зомби до GC/subprocess._active прохода; при тысячах boot'ов (recycle/reboot регулярны) — накопление зомби-записей.
**Фикс:** слабый список + периодический poll.
**Статус:** Сделано, коммит 0bbe6ff

### RT-8. Reboot по recycle/debug-toggle без ожидания heartbeat — P2
**Где:** `batch_service.py:286-305` (recycle/toggle → session.boot() → probes сразу) против zero-events ветки `:340-361` (есть `_wait_heartbeat`). settle_max=0.5s может вернуть таймаут без демона; правило стоит с --queue-bypass → первая проба пакета проходит RAW → одиночный ложный вердикт после каждого recycle (при длинных кампаниях систематически).
**Фикс:** единый путь boot→wait-heartbeat для всех трёх триггеров.
**Статус:** Сделано, коммит 47dc9f7

### RT-9. Гонка unlink tmp_conf с медленным чтением демоном — P3
**Где:** `nfqws2.py:131,203-214`: готовность = «любой процесс comm=nfqws2 в ns», не конкретный PID; при задержке exec unlink conf может произойти до открытия @conf → демон умирает каскадом «zero events».
**Фикс:** держать conf до маркера чтения в out/debug-логе, либо per-session каталог конфигов.
**Статус:** Сделано, коммит 0bbe6ff

### RT-10. Результат _wait_nfqws2_gone игнорируется — P3
**Где:** `nfqws2.py:142-146`: bool не проверяется; при устойчиво «залипшем» процессе — 5 неудачных попыток и тихий возврат.
**Фикс:** логировать таймаут, учитывать в решении о retry.
**Статус:** Сделано, коммит 0bbe6ff

### RT-11. teardown_all_bridge_shm затирает shm чужих процессов — P3
**Где:** `lua_session.py:94-99` + `run_control.py:184-192`: rmtree всего SHM_BASE; две кампании от разных пользователей (разные lock-файлы) имеют общую shm-базу.
**Влияние:** завершение одной кампании удаляет IPC живой второй → потеря events, ложные PASS-without-APPLIED.
**Фикс:** удалять только каталоги своих ns.
**Статус:** коммит 8b6c9d4

### RT-12. MCP dbg фиксированное имя IPC-каталога — P3
**Где:** `server.py:462-472` LuaBridge("bs-mcp-dbg"): два параллельных dbg_inspect_lua — teardown первого сносит базу второго.
**Фикс:** уникальный суффикс на запрос.
**Статус:** Сделано, коммит e8121a8

### RT-13. Остатки except-pass в критичных путях очистки — P2/P3
`netns_pool.py:91-93` (atexit), `:172-174`, `:296-300` (rollback create_all!), `firewall.py:120-126` (cleanup -D), `voice_dns.py:432-441`. Любая ошибка очистки исчезает бесследно.
**Фикс:** log.warning с контекстом (образец уже есть в gc.py:83-86).
**Статус:** коммит ca2c6df

### RT-14. Деградация ACL-цепочки оставляет IPC нерабочим молча — P2
**Где:** `lua_bridge_ipc.py:39-79`: цепочка chmod→sudo-chmod(fail→**return без какого-либо доступа**)→setfacl(timeout 2c)→0777. Если sudo -n недоступен и setfacl отсутствует — выход по return: файлы root:root 0660, демон не читает strategy.* → Lua получает nil → все APPLIED теряются без объяснений. Альтернатива — 0777 на весь каталог с однократным warning.
**Фикс:** при полном провале raise/health-flag; кэшировать доступность setfacl (сейчас 3+ subprocess на publish).
**Статус:** Сделано, коммит dc470a6

### RT-15. rmtree/staging ignore_errors=True без лога — P3
**Где:** `lua_bridge_ipc.py:151-152,171-176`. Инвариант «shutdown = чистый shm» не гарантирован, никто не узнает.
**Статус:** Сделано, коммит dc470a6

### RT-16. Исчерпание пула маскируется под «остановку» — P3
**Где:** `batch_service.py:33` (ACQUIRE_NS_TIMEOUT=30) → тот же `_empty_stopped_result`, что при graceful-stop → триаж искажён.
**Фикс:** отдельный error-маркер «ns pool exhausted» + метрика.
**Статус:** Сделано, коммит 47dc9f7

### RT-17. sudo без -n в пуле — P2
**Где:** `netns_pool.py:109,226` (vs `sudo -n` в Nfqws2Manager:255). Парольный sudo → висит до timeout=15 на команду, в atexit stdin закрыт — вся тихая очистка гарантированно фейлится.
**Фикс:** единый `sudo -n` + явная ошибка «passwordless sudo required».
**Статус:** Сделано, коммит 1b15231

### RT-18. ENOSPC: IPC OSError валит весь пакет; WAL/.old вне gc — P3
**Где:** `lua_bridge_ipc.py:120-123` (OSError пробрасывается), gc.py не смотрит WAL/events_live.jsonl.old (ротация live_events.py:44-48 создаёт .old до 32МБ без удаления).
**Фикс:** детект ENOSPC с явным сообщением и ранним стопом; .old в gc.
**Статус:** Сделано, коммит dc470a6 (IPC ENOSPC); gc-half 6b18435

### RT-19. TODO/FIXME в фокусных модулях отсутствуют (grep=0) — техдолг нигде не промаркирован. NOTE

---

## 5. Хранилище и качество данных

### ST-1. Нет run_id / uuid пробы / версии кода — смешение кампаний — P1
**Где:** `schema.py:16-31` (tcp_results без run_id/probe_uuid); `bridge_batch_id/bridge_gen` сбрасываются каждым запуском (`async_runner.py:165-167`); matrix_fingerprint защищает только от смены списка стратегий, не доменов/времени/провайдера.
**Влияние:** один state.db копит все кампании; `--resume` через get_completed_tcp_keys считает сделанным всё, что писалось этим файлом ЛЮБОЙ прошлой кампанией; вердикты разных дней/конфигов неразличимы.
**Фикс:** таблица `runs(id, started_at, code_version, args_hash, fingerprint)` + run_id во всех results-таблицах; resume-скоуп по run_id.
**Статус:** Сделано, коммит c89f7d7

### ST-2. Flush: потеря буфера при краше + timestamp-shift + N+1 — P2
**Где:** `_tcp_pending` порог 500 без таймера (`sqlite_store.py:259-266`, `store/__init__.py:91`) → SIGKILL/OOM теряет до ~1000 строк; `ts = strftime(...)` один на батч в момент flush (`:147`) — время события уплывает на минуты; flush создаёт новое соединение + 6 PRAGMA (`:156`, `_apply_pragmas:91-98`) и делает N+1 `ensure_strategy` (SELECT+UPDATE на строку) под общим BEGIN IMMEDIATE (`:141-215`).
**Влияние:** запись БД — узкое место при parallel↑; чужие читатели видят БД без хвоста.
**Фикс:** per-row ts (+epoch-ms UTC), кэш `{(name,proto):id}`, executemany, одно долгоживущее соединение-писатель, таймерный flush.
**Статус:** коммит 4e2bd2d

### ST-3. Тест_tcp пишет resolved_ip не тот IP — P2
**Где:** `async_runner.py:436-448`: `resolved_ip=resolved_ip or ""` (DoH-кандидат), хотя retry-on-next-IP зондировал другой — `result.used_ip` игнорируется. Batch-путь корректен (`used_ip or resolved_ip`, :615).
**Влияние:** L3-триаж и pinning по одиночным пробам указывают на неверный IP.
**Фикс:** `resolved_ip=(result.used_ip or resolved_ip or "")`.
**Статус:** Сделано, коммит f636316

### ST-4. Нет индекса tcp_results(domain) — P2
**Где:** `schema.py:63-69`: индексы только (status)/(strategy_id,domain)/(strategy_id,domain,id DESC); частые запросы фильтруют по domain (`get_working_proto_details:556`, `domain_pass_rows:296` full-scan при старте карантина!, views v_coverage/v_latest_run).
**Фикс:** `CREATE INDEX idx_tcp_domain ON tcp_results(domain, strategy_id, id DESC)`.
**Статус:** Сделано, коммит 78b4907

### ST-5. Вердикт невоспроизводим по строке БД — P2
**Где:** log_tcp не сохраняет repeats/repeats_mode/фактический timeout (settle_profile может менять индивидуально! `async_runner.py:234-242`), disable_ech, impersonate-профиль, версию nfqws2/блобов; settle_ms вычисляется и выбрасывается; content_len не пишется; error обрезан до 120 симв.
**Влияние:** нельзя отличить изменение сети от смены условий пробы (подмена impersonate между запусками выглядит как «деградация стратегий»).
**Фикс:** конфигурация пробы в runs-заголовке + settle_ms/content_len колонки.
**Статус:** коммит 4e2bd2d

### ST-6. THROTTLED смешан с PASS в «working» — P3 NOTE
`_WORKING_STATUSES='(PASS,THROTTLED)'` во всех coverage/best запросах: экспорт best-config может отдать деградированный канал (<256КБ/с). Зафиксировать долю THROTTLED в отчётах.

### ST-7. Эксплуатация sqlite: нет wal_checkpoint/VACUUM/auto_vacuum — P3
grep по src = 0 совпадений. WAL растёт при постоянных писателях+читателях; БД сотни МБ никогда не уплотняется. Фикс: периодический PASSIVE-checkpoint + auto_vacuum=INCREMENTAL + VACUUM в finalize.
**Статус:** коммит 4e2bd2d

### ST-8. Прочее — P3
Соединение на операцию (29 мест aiosqlite.connect) + reclaim_sudo_ownership после каждого лога даже не под root (`:226,:310,:346,:367,:837`). query_strategies возвращает ошибки как элементы списка результатов (контрактная неоднородность).

---

## 6. Производительность

### PERF-1. Полный python-старт на каждую пробу — P1
**Где:** `service/probe.py:58-99` Popen(`python -m blockchecks.engine.in_ns_workers --mode curl`) — вызывается из classic `_run_tcp_check:425` И из bridge `batch_bridge_probe.py:150-160` (mode=single на каждый домен!). Замер: голый интерпретатор 18мс + import in_ns_workers **248мс** + sudo/exec ≈ 20-60мс.
**Влияние:** ~0.3с фикс-оверхеда на пробу → 50-70 CPU-ч на 700k джобов (12-17ч wall-time на 4 воркерах). Bridge-backend демонов переиспользует, интерпретатор — нет.
**Фикс:** долгоживущий воркер на ns (JSON-lines; batch-режим уже существует в curl_probe:411-437 — bridge шлёт single); минимум — переключить bridge-цикл на конвейерный воркер.
**Статус:** Сделано, коммит de7a0db

### PERF-2. pop_batch→_rebuild_heap O(n²) в classic-AQ — P1
**Где:** `adaptive_queue.py:477-478` rebuild после каждого батча; `pending_domains_for_strategy:442-443` линейный скан; `_rebuild_heap:412-421` аллокация n entries + heapify.
**Влияние:** 800k очередь × ~200k rebuilds ≈ 10¹¹ операций — классический режим деградирует до часов CPU только на очереди.
**Фикс:** lazy deletion (версионирование приоритета в entry), инкрементальные веса, индекс label→ключи.
**Статус:** Сделано, коммит 0d35760

### PERF-3. Память очереди ~450Б/джоб — P2
Замер tracemalloc: AdaptiveJob+_HeapEntry=291Б + dict/_done ≈ 400-450Б. 800k≈350МБ RSS; матрица 10M ≈ 4-4.5ГБ ещё до первой пробы; filter_resume держит 2×n указателей (`:491`).
**Фикс:** компактное хранение (key→idx, массивы), done в SQLite, генерация AdaptiveJob на лету.
**Статус:** TODO

### PERF-4. ε-greedy pop O(n) скан — P2
`adaptive_queue.py:344-352`: полный список pending на ~10% попов → 80k-элементные списки десятки тысяч раз.
**Фикс:** reservoir sampling / индексная структура.
**Статус:** Сделано, коммит 0d35760

### PERF-5. fanout_on_pass: regex O(passes×domains) — P2
`adaptive_queue.py:399-409` → `cluster_domain:30-39` без кэша; 100k PASS × 5000 доменов × 3 regex ≈ 10⁹ вызовов.
**Фикс:** предрассчитать cluster→[domains]; lru_cache на cluster_domain.
**Статус:** Сделано, коммит 0d35760

### PERF-6. sudo/iptables шторм на пробу и релиз ns — P2
`in_ns_workers.py:377-386` (-A на каждую пробу), `:111,199` (-F на каждую попытку QUIC/UDP), release→pkill+-F+teardown (lua_netns:34-47, netns_pool release): 5-7 sudo/ip процессов на одну solo-пробу; параллельные iptables сериализуются на xtables-lock.
**Влияние:** при parallel=16 — рост очереди fork/exec, деградация settle.
**Фикс:** правило заливать один раз при создании ns (пересоздавать только после аварийного flush); cleanup по флагу «грязный ns».
**Статус:** коммит 64fa8e4 (in_ns_workers closed)

### PERF-7. Прочее — P3
Тяжёлые top-level импорты воркера (`in_ns_workers.py:14-45` тянет conf_builder/config/nfqws_config/service.nfqws2 — зондировщику нужен только curl_probe) — основа 248мс; новая Session+полный handshake на каждый repeat (`curl_probe.py:269-296` цикл `:385-407`); impersonate_target читает env каждую сессию (`:36-41`); QUIC/UDP через embedded `python -c` (дубль паттерна).

### PERF-8. Масштабируемость — прогноз
parallel=16 сломается первым на процессном шторме (PERF-1/6) затем на _flush_lock; матрица 10M умрёт последовательно: OOM очереди (~4.5ГБ) → classic AQ O(n²) → resume set 10M кортежей (~2ГБ, блокирующий fetchall) → SQLite без индекса domain (минуты на запрос).

---

## 7. Тесты / CI / Docs / MCP

### QA-1. Дедлок MCP-triage замаскирован тестом — P1
**Где:** `service/server.py:280-290`: замыкание probe делает `async with self.service._lock:` (:283) и вызывается под тем же замком (:288); asyncio.Lock не реентерабелен → вечное ожидание; `PreflightOptions(skip_diagnostics=False)` гарантирует запуск fooling-grid (`preflight.py:589-595` → awaited probe_fn). Один вызов MCP triage_domain клинит демон навсегда (последующие probe/triage/find_strategy висят на том же локе, `probe_service.py:202`).
Маскировка: `tests/unit/test_preflight.py:712-735` подменяет run_preflight_async целиком AsyncMock и проверяет лишь callable(opts.fooling_probe_fn).
**Фикс:** не захватывать замок в замыкании (уже удержан) / освободить внешний перед grid-фазой / отдельный probe-lock. Интеграционный unit-тест с настоящим run_preflight_async + wait_for(timeout=5) — сегодня падает по таймауту.
**Статус:** Сделано, коммит 7cca7f5

### QA-2. Integration/mutation/armv7l джобы никогда не выполняются автоматически — P1
**Где:** `.github/workflows/ci.yml:160-173`: integration только workflow_dispatch, без nfqws2 на раннере — `exit 0`. 
**Влияние:** регрессии netns-lifecycle/nfqws2-флагов/nftables/lua-IPC гарантированно проходят CI; единственная защита — ручные смоки (release_smoke/smoke_all), нигде не enforced.
**Фикс:** self-hosted runner на probe host с обязательным `-m integration` на push alpha/master; убрать безусловный exit 0.
**Статус:** TODO

### QA-3. generate_router_config при живом демоне игнорирует БД — P2
**Где:** daemon-handler `_handle_generate_config` (`service/server.py:419-420`) всегда строит из двух захардкоженных stock-стратегий; офлайн-fallback честно выбирает топ PASS из state.db (`mcp/server.py:249-270`). У пользователя с работающим bs serve инструмент выдаёт ХУЖЕ, чем без него — инверсия контракта («from the highest-scoring PASS strategies», mcp/server.py:226-229). Тест не видит: fake-демон возвращает произвольную строку.
**Фикс:** handler читает топ PASS через store; stock — fallback.
**Статус:** Сделано, коммит e8121a8

### QA-4. HTTP bridge читает тело неограниченного размера ДО авторизации — P2
**Где:** `service/server.py:748-757` readexactly(content_length) без верхней границы; токен проверяется после полного чтения (:893-895). Неаутентифицированный клиент с Content-Length:10G → аллокация 10ГБ (OOM) до 401.
**Фикс:** cap Content-Length (1MiB) + 413 до чтения.
**Статус:** Сделано, коммит 7cca7f5

### QA-5. Слабые ассерты и тесты реализации — P2
«assert True» единственный случай (`test_lua_session.py:107`); `"error" in result or "path" in result` (`test_mcp_server.py`); плотность <1.1 assert/тест в test_run_finalize (0.95), test_main_phases (66 тестов, 0 pytest.raises!), test_commands_*, test_gv_url; массовое патчирование приватных атрибутов (`runner._run_probe_batch`, `mgr._pid/_temp_files`, `bp._debug_env`). conftest mock_tcp_udp всегда success=True/200 — FAIL/TIMEOUT/THROTTLED ветки в общих фазах не покрыты.
**Фикс:** параметризовать фикстуру профилями ответов; ассерты на содержимое экспорта; негативные ветки.
**Статус:** TODO

### QA-6. ТОП-10 непокрытых критичных зон
base_worker.py (74 строки, 0 импортов — мёртвый слой!); batch_service ветки boot-fail/retry/таймаутов; реальное исполнение in_ns_workers внутри netns; реальные TLS-ошибки curl_probe; фактическое применение firewall; main_phases resume/checkpoint/export над реальным store; harvest_batch CLI-обвязка; lua IPC с настоящим scan_bridge.lua; adaptive_runner asyncio.TimeoutError mid-run + restore tap'ов; HTTP bridge edge-cases (oversized/медленные клиенты).

### QA-7. pytest-randomly остаточные риски — P2
seed нигде не фиксируется; lru_cache settings/ipset очищается только в собственных тестах (будущий тест, читающий кэш после смены env чужим тестом, — флейка); восстановления вида `ca._FULL_RUN_ACTIVE=False` пишут литерал вместо исходного значения; operator_logs при исключении между yield и очисткой оставляет битую конфигурацию логгера.
**Фикс:** autouse-фикстура сброса load_settings/ipset-кэшей; восстанавливать исходные значения.

### QA-8. Docs drift — P2/P3
`long_term_runs.md:56`: пример `RunStateStore(path=...)` даёт TypeError (Protocols cannot be instantiated) — рабочий вариант SqliteRunStore(db_path=...)/open_run_store. `api.md:83` заявлено 19 MCP-инструментов, фактически 22 (нет get_campaign_domains_summary/get_provider_profile/get_live_events); mcp.md §3 противоречит собственной таблице по слоям A/A2. `database.md:130` «synchronous=OFF» vs код NORMAL; ER tcp_results без bridge_applied/probe_host. architecture.md карта модулей не знает ggc_pool/domain_quarantine/harvest_batch/live_events/metrics; package.md — ни одного упоминания. harvest_batch формат манифеста v1/saturation описан только в docstring.
**Фикс:** синхронизация + тест-парсер `@mcp.tool()` ↔ docs (правило api.md §10.5 нарушено).
**Статус:** ЧАСТИЧНО (probe_host/database.md дополнены сегодня)

### QA-9. pyproject/requirements — P3
Открытые нижние границы без lockfile/constraints (curl-cffi>=0.8 при установленном 0.16.1); requirements.txt вручную зеркалит pyproject (расходится стилем маркера); pytest-cov объявлен, но не используется ни CI, ни гейтами (полумёртвая зависимость); .coverage в корне stale (11 августа). CI гоняет только Python 3.12 — ветка tomli/py<3.11 не тестируется никем.

### QA-10. Мелочи MCP — P3
Bearer-сравнение не constant-time (`server.py:895` → hmac.compare_digest бесплатен); get_series_status: синхронный sqlite в async-туле (до 2с блокировки loop) + quarantined без LIMIT + наивный argv-парсинг (`--max --resume` даст max="--resume"); dbg_probe_raw TIMEOUT только для connect_timeout фазы; no-op ветка dry_run_db; fake_blob молча игнорируется при наличии blob= в стратегии. Позитив: сокет 0600, health без токена единственный, anti-traversal покрыт тестом, fair-exclusion подтверждён.
**Статус:** Сделано, коммит 7cca7f5

---

## 8. Уже исправлено в этой сессии (не переоткрывать)

| Коммит | Что |
|---|---|
| `74d60ca` | Last-resort GGC: ротация **только** `DEFAULT_LAST_RESORT_IPS` (env/dns/кэш — голова списка); IPC warning `path` затем overflow-uid; тесты dns.db-тира, `prepare_ggc_probe`, `open_out_capture` |
| `a7e8f34` | **ECH-off best-effort**: биндинг знает CURLOPT_ECH(10325), вшитый libcurl — нет; setopt-ошибка абортила 100% gv/static проб. Теперь warning-once + продолжение. Юнит-тесты контракта |
| `12debb4` | GGC-ротация живых IP по тирам; мёртвый 74.125.108.234 исключён из fallbacks.txt/config/ipset_catalog/тестов; QUIC probe_host chain; NFQWS2_BIND_ATTEMPTS |
| `cbad0c6` | probe_host в QUIC/classic; bind-retry Manager; IptablesError abort boot; [google].mode из toml; sudo-aware expand_path |
| `241ba46` | Развитие тех же направлений агентом (loud warnings вместо except-pass в ggc_pool/nfqws2) |
| `fb08b56` | stdout-захват nfqws2 (bind-ошибки видны!) + bind-retry start_daemon + probe_host колонка |
| `af99104` | ACL overflow-uid + sudo-chmod fallback; loud iptables errors |
| `40a848c` | XDG → SUDO_USER home под sudo |
| `594efbe` | ggc_pool модуль (synthetic/real/fixed), карантин re-sync, пресет 25 доменов |
| `a6ded46` | Карантин re-sync после сидирования (pre-seed работает) |
| ручное | Чистка 13900 shm-мусорных FAIL строк из yt_cov.db; очистка quarantine yt_cov (10 доменов, отравлены инфраструктурными фейлами) |

Проверено корректным в ходе аудита (не трогать): epsilon-pop fallback-цепочка; drain-under-lock flush; publish gen-first commit order; scoped kill по inode netns; busy_timeout+ретраи locked; latest-row индексы; чанкование filter_resume; fair-exclusion через run.lock; anti-traversal MCP.

---

## 9. План лечения

### Wave 1 — quick wins (каждый ≤1ч, высокий профит)
1. ENG-1: удалить `quarantine=None` затирание (+тест mid-run карантина)
2. ENG-2а: статус SKIPPED для «stopped before probe» + исключить из resume
3. ARC-4: WssizeRetryPolicy единый (min(timeout,1.5))
4. ST-3: resolved_ip=used_ip в test_tcp
5. RT-17: `sudo -n` в пуле + fail-fast сообщение
6. QA-4: cap Content-Length до auth
7. ARC-9: удалить dpi-tester python-fallback
8. RT-13: except-pass → log.warning в cleanup путях пула
9. QA-10: hmac.compare_digest + LIMIT quarantined + argv-parse guard
10. ENG-6.2: THROTTLED считать успехом в сидировании карантина

### Wave 2 — структурные (по 0.5-2 дня)
1. RT-1: signal-handlers в главном потоке (P1!)
2. ENG-2б: get_completed_tcp_keys WORKING-семантика + --reprobe-failed
3. ENG-3: периодический rebuild heap в bridge + cap triage-сида
4. ENG-4/ST-2: per-row ts + таймерный flush + strategy-id кэш + executemany
5. PERF-1/1.2: долгоживущий воркер + тонкие импорты (−0.3с/проба)
6. PERF-2/4/5: lazy-deletion heap, ε-sampling, cluster-кэш
7. ST-4: индекс tcp_results(domain)
8. RT-2/3/4/13: детерминированный rollback destroy-путей с логами
9. RT-6: gc/cleanup покрытие shm//tmp артефактов SIGKILL
10. QA-3/4: generate_router_config из БД; Content-Length cap
11. ARC-7 частично: RunContext для настроек/warning-флагов

### Wave 3 — рефакторинг (планировать отдельно)
1. ARC-1: декомпозиция AsyncTestRunner (DnsPinService/PairMatrixRunner/ProbeResultLogger/Executors)
2. ARC-3/ARC-6: NsFirewall единый + WssizeRetryPolicy + BridgeWorkerPool + quic_subprocess_result
3. ARC-2: archrule-фиксация слоёв + перенос in_ns_workers/test_runner
4. ARC-5: один CLI-фронтенд
5. ARC-8: FamilySpec-реестр + backend-стратегия
6. ST-1: runs/run_id схема (миграция)
7. PERF-3: компактная очередь (актуально при матрицах ≥10M)

### Операционные правила (уже действуют)
- Смоки (`smoke_full_quick` + `smoke_backend_matrix`) перед каждым деплоем движка
- После sudo↔user переключения стиля запуска: полная очистка shm (/dev/shm/blockchecks)
- Чистка битых окон: критерий `status='FAIL' AND http_code=0 AND error LIKE '%dev/shm%'`
- Мониторинг прогона: фамильные срезы + probe_host ротация + read_rate_bps + zero-events доля

---

## 10. Карта покрытия исходников (132 `.py`)

Первый проход аудита бил в «горячий путь» кампании (runner/AQ/netns/store/MCP). Ниже — **полный инвентарь**: каждый файл либо уже разобран в §§2–7, либо закрыт добором §11, либо помечен CLEAN/NOTE (прочитан, дефекта уровня реестра нет).

**Легенда:** `§` — находка в разделах 2–7 · `GAP` — новая находка §11 · `CLEAN` — прочитан, без нового дефекта · `NOTE` — наблюдение без бага.

### 10.1 Root / CLI / экспорт (~8.5k LOC)

| Файл | LOC | Статус |
|---|---:|---|
| `bs.py` | 14 | CLEAN (тонкий `main`) |
| `main.py` | 152 | NOTE: оркестратор `full`; карантин/backend — ENG-1, ARC-8 |
| `main_phases.py` | 1303 | § ENG-1, ARC-2/8 |
| `terminal.py` | 105 | CLEAN (ANSI/теги) |
| `harvest_batch.py` | 267 | GAP-DAT-1; THROTTLED=working как ST-6 |
| `nfconf.py` | 402 | GAP-DAT-2 (common_only fallback) |
| `provider_import.py` | 234 | CLEAN (импорт провайдера в XDG) |
| `shortlist_export.py` / `shortlist_import.py` | 198+214 | NOTE: экспорт shortlist; QUIC через `get_best_quic` уже с `probe_host` |
| `cli/parser.py` | 1133 | ARC-5 (184 флага); дубли `--http-off`=`--no-http` |
| `cli/cliapp.py` | 736 | ARC-5/7 |
| `cli/presets.py` | 66 | CLEAN |
| `cli/profiles.py` | 107 | CLEAN (`smoke`/`fast`/`20h`) |
| `cli/user_config.py` | 116 | NOTE: toml→argparse defaults; кэш settings — ARC-7 |
| `cli/commands/tcp.py` / `udp.py` | 124+128 | CLEAN (loader+TestRunner) |
| `cli/commands/pair.py` | 211 | NOTE: делегирует `pair_phases` |
| `cli/commands/pair_phases.py` | 893 | ENG-2 (checkpoint); DPI_TESTER_SETTINGS — ARC-9 |
| `cli/commands/preflight.py` | 120 | QA-1 (через serve) |
| `cli/commands/serve.py` / `stop.py` / `mcp.py` | 92+18+22 | RT-1 (`bs stop`→SIGTERM); CLEAN тонкие обёртки |
| `cli/commands/data_block.py` / `gc.py` / `harvest_batch.py` | 34+26+66 | CLEAN CLI-клей |
| `cli/commands/bench_settle.py` | 161 | NOTE: пишет settle-profile; AUTO_LOAD_MIN_CURL=2.0 |

### 10.2 Checkers (~5.3k LOC)

| Файл | LOC | Статус |
|---|---:|---|
| `curl_probe.py` | 1065 | PERF-7; TLS bypass 401/403/404; ECH `a7e8f34`; `_ech_warned` ARC-7 |
| `dns_secure.py` | 679 | NOTE: DoH pin + audit; hijack=tampering, sinkhole отдельно |
| `tcp_tls.py` | 261 | NOTE: Discord family redirects + TLS-proof statuses (согласовано с curl_probe) |
| `fooling_probe.py` | 178 | **GAP-CHK-1** viable без 401/403/404 |
| `http3.py` | 92 | **GAP-CHK-2** curl_cffi `v3only` ≠ реальный QUIC UDP на Fryazino |
| `quic_raw.py` | 181 | CLEAN (сырой Initial UDP/443; blob→synthetic warning) |
| `udp_voice.py` | 234 | RT-13 except-pass; NOTE STUN/burst |
| `voice_dns.py` | 601 | RT-6 `/tmp/bs_discover_udp_*`; except-pass |
| `voice_discovery.py` | 341 | ARC-9 токены dpi-tester; except-pass |
| `youtube_url.py` | 191 | ARC-7 global; CI мок `which` |
| `l3_probe.py` / `ttl_probe.py` / `ip_block.py` / `ip_pin.py` / `port_block.py` | 157+105+165+94+79 | CLEAN классификаторы L3/TTL/IP/port (raw ICMP best-effort) |
| `composite_runner.py` | 184 | ARC-2/3 (импорт AsyncTestRunner + свой iptables) |
| `dpi_diag/{runner,probes,classify,dns_as}.py` | 98+210+27+31 | NOTE: свой classify **не** патчит FailPhase (хорошо); отдельный контур диагностики |

### 10.3 Engine (~14k LOC) — добор сверх §§2–3

Уже в реестре: `async_runner`, `adaptive_*`, `in_ns_workers`, `ggc_pool`, `store/*`, `preflight`, `domain_quarantine`, `conf_builder`, `config`, `settings`, `ipset_catalog`, `gc`, `log`, `family_*`, `static_validator`, `test_runner`, `blob_filter`, `generators/standard|custom|fake`, `base_worker`.

| Файл | LOC | Статус |
|---|---:|---|
| `fail_phase.py` | 136 | **GAP-ENG-A** `_PASS_HTTP`; **Статус:** коммит 83431ee DATA_STALL_7K word-boundary |
| `byedpi_translator.py` | 306 | **GAP-ENG-B** `tcp_ts→--ttl` PARTIAL — на Fryazino это другая семантика |
| `byedpi_matrix_generator.py` | 129 | NOTE: матрица только транслируемых семей |
| `blob_aliases.py` | 244 | NOTE: `4pda`/`p4da` → один файл (урок PASS-without-APPLIED) |
| `matrix_generator.py` | 341 | ENG-6.5 udp_game→udp_voice — **Статус: коммит b4e24b8** |
| `generators/flowseal.py` | 369 | NOTE: каталог Flowseal→nfqws2 |
| `generators/families/{split,tamper,_helpers}.py` | 325+332+175 | ARC-8; ENG-6.4 усечение имён |
| `generators/base.py` | 41 | CLEAN StrategyItem |
| `domain_loader.py` | 190 | NOTE: denylist XDG overlay; `auto_enable_gv_ggc` setdefault env |
| `preset_paths.py` | 150 | **Статус:** коммит 83431ee sudo ipset expand_path |
| `paths.py` | 363 | `40a848c` SUDO_USER; NOTE |
| `nfqws_config.py` | 87 | **Статус:** коммит 83431ee QUIC CLI blob inject |
| `strategy_loader.py` | 64 | **Статус:** коммит 83431ee from_file \\n + from_config warn |
| `settle_profile.py` | 183 | ST-5 (таймауты не в tcp_results); AUTO_LOAD_MIN_CURL |
| `run_deadline.py` | 148 | CLEAN monotonic+CancelledError проброс |
| `run_finalize.py` | 196 | **GAP-DAT-3** early-return best_config без лога |
| `run_spec.py` | 192 | CLEAN pydantic RunSpec |
| `tcp_fanout.py` | 100 | CLEAN gv всегда solo |
| `system_deps.py` | 495 | NOTE: vendor zapret2 из GitHub; не путь кампании |
| `triage.py` | 260 | NOTE: профиль ТСПУ; ECH-off из triage |
| `results.py` | 85 | CLEAN dataclass + probe_host |
| `secure_io.py` | 24 | **Статус:** коммит 83431ee OSError/UnicodeError + reclaim |
| `db_logger.py` | 22 | CLEAN тонкая обёртка |
| `_probe_worker.py` / `_curl_probe_worker.py` | 30+26 | CLEAN entrypoints `-m` |

### 10.4 Service / MCP / data_block (~6.5k LOC)

Уже в реестре: `netns_pool`, `nfqws2`, `lua_bridge_ipc`, `lua_session`, `lua_netns`, `batch_service`, `batch_bridge_probe`, `batch_scheduler`, `batch_models`, `firewall`, `probe`, `probe_service`, `run_control`, `server`, `mcp/server`.

| Файл | LOC | Статус |
|---|---:|---|
| `lua_conf.py` | 126 | NOTE: blob rename через aliases; stage lua в writable IPC |
| `metrics.py` | 251 | NOTE: `pkill_nfqws2_in_ns` по inode — канон (не `netns exec pkill`) |
| `nfqws2_settle.py` | 79 | RT-8/9: ready = процесс в ns, не heartbeat; возврат elapsed при таймауте |
| `live_events.py` | 137 | RT-18 `.jsonl.old`; ARC-7 один файл на $STATE |
| `data_block/provider.py` | 302 | NOTE: ipinfo slug + XDG |
| `data_block/store.py` | 539 | NOTE: dns.db/strategies.db/triage.toml |
| `data_block/export.py` | 79 | NOTE: copy XDG→submodule, WAL skip |

### 10.5 Вне Python (исполняемое)

| Артефакт | Статус |
|---|---|
| `scripts/run_week_coverage.sh` и 20h/coverage | ARC-9 `BLOCKCHECKS_SETTINGS=../dpi-tester` |
| `cleanup_env.sh` | грабли AGENTS.md (не гонять full во время кампании) |
| `lua/scan_bridge.lua` (в дереве blockchecks lua) | heartbeat-fence 200ms; APPLIED events |
| `.github/workflows/ci.yml` | QA-2 шарды; не монолитный pytest |
| `presets/ipset/fallbacks.txt` | 74d60ca `ggc 64.233.161.198` |

`__init__.py` пакетов (12 шт., ~100 LOC суммарно) — CLEAN реэкспорт/пакетные докстринги.

**Итог покрытия:** 132/132 `.py` в `src/blockchecks` имеют строку в §10. Находки уровня реестра по добору — §11 (не дублируют ENG/RT/QA с теми же file:line).

---

## 11. Добор находок (слои вне первого прохода)

### GAP-CHK-1. Fooling-grid не считает TLS-bypass 401/403/404 «живым» — P2
**Где:** `fooling_probe.py:49-58` (`is_fooling_viable`: только 200/204/101 и `phase==pass`).
**Проблема:** `curl_probe` с 1.3.8 трактует 401/403/404 по TLS как PASS (`_TLS_BYPASS_PROOF_STATUSES`). Fooling-grid и `classify_fail_phase` (пустой error + 403 → `http_403`, не `pass`) помечают ту же пробу как fail. Preflight **вырезает** fooling, который на Fryazino как раз работает (часто ответ Google — 403 + `gvs`).
**Влияние:** `map_triage_to_generators` недополучает tcp_ts/fake; матрица беднее боевой реальности.
**Фикс:** viable = те же статусы, что `_TLS_BYPASS_PROOF_STATUSES` ∪ {200,204,206,101}; `classify_fail_phase`: пустой error + TLS-proof → `PASS`.
**Статус:** Сделано, коммит 65d3866

### GAP-CHK-2. `check_http3` — ALPN-ложняк, не захват QUIC Initial — P2 NOTE
**Где:** `http3.py:38-73` (`http_version="v3only"` / HEAD).
**Проблема:** на Fryazino curl_cffi HTTP/3 не шлёт реальные UDP:443 (факт AGENTS.md). Сырой путь — `quic_raw.py` + `dev/capture_quic_blob.sh`.
**Влияние:** фаза `--quic` / preflight QUIC может дать ложный DROP/OK независимо от ТСПУ.
**Фикс:** не использовать http3 как оракул YouTube-QUIC; для YouTube — только `quic_raw` / внешний захват.
**Статус:** NOTE (не регрессия кода, контракт чекера)

### GAP-ENG-A. FailPhase расходится с TLS-bypass proof — P2
**Где:** `fail_phase.py:119-131` `_PASS_HTTP={200,204,206}`; паттерн HTTP_BLOCKED `:114` (`403|451|captcha`).
**Проблема:** успех с http=403 классифицируется как `http_403`. Текст ошибки с «403» → HTTP_BLOCKED даже при TLS handshake OK. `probe_service.from_tcp_result` на success обнуляет phase (`:47`) — MCP ок; **preflight `_apply_prolog`** при `tls.success` ставит PASS (`:514-515`) — ок. Битый путь — fooling_grid (GAP-CHK-1) и любой потребитель `classify_fail_phase` без проверки `success`.
**Фикс:** единый `_PASS_HTTP` с TLS-proof; HTTP_BLOCKED не матчить голый `403`.
**Статус:** Сделано, коммит 65d3866

### GAP-ENG-B. byedpi: `tcp_ts` → `--ttl 8` — P2
**Где:** `byedpi_translator.py:137-149`, `_DROPPABLE_FOOLINGS` без `tcp_ts` (мапится, не дропается).
**Проблема:** на Fryazino `tcp_ts=-1000` — рабочий fooling nfqws2; `--ttl` в ciadpi — другой механизм. Quality=PARTIAL, но `can_translate()` = True → внешняя валидация (harvest→dpi-tester/byedpi) гоняет **не ту** атаку.
**Влияние:** ложные FAIL валидатора на стратегиях, которые в nfqws2 PASS.
**Фикс:** `tcp_ts*` → untranslatable (None) либо явный флаг `--partial-ok`; не кормить harvest/byedpi без quality=FULL.
**Статус:** Сделано, коммит 42524d8

### GAP-DAT-1. Harvest latest-row + THROTTLED + карантин как «истина» — P2
**Где:** `harvest_batch.py:110-141` (`statuses=("PASS","THROTTLED")`, `ROW_NUMBER() ... id DESC`, exclude quarantined).
**Проблема:** та же latest-row семантика, что ENG-2: инфраструктурный FAIL, затем resume, затем случайный THROTTLED — кандидат попадает в batch.txt. Карантин, отравленный ENG-1/инфрой, выкидывает живые домены из выборки. `min_domains` молча skip'ает `_resolve_strategy_string` miss (`skipped_unresolved`).
**Влияние:** валидатор получает шум / теряет чемпионов.
**Фикс:** harvest только `PASS` + `bridge_applied IS NOT 0`; карантин — отдельный флаг; логировать skipped.
**Статус:** Сделано, коммит c2631b8 + 9972953 (`--exclude-quarantined`)

### GAP-DAT-2. nfconf `common_only` деградирует в coverage/best одного домена — P3
**Где:** `nfconf.py:46-68`.
**Проблема:** если пересечения по доменам нет, код переходит к `get_best_by_coverage` затем `get_best_tcp(domain)` — экспорт «общего» конфига становится конфигом самого «лёгкого» домена (ST-6 THROTTLED в working).
**Влияние:** Keenetic-бандл слабее, чем кажется по имени common.
**Фикс:** если common_only и пересечение пусто — warning + пустой tcp, не тихий fallback.
**Статус:** Сделано, коммит 40f901b

### GAP-DAT-3. `maybe_write_best_config_data_block` молча no-op — P3
**Где:** `run_finalize.py:60-69` (`return` без лога, если нет db/rows).
**Проблема:** нарушает правило «запрет Silent Fallback»: оператор думает, что `best_config.conf` обновлён.
**Фикс:** `log.info` причина skip.
**Статус:** Сделано, коммит 65d3866

### GAP-CLI-1. `pair_phases` тянет `DPI_TESTER_SETTINGS` — P2
**Где:** `pair_phases.py:25` import `DPI_TESTER_SETTINGS` (config.py / ARC-9).
**Проблема:** voice/full-voice на чистой машине без ../dpi-tester деградирует (токен/settings).
**Фикс:** тот же, что ARC-9: settings.example.toml в blockcheckS.
**Статус:** коммит b155c6c

### GAP-RT-20. `Nfqws2Manager._launch` игнорирует elapsed settle — P3
**Где:** `nfqws2.py:272` `wait_nfqws2_ready(self.ns_name)` без сравнения с max_wait.
**Проблема:** пересекается с RT-8/9: «процесс виден» ≠ heartbeat/bind. Manager после bind-retry всё ещё может пойти в пробы на полуживом демоне.
**Фикс:** если elapsed ≥ settle_max и count=0 — raise; иначе wait-heartbeat как в batch_service zero-events.
**Статус:** Сделано, коммит 0bbe6ff

### WAVE-1 дополнение (к §9)
11. GAP-CHK-1 + GAP-ENG-A: TLS-proof статусы в fooling/FailPhase  
12. GAP-DAT-3: лог skip best_config  
13. GAP-DAT-2: не подменять common_only тихим best-of-one
14. GAP-OPS-1: `--orphans-only` требует prefix / pid из run.lock
15. GAP-XPORT-1: rename `4pda→b4pda` до `_keep_export_strategy` (как harvest)
16. GAP-CFG-1: join desync cores через literal `\\n` или валидировать по ядрам
17. GAP-PAIR-1: не синтезировать PASS в pair coverage
18. GAP-SEED-1: `await db.flush(); close()` в seed_state_db
19. GAP-LOCK-1: атомарный захват run.lock

---

## 12. Явно CLEAN (чтобы не переоткрывать)

Прочитаны, дефекта реестра нет: `bs.py`, `terminal.py`, `cli/presets.py`, `cli/commands/{tcp,udp,stop,gc,data_block,mcp}`, `run_deadline.py` (механизм; WALL_SLACK — GAP-ENG-7 в §13), `run_spec.py`, `tcp_fanout.py`, `strategy_loader.py`, `nfqws_config.py`, `results.py`, `generators/base.py`, `ip_pin.py`, `port_block.py`, `lua_conf.py` (runtime rename OK; export — GAP-XPORT-1), `metrics.pkill` **design** inode-scope (EPERM — GAP-SVC-2).

Не считать CLEAN: `cli/commands/serve.py` (GAP-CLI-17/18), `provider_import.py`/`shortlist_import.py` (GAP-SEED-1), `ip_block`/`l3_probe`/`ttl_probe`/`quic_raw` (§13 GAP-CHK-*).

`dns_secure.py` — DoH+CURLOPT_RESOLVE; picker last-resort — GAP-CHK-6.
`http3.py` — GAP-CHK-2 / агентский QUIC-оракул.
`system_deps.py` — не горячий путь week_cov.

---

## 13. Верифицированный добор сабагентов

Источники: [CLI/orchestration](f600ccfb-622f-4abc-a6eb-968740471741), [checkers](12c1e511-9251-4eed-8a2f-a1e42bcb6b21), [engine](46923f76-0d49-4648-b5fa-17015b02562e), [service/MCP](10878547-e11c-4ea6-b8d4-23349135b54c), [scripts/lua](ae958a96-a19c-4d12-aded-e96db758c5f3). Ниже — **только уникальное**, сверенное с файлами. Дубли опущены: MCP-lock = QA-1; http3 ALPN = GAP-CHK-2; fooling 403 = GAP-CHK-1; udp_game remap = ENG-6.5; settle elapsed = GAP-RT-20; harvest THROTTLED = GAP-DAT-1; dpi-tester settings = ARC-9.

### Операции / lua

### GAP-OPS-1. `--orphans-only` без prefix сносит live netns — P1
**Где:** `scripts/cleanup_env.sh:46-71` (`is_protected` истинно только при непустом `EXCLUDE_PREFIX`).
**Проблема:** AGENTS требует `--exclude-prefix=bs-p-<pid>-`; скрипт это не enforce’ит и не берёт pid из `run.lock` (хотя `lock_pid` уже читается).
**Влияние:** «безопасная» чистка mid-run удаляет `bs-p-*` → PASS-without-APPLIED / гибель воркеров.
**Фикс:** без prefix — exit 2; либо авто-prefix `bs-p-${lock_pid%????}-`.
**Статус:** Сделано, коммит 65d3866

### GAP-OPS-3. Week stages продолжают при rc∉{0,2,4} — P2
**Где:** `scripts/run_week_coverage.sh:178-186`.
**Проблема:** OOM/netns/bind (не exit 2) → «failed — continuing» → следующий пресет с `--resume` в ту же `week_cov.db`.
**Фикс:** abort на rc∉{0,4} или `WEEK_CONTINUE_ON_FAIL=1`; итоговый exit≠0.
**Статус:** Сделано, коммит 1eb39f1

### GAP-OPS-5. Хардкод `eth3` и UDP `35.217.*` в лаунчерах — P2
**Где:** `run_week_coverage.sh` / `run_full_20h.sh` / `run_variant.sh`; parser/nfconf default iface.
**Проблема:** хост — `wlp4s0`; GCP voice IP плавает.
**Фикс:** iface из env/toml; UDP через `--discover-dns`.
**Статус:** коммит b155c6c

### GAP-OPS-6. systemd boot-resume гоняет A→F при любой непустой БД — P2
**Где:** `scripts/boot_resume_series.sh`.
**Фикс:** sentinel COMPLETE; не стартовать unit по умолчанию.
**Статус:** Сделано, коммит 1eb39f1

### GAP-OPS-7. Lua `write_ipc` молча глотает open-fail; STRATEGY_FAIL без `id` — P2
**Где:** `lua/blockchecks/write_ipc.lua`; `scan_bridge.lua` rst_in/retrans.
**Влияние:** APPLIED не пишется без Lua-лога; triage rst_in теряется.
**Фикс:** id в FAIL; счётчик failed-writes; тест open-fail.
**Статус:** Сделано, коммит 1c8f328
### GAP-OPS-8. CQ009 ловит только голый `except:` — P2
**Где:** `tests/unit/test_code_quality.py`.
**Проблема:** `except Exception: pass` (десятки в src) проходит quality-гейт вопреки AGENTS §2.
**Фикс:** CQ на Exception-swallow / CancelledError.
**Статус:** коммит c9f3238

### GAP-OPS-10. Presets с сырым `blob=4pda` — P2
**Где:** `presets/strategies/flowseal-fast.tls` и др.; `test_presets_integrity.py` только counts.
**Фикс:** assert `safe_blob_name` на всех preset lines.
**Статус:** Сделано, коммит 1c8f328
### CLI / оркестрация

### GAP-LOCK-1. `run.lock` TOCTOU — P1
**Где:** `run_control.py:91-109`.
**Проблема:** read alive pid → write tmp+replace без O_EXCL.
**Фикс:** `os.open(O_CREAT|O_EXCL)` или flock.
**Статус:** Сделано, коммит 1b15231

### GAP-PAIR-1. Фейковый PASS в pair coverage — P1
**Где:** `main_phases.py:1171-1181` (`by_status.get(..., {"status": "PASS", "latency_ms": 0})`).
**Проблема:** coverage-победитель без строки на primary считается PASS для UDP-пар.
**Фикс:** только пересечение с `get_working_tcp_details(primary)`.
**Статус:** Сделано, коммит 65d3866

### GAP-XPORT-1. Export отбрасывает `blob=4pda` — P1
**Где:** `conf_builder.py:47,208-230`; `nfconf._resolve_export_strategy`. Контраст: harvest rename-then-filter.
**Влияние:** alt10/Flowseal 4pda не попадают в Keenetic `.conf`.
**Фикс:** `apply_blob_renames` до `_keep_export_strategy`; `--blob=b4pda:@`.
**Статус:** Сделано, коммит 65d3866

### GAP-CFG-1. Multi-desync `.conf` skip в матрице configs — P1
**Где:** `generators/custom.py:82` (`"\\n".join` реальных переводов строк) vs `static_validator.py:91-129` (raw newline = malformed).
**Влияние:** dual-fake каталог (simple_fake_alt2, alt10) выпадает из `configs` source.
**Фикс:** join через literal `\\n` или валидировать каждое ядро отдельно.
**Статус:** Сделано, коммит 65d3866

### GAP-SEED-1. Seed DB без flush — P1
**Где:** `shortlist_import.py:68-139`; `provider_import.py` аналогично.
**Проблема:** `log_tcp` буфер 500; return count без `flush`/`close`.
**Статус:** Сделано, коммит 65d3866

### GAP-CLI-5. Stock UDP/QUIC в nfconf при пустой БД — P2
**Где:** `nfconf.py:88-100`.
**Фикс:** пустой список + exit≠0 без `--allow-stock-fallback`.
**Статус:** Сделано, коммит 40f901b

### GAP-CLI-8. `scan`/`pair` AQ без карантина — P2
**Где:** `pair_phases.py:705-725` (`run_adaptive_tcp` без `quarantine=`). Даже после ENG-1 full-only.
**Статус:** Сделано, коммит 7f0d5b4

### GAP-CLI-9. `--resume --no-adaptive` не скипает TCP — P2
**Где:** `pair_phases.py:769-835`.
**Статус:** Сделано, коммит 7f0d5b4

### GAP-CLI-12. CliApp drop `--adaptive`; argparse без serve/mcp — P2
**Где:** `cliapp.py:189`; `parser.py` dispatch.
**Статус:** Сделано, коммит 240949e

### GAP-CLI-13. `--max 0` + `--profile` затирает unlimited — P2
**Где:** `profiles.py:37-39` (`0` в `_UNSET_VALUES["max"]`).
**Статус:** Сделано, коммит 7f0d5b4

### Engine (уникальное)

### GAP-ENG-3. byedpi `"dup" in line` / `"quic" in line` — P1
**Где:** `byedpi_translator.py:281-284` + `_UNMAPPED_FOOLINGS`.
**Проблема:** `dupsid` и `blob=quic_*` → SKIP. Уточняет GAP-ENG-B.
**Фикс:** токенизация, не substring.
**Статус:** Сделано, коммит 42524d8

### GAP-ENG-4. `tcp_ts` матчится внутри `tcp_ts_up` — P1
**Где:** `_fooling_argv` `elif "tcp_ts" in line`.
**Статус:** Сделано, коммит 42524d8

### GAP-ENG-6. Settle override без лога — P2
**Где:** `settle_profile.load_profile` / `async_runner._timing_for`.
**Статус:** коммит 2ce6937

### GAP-ENG-9. `quarantine_min=0` → 300 через `or` — P2
**Где:** `domain_quarantine.py:152`.
**Статус:** Сделано, коммит 65d3866

### GAP-ENG-10 / 12 / 14. StrategyLoader / sudo ipset expanduser / QUIC CLI без blob inject — P2–P3
**Где:** `strategy_loader.py`; `preset_paths._user_ipset_dir`; `nfqws_config._build_quic_nfqws_lines`.
**Статус:** коммит 83431ee

### GAP-ENG-11. `secure_io` broad except + no reclaim — P3
**Где:** `secure_io.py`.
**Статус:** коммит 83431ee

### GAP-ENG-13. `DATA_STALL_7K` матчит «stalled at 70» — P3
**Где:** `fail_phase.py` `_PHASE_PATTERNS`.
**Статус:** коммит 83431ee


### Service / MCP / store

### GAP-SVC-1. live_events один журнал на STATE — P2
**Где:** `live_events.py:28-39`. Углубление ARC-7; не отдельный P1 без второго процесса.
**Фикс:** суффикс pid/run_id.
**Статус:** Сделано, коммит 6b18435

### GAP-SVC-2. pkill EPERM → killed=0 — P2
**Где:** `metrics.py:65-136`.
**Статус:** коммит 5b57a28

### GAP-SVC-5. `item_domains` + `zip(..., strict=False)` — P2
**Где:** `batch_models.py:24-27`; `batch_service.py:116,143,180`.
**Проблема:** mismatch длин → все пробы пишутся на один `domain`.
**Фикс:** ValueError; `strict=True`.
**Статус:** Сделано, коммит 47dc9f7

### GAP-SVC-6. provider slug cache soft-default — P2
**Где:** `data_block/provider.py`; `export.sync_exported(allow_detect=False)`.
**Статус:** коммит bff6d46

### GAP-SVC-8. UNIQUE(strategy, domain) без protocol — P2
**Где:** `data_block/store.py`.
**Статус:** коммит bff6d46

### GAP-SVC-9. MCP `query_strategies` status=PASS ≡ THROTTLED ≡ ALL — P2
**Где:** `mcp/server.py:658-669`.
**Статус:** Сделано, коммит e8121a8

### GAP-SVC-12. SIGUSR1 делает I/O вопреки «signal-safe» — P2
**Где:** `engine/log.py:200-225`.
**Статус:** Сделано, коммит acbd0b5

### Checkers (уникальное сверх §11)

### GAP-CHK-3. Нет 303 в `REDIRECT_BLOCK_STATUSES` — P2
**Где:** `tcp_tls.py:35` `{301,302,307,308}`; curl_probe same-host 303 ловит, foreign 303 — нет.
**Статус:** Сделано, коммит 2e0d176

### GAP-CHK-4. Нет Google/YouTube redirect family — P2
**Где:** `tcp_tls.py:57-79` только Discord.
**Влияние:** youtube.com→accounts.google.com = suspicious FAIL.
**Статус:** Сделано, коммит 2e0d176

### GAP-CHK-6. `pick_working_doh` отдаёт мёртвый URL — P2
**Где:** `dns_secure.py` JSON без проверки HTTP/Status; fallback `(pool)[0]`.
**Статус:** Сделано, коммит 2e0d176

### GAP-CHK-7 / 8 / 12 / 14 / 16. ip_block unpinned baseline; ttl bind:443; L3 refused≡RST; quic_raw любой UDP байт=PASS; dpi_diag l4_25 fail→ok
**Статус:** коммит 96de66d

Не взято в реестр без воспроизведения: «15/28 configs skipped» как точная цифра; `supports_http3` True на generic error (нужен тест); systemd 120ч — оценка.
