# Тестовый аудит blockcheckS — 2026-08-16

> Полный аудит тестов 3 explore-агентами (Quality / Integration / Mutation), read-only.
> Серия A→F активна — мутации статически не запускались.
> Результат: 3 вакуумных гейта, 1 мёртвый флаг, 1 непокрытая команда, ~6 unit-маскировок в integration.

---

## 1. Сводка (ключевые находки)

| # | Находка | Направление | Severity |
|---|---|---|---|
| F1 | **vulture-гейт вакуумный**: `min_confidence=80` > макс. уверенности находок (60) → 164 находки скрыты навсегда | Quality | 🔴 P1 |
| F2 | **mutation-гейт не может упасть**: mutmut 3.7.0 всегда exit 0, в выводе нет слова «survived» (только эмодзи+число) | Mutation | 🔴 P1 |
| F3 | **`bs serve --timeout` — мёртвый флаг** (объявлен, нигде не читается); `serve` не в dead-cli-flags гейте | Quality | 🔴 P1 |
| F4 | **CI integration job — плейсхолдер**: даже на workflow_dispatch ничего не запускает (echo) | Integration | 🔴 P1 |
| F5 | **`blockchecks.mcp*` без architecture-правил** | Quality | 🟠 P2 |
| F6 | **~6 unit-маскировок в integration** (firewall×2, run_control, sqlite×2, bin-exists×2) | Integration | 🟠 P2 |
| F7 | **E2E-пробелы**: serve, mcp, full--resume, stop--force, presets, nfconf-export не покрыты | Integration | 🟠 P2 |
| F8 | **mutation scope 15/95 модулей (~19%)**: async_runner(1007), generators(~2100), adaptive_runner, static_validator не включены | Mutation | 🟠 P2 |
| F9 | **`do_not_mutate_patterns["logger."]` мёртв** (0 совпадений в src); `"raise "` скрывает лишь 6 строк в скоупе | Mutation | 🟡 P3 |
| F10 | UP007 в select+ignore ruff_quality (мёртвая запись); `full` в мёртвом dead-flag конфиге | Quality | 🟡 P3 |

---

## 2. Quality Audit (121 тест, ~5.4s)

### Сильные гейты
- **test_architecture** (8 правил, pytest-archon, AST-граф по 108 модулям) — механика strong.
- **test_code_quality** (9 AST-детекторов + ruff subprocess) — пороги мягкие, но честные (при nest=3 ловит 29×CQ001).
- **test_dead_cli_flags** — живые argparse-поверхности для tcp/udp/scan/pair/composite/bench-settle/stop.

### Пробелы
- **G1 (P1)**: `bs serve --timeout` мёртв (parser.py объявляет, serve.py/cliapp/ProbeService не читают).
- **G2 (P1)**: `serve` не в dead-flags (ни параметризация, ни command_readers).
- **G3 (P2)**: `mcp*` без architecture-правил (граф видит модуль — правило можно добавить).
- **G4 (P1)**: vulture инертен при min_confidence=80 (164 скрытых находки при conf 60).
- **G6 (P2)**: 8 новых actions в service/server.py не проверяются (нет теста реестра handle_request).
- **G7/G10 (P3)**: UP007 select+ignore; `full` в мёртвом конфиге.

---

## 3. Integration Audit (22 теста, 6 файлов)

### Критика
- **CI job — плейсхолдер** (echo, не запускает тесты даже на dispatch).
- **7/8 e2e — smoke на выходе** (только `rc in (0,1)`, нет проверки PASS/строк в БД).
- **~6-7 unit-тестов в integration-одежде**: `test_firewall_cleanup_no_flush_output`, `test_firewall_queue_bypass_tracked` (fake_run), `test_run_control_lock_cleared_on_abort`, `test_sqlite_concurrency` ×2 (asyncio+SQLite, без sudo), `test_python_bin_exists`/`test_nfqws2_bin_exists` (тривиальные файл-чеки).

### E2E-матрица (покрытие)

| Сценарий | Покрыт | Комментарий |
|---|---|---|
| `bs serve` + Unix socket | ❌ НЕТ | только unit с моками |
| `bs mcp` ↔ serve | ❌ НЕТ | только fake_daemon unit |
| `bs full --resume` | ❌ НЕТ | только store-уровень |
| `bs stop --force` | ❌ НЕТ | только unit-мок |
| `bs scan --preset` | ❌ НЕТ | — |
| export nfconf | ❌ НЕТ | только unit |
| lua_bridge batch | ✅ ЧАСТИЧНО | test_lua_bridge_compare (4, реальные) |
| netns cleanup | ✅ ДА | test_netns_leak (2 real) |

### CI-рекомендации
- Вынести в unit (без sudo): 6-7 маскировок (firewall×2, run_control, sqlite×2, bin-exists×2).
- `test_e2e_stop_no_active_run` — единственный кандидат на push-smoke (sudo есть, nfqws2 не нужен) — но аккуратно (autouse `_clean_each`).
- Заменить CI-плейсхолдер на safelist или явно задокументировать ручной прогон.

---

## 4. Mutation Audit (15 модулей = 4636 LOC / ~19% кода)

### Ключевые факты
- `.mutmut-cache/` отсутствует → мутации **ни разу не запускались**.
- `logger.` — 0 совпадений в src (паттерн мёртв).
- `raise ` — 59 строк в src, 6 в скоупе (не большая потеря).
- Во всех тестах включённых модулей `parametrize = 0` — фиксированные входы.

### Слабые включённые модули (гарантированные survivors)
| Модуль | LOC | Тесты | Оценка |
|---|---|---|---|
| `in_ns_workers.py` | 784 | 5 | 🔴 очень слабая |
| `sqlite_store.py` | 743 | 14 | 🔴 слабая (37 def) |
| `netns_pool.py` | 228 | 3 | 🔴 очень слабая (13 методов) |
| `results.py` | 82 | ~0 прямых | 🔴 очень слабая |
| `dns_secure.py` | 497 | 13 | 🟠 средне-слабая |

### Не включённые критичные (P1)
`async_runner.py` (1007), `generators/` (~2100), `adaptive_runner.py` (353), `static_validator.py` (277), `mcp/server.py` (721 — тесты скипаются без `[mcp]`), `service/server.py` (430), `preflight.py` (489).

---

## 5. План фиксов (приоритизированный)

### P1 — закрыть вакуумные/пропускающие гейты
1. **Mutation gate**: парсить `mutmut results` → `pytest.fail` при survivors; CI: `mutmut results | grep -c survived` как fail-условие.
2. **Vulture gate**: снизить `min_confidence` до 60-65 + whitelist реальных находок (или явно задокументировать инертность).
3. **Dead-flag**: добавить `serve` в параметризацию + `command_readers` → покажет мёртвый `--timeout` → прокинуть в ProbeService или удалить флаг.
4. **CI integration**: заменить плейсхолдер на реальный safelist push-безопасных smoke или явный мануал.

### P2 — усилить непокрытое
5. Architecture-правило для `mcp*` (should_not_import: cli, bs, main).
6. Тест реестра actions service/server.py (10 команд == handle_request).
7. E2E: `bs serve`+socket roundtrip, `bs full --resume`, `bs stop --force`, preset-флаги, nfconf-export (probe-host, dispatch).
8. Вынести 6-7 unit-маскировок из integration в unit.
9. Усилить e2e-ассерты (PASS-строки, `COUNT(*) FROM tcp_results`).
10. Расширить `source_paths`: async_runner, adaptive_runner, static_validator, generators/*, family_needs, run_control, preflight.

### P3 — гигиена
11. Убрать UP007 из select; `full` из мёртвого конфига; удалить мёртвый `logger.` паттерн.
12. `mutate_only_covered_lines = true` + увеличить `timeout-minutes` mutation job.
13. Поднять `test_settings_quality_smoke` (required_fields) в quality.

---

## 6. Изменения для серии A→F

- Реальный `mutmut run` — после завершения серии (CPU/netns заняты).
- P1.3 (serve --timeout) — не влияет на серию (serve не запущен сейчас).
- Все фиксы — в отдельных коммитах/ветках, не прерывая серию.
