---
name: blockcheckS-mcp
description: Use when working with blockcheckS (DPI strategy tester for zapret2/nfqws2): checking long-term campaign status, querying found strategies, triage, generating nfqws2 router configs, or using MCP tools get_series_status / query_strategies / triage_domain / dbg_* / generate_router_config.
---

# blockcheckS MCP Skill (обезличенная копия)

> Эта копия — для репо/публичного использования. Локальная версия живёт в
> `~/.config/opencode/skills/blockcheckS-mcp/SKILL.md` (с путями под конкретный
> хост). Здесь локальные пути заменены на `<PROJECT_DIR>` / XDG-обозначения.

---

# blockcheckS MCP — инструменты и воркфлоу

blockcheckS — массовый тестер DPI-стратегий (zapret2/nfqws2). MCP-сервер
(`bs-mcp`) подключает его к opencode/Claude/Cursor. Этот скилл — шпаргалка:
какие инструменты когда использовать.

## 1. MCP-инструменты (12)

### Без демона (работают всегда, даже во время серии A→F)
| Инструмент | Что делает |
|---|---|
| `get_series_status` | Статус кампании из run.lock + state.db: pid, uptime, progress `[done/total] pass=N rate ETA`, tcp_total/pass, backend, топ-fail-фазы |
| `query_strategies(domain, status, limit)` | Топ-стратегии для домена из state.db (PASS/THROTTLED/FAIL) |
| `get_presets(kind)` | Список strategy/domain пресетов из presets/ |
| `dbg_validate_strategy_syntax(strategy)` | Офлайн-валидация стратегии (9+ правил) |

### Требуют демон `bs serve` (root, netns)
| Инструмент | Что делает |
|---|---|
| `get_service_status` | Статус демона (pool, uptime, active_run) |
| `triage_domain(domain)` | Preflight Triage: L3/DNS/TLS/QUIC + рекомендации генераторов |
| `find_working_strategy(domain, profile, time_limit_sec)` | AQ-поиск работающих стратегий (≤60с) |
| `dbg_probe_raw(domain, strategy)` | Одиночная проба, `dry_run_db=True` по умолчанию |
| `dbg_inspect_lua_ipc(domain, strategy)` | Трейс событий Lua bridge (APPLIED / rst_in / ttl) |
| `dbg_dump_pool_state` | netns pool, PID nfqws2, stale run.lock |
| `stop_campaign(wait)` | Graceful stop кампании через демон |
| `generate_router_config(target_os, domains)` | nfqws2 .conf для Keenetic/OpenWrt/Linux |

## 2. Fair-exclusion правило (ВАЖНО)

Пока активна длинная серия A→F (`get_series_status.active == true`), демон
`bs serve` НЕ запущен (он откажется стартовать из-за run.lock). Поэтому:
- **Демон-инструменты вернут** `Connection refused` — это НЕ ошибка, а ожидаемое поведение.
- **Используй только read-only**: `get_series_status`, `query_strategies`, `get_presets`, `dbg_validate_strategy_syntax`.
- Статус серии смотри через `get_series_status` (НЕ через `get_service_status`).

## 3. Воркфлоу-цепочки

### Статус серии (во время A→F)
```
get_series_status → active/running/uptime_h/progress/tcp_pass
```

### Поиск стратегий для домена
```
triage_domain(domain) → рекомендации генераторов
find_working_strategy(domain, profile="fast", time_limit_sec=30) → топ
dbg_probe_raw(domain, strategy) → одиночная проверка (dry_run_db=True)
```

### Экспорт конфига для роутера
- MCP: `generate_router_config(target_os="keenetic", domains=[...])`
- CLI (точнее, из БД): `bc-nfconf --db <db> --out-dir <dir> --ipset`

## 4. Ключевые пути (обезличенно)

- Сокет демона: `$BLOCKCHECKS_STATE_HOME/blockcheckS/blockchecks.sock`
  (по умолчанию `~/.local/state/blockcheckS/`)
- Кампанийные БД: `<PROJECT_DIR>/logs/run_*.db`
- Пресеты стратегий: `<PROJECT_DIR>/presets/strategies/` (`-M <name>`)
- Кастомные Lua: `<PROJECT_DIR>/lua/custom/` (dupfake, manifest.toml)
- Документация: `<PROJECT_DIR>/docs/`

## 5. Грабли

- `get_series_status` читает run.lock + state.db напрямую — не требует демона и не пишет в БД.
- `dbg_probe_raw` по умолчанию `dry_run_db=True` — не засоряет боевую БД.
- `dbg_validate_strategy_syntax` — офлайн, полезен до отправки стратегии в netns.
- Пресеты имеют расширения под протокол: `.tls/.txt/.http/.quic/.udp` (приоритет .tls).
- Кастомные lua регистрируются в `lua/custom/manifest.toml` (included/excluded параметры).

## Установка локального скилла

```bash
mkdir -p ~/.config/opencode/skills/blockcheckS-mcp
cp docs/mcp-skill.md ~/.config/opencode/skills/blockcheckS-mcp/SKILL.md
# затем заменить <PROJECT_DIR> на фактический путь проекта
```

Перезапустить opencode — скилл `blockcheckS-mcp` станет доступен.
