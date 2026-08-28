# MCP Server (Model Context Protocol)

blockcheckS поставляет **FastMCP-сервер** — шлюз между локальными LLM-клиентами
(Claude Desktop, Cursor, opencode) и резидентным демоном `bs serve`.
Детали общего контракта сокета и HTTP-моста описаны в [docs/api.md](api.md).

Схема:

```
LLM client ──stdio──> bs-mcp (FastMCP) ──Unix socket──> bs serve (root, netns)
```

- **`bs-mcp`** — лёгкий stdio-процесс: проксирует инструменты к демону.
- **`bs serve`** — привилегированный демон: единственный, кто трогает
  netns / nfqws2 / curl. Работает под root.
- LLM-агент **не имеет root** — все сетевые операции выполняет демон.

---

## 1. Установка

Зависимость `mcp` — **опциональная** (extras `[mcp]`), чтобы базовый пакет
оставался лёгким для роутеров/CI.

```bash
cd ~/workspace/blockcheckS
.venv/bin/pip install -e ".[mcp,dev]"        # dev: тесты; mcp: сервер
# или только рантайм MCP:
.venv/bin/pip install -e ".[mcp]"
# или через файл:
.venv/bin/pip install -r requirements-mcp.txt
```

Проверка (без mcp — подсказка + exit 1):
```bash
.venv/bin/bs mcp        # без [mcp] → инструкция по установке
.venv/bin/bs-mcp        # то же (console script)
```

---

## 2. Запуск демона (обязательно, root)

MCP-инструменты обращаются к `bs serve` по Unix-сокету. Демон нужен заранее:

```bash
# в tmux (фоне):
tmux new-session -d -s bs-serve "sudo -E .venv/bin/bs serve --pool 2"
# или systemd: sudo systemctl enable --now blockcheck-serve.service
```

Проверка сокета:
```bash
ls -la ~/.local/state/blockcheckS/blockchecks.sock   # srw------- zhoel
```

> **Fair exclusion**: пока активна длинная серия (`bs full`, run.lock),
> `bs serve` откажется стартовать (exit 2), а probe-инструменты вернут
> `busy/campaign_active`. Живые проверки — после завершения серии.

---

## 3. Инструменты

| Слой | Инструмент | Что делает |
|---|---|---|
| A | `triage_domain` | Preflight Triage домена (L3/DNS/TLS/QUIC) + рекомендации генераторов |
| A | `find_working_strategy` | AQ-поиск стратегий с `time_limit_sec` (≤60) |
| A | `generate_router_config` | nfqws2 .conf для Keenetic / OpenWrt / Linux (демон если жив; иначе offline SQL по PASS, **без** фильтра `bridge_applied`) |
| A | `get_service_status` | Статус демона (pool, uptime, активная серия) — требует `bs serve` |
| A | `set_debug_mode` | Unified debug: Python DEBUG + nfqws2 `--debug=1` (требует `bs serve`) |
| A | `get_series_status` | Статус кампании **напрямую из диска** (run.lock + state.db) — без демона; работает пока серия A→F владеет pool |
| A | `get_log_tail` | Хвост лога `python` / `campaign` / `nfqws2` с диска (`LOG_SOURCES`; без демона) |
| A2 | `query_strategies` | Топ-стратегии для домена из state.db (read-only, без демона/root; `proto=tcp\|udp`) |
| A2 | `get_campaign_domains_summary` | Сводка по доменам кампании: PASS/FAIL/попытки из state.db (read-only) |
| A2 | `get_presets` | Список strategy/domain пресетов из `presets/` (read-only) |
| A2 | `stop_campaign` | Останавливает демон **`bs serve`** (socket `stop`), **не** кампанию `bs full`. Во время A→F сокета нет — используй CLI `bs stop` |
| A2 | `get_live_events` | Live-журнал проб (`events_live.<pid>.jsonl` / `current_probe.json`) — без демона; поля включают `applied` |
| B | `dbg_probe_raw` | Одиночная проба стратегии, `dry_run_db=True` по умолчанию |
| B | `dbg_inspect_lua_ipc` | Трейс событий Lua bridge (APPLIED / rst_in / ttl) |
| B | `dbg_validate_strategy_syntax` | Офлайн-валидация CLI-аргументов nfqws2 |
| B | `dbg_dump_pool_state` | netns pool, PID nfqws2, stale run.lock |
| C | `get_nfqws2_status` | Статус nfqws2 на хосте (pids, бинарник, ELF-арх vs host) — read-only, без демона |
| C | `get_zapret2_config` | Активный `/opt/zapret2/config` (профили, строки) — read-only |
| C | `list_zapret2_blobs` | Blobs в `/opt/zapret2` (blobs/ + files/fake/) + алиасы blockcheckS |
| C | `get_ipset_status` | Скрипты `/opt/zapret2/ipset/` + живые kernel ipset-таблицы |
| C | `get_provider_profile` | Профиль провайдера в `data_block/` (triage, DNS cache, pass strategies) — read-only |
| C | `probe_strategy` | Алиас `dbg_probe_raw` (dry_run_db=True) — требует `bs serve` |

Ресурсы: `blockchecks://presets/manifest`, `blockchecks://telemetry/active_run`.

> **zapret2 filesystem-MCP заменён**: раньше был отдельный `server-filesystem`
> с доступом к `/opt/zapret2`. Теперь полезные zapret2-инструменты встроены
> прямо в blockchecks (LAYER C) — один MCP на всё. Чтение файлов zapret2
> остаётся доступным через обычные средства агента.

> **Без демона работают**: `get_series_status`, `get_log_tail` (python/campaign/nfqws2),
> `query_strategies`, `get_campaign_domains_summary`, `get_presets`, `get_live_events`,
> `dbg_validate_strategy_syntax`, `get_nfqws2_status`, `get_zapret2_config`,
> `list_zapret2_blobs`, `get_ipset_status`, `get_provider_profile` + ресурс `presets/manifest`.
> Offline-fallback: `generate_router_config` (сырой PASS в SQL).
> **Требуют `bs serve`**: `triage_domain`, `find_working_strategy`,
> `get_service_status`, `set_debug_mode`, `stop_campaign` (это stop **демона**, не `bs full`),
> `dbg_probe_raw`, `dbg_inspect_lua_ipc`, `dbg_dump_pool_state`, `probe_strategy`.

`get_series_status` (диск): `backend` всегда `"lua_bridge"`; `adaptive` = нет `--no-adaptive` в argv;
`quarantined[]` из таблицы; `live` = `current_probe.json`; `domain_pass_counts` — топ-10 PASS (сырой статус).
`query_strategies` / `get_campaign_domains_summary` / `tcp_pass` **не** фильтруют `bridge_applied`
(в отличие от `harvest-batch`). Для кампании во время A→F: диск-инструменты; стоп — `bs stop`.

> **Скилл для LLM-агентов**: [docs/mcp-skill.md](mcp-skill.md) — шпаргалка
> по инструментам, fair-exclusion правило и воркфлоу-цепочки (обезличенная
> копия локального `~/.config/opencode/skills/blockcheckS-mcp/SKILL.md`).

---

## 4. Конфигурация клиентов

### opencode (`~/.config/opencode/opencode.jsonc`)
```jsonc
{
  "mcp": {
    "blockchecks": {
      "type": "local",
      "command": ["/home/zhoel/workspace/blockcheckS/.venv/bin/bs-mcp"],
      "enabled": true
    }
  }
}
```

### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "blockchecks": {
      "command": "/home/zhoel/workspace/blockcheckS/.venv/bin/bs-mcp",
      "args": []
    }
  }
}
```

### Cursor (`~/.cursor/mcp.json` or project `.cursor/mcp.json`)
```json
{
  "mcpServers": {
    "blockchecks": {
      "command": "/home/zhoel/workspace/blockcheckS/.venv/bin/bs-mcp",
      "args": []
    }
  }
}
```

---

## 5. Smoke-проверка

```bash
# 1) демон жив
echo '{"cmd":"status"}' | timeout 5 \
  python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect('$HOME/.local/state/blockcheckS/blockchecks.sock'); s.sendall(sys.stdin.read().encode()+b'\n'); s.settimeout(5); print(s.recv(4096).decode())"

# 2) MCP stdio handshake
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}' \
  | timeout 6 .venv/bin/bs-mcp
```

---

## 6. Контракт сокета (для интеграторов)

Демон отвечает **гибридным конвертом** — обратная совместимость:

```json
{
  "status": "ok",                // legacy: ok | error | busy | stopping
  "ok": true,                    // MCP: bool
  "data": { ... },               // MCP: payload
  "error": null,                 // MCP: str | null
  ...legacy_fields               // results, active_run, pool_size, ...
}
```

Запросы: `{"action": "triage", "domain": "..."}` (или legacy `{"cmd": ...}`).

Actions: `probe` `status` `triage` `find_strategy` `generate_config`
`dbg_probe` `dbg_inspect_lua` `dbg_dump_pool` `get_telemetry` `set_debug` `log_tail` `stop`.

Инструменты `get_series_status`, `get_log_tail`, `query_strategies`, `get_presets` читают
состояние напрямую из `run.lock` / `state.db` / `presets/` / лог-файлов и **не требуют** ни
демона, ни сокета (работают во время активной серии A→F).

---

## 7. Troubleshooting

| Симптом | Причина | Решение |
|---|---|---|
| `daemon socket not found` | Демон не запущен | `tmux new-session -d -s bs-serve "sudo -E .venv/bin/bs serve --pool 2"` |
| `Connection refused` | Сокет есть, демон упал | `ps aux \| grep 'bs serve'`, рестарт |
| `busy/campaign_active` | Активна серия A→F (run.lock) | Дождаться завершения серии |
| `Ошибка: зависимость 'mcp' не найдена` | Не установлен extras `[mcp]` | `pip install -e ".[mcp]"` |
| `no module mcp.server.fastmcp` | Установлен mcp 2.x | Пинить `mcp>=1.1.0,<2.0.0` |
| Боевая БД замусорена | dbg-инструменты без `dry_run_db` | `dbg_probe_raw` всегда `dry_run_db=True` |

---

## 8. Безопасность

- Сокет 0600 (создаёт `ProbeServer.serve`).
- Демон отвечает только на локальные запросы (Unix socket + HTTP 127.0.0.1).
- MCP stdio не открывает порты — только локальный процесс.
- `dbg_probe_raw` по умолчанию не пишет в `state.db`.
