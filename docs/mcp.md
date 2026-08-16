# MCP Server (Model Context Protocol)

blockcheckS поставляет **FastMCP-сервер** — шлюз между локальными LLM-клиентами
(Claude Desktop, Cursor, opencode) и резидентным демоном `bs serve`.

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
| A | `generate_router_config` | nfqws2 .conf для Keenetic / OpenWrt / Linux |
| A | `get_service_status` | Статус демона (pool, uptime, активная серия) |
| B | `dbg_probe_raw` | Одиночная проба стратегии, `dry_run_db=True` по умолчанию |
| B | `dbg_inspect_lua_ipc` | Трейс событий Lua bridge (APPLIED / rst_in / ttl) |
| B | `dbg_validate_strategy_syntax` | Офлайн-валидация CLI-аргументов nfqws2 |
| B | `dbg_dump_pool_state` | netns pool, PID nfqws2, stale run.lock |

Ресурсы: `blockchecks://presets/manifest`, `blockchecks://telemetry/active_run`.

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

### Cursor (`~/.cursor/mcp.json`)
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
`dbg_probe` `dbg_inspect_lua` `dbg_dump_pool` `get_telemetry` `stop`.

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
