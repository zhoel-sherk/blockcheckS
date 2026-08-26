# blockcheckS custom Lua (nfqws2 bridge)

Loaded via `--lua-init` when `--lua-bridge` is enabled. См. также
[docs/custom_lua.md](../docs/custom_lua.md) — источник идей: `scan_pick`,
`smart_fallback` и hot-swap реализованы; §3–§5, §14 — backlog.

## Структура

```
lua/
├── blockchecks/         # bridge-цепочка прогона (scan_bridge, write_ipc, init, geneva)
└── custom/              # кастомные скрипты для экспорта на Keenetic/внешний хост
    ├── dupfake.lua      # dupfake: atomic multi-blob (winws fake+repeats аналог)
    └── README.md        # как подключать, маппинг, COPY + --lua-init
```

`lua/blockchecks/`:

- `scan_bridge.lua` — обрабатывает payload'ы `tls_client_hello`, `http_req`,
  `quic_initial` (`bs_l7_ok`). Для каждого ClientHello/HTTP-запроса/QUIC
  Initial публикует активный strategy id в `/dev/shm`, исполняет только
  подходящий plan-instance и пишет `APPLIED` в `events.ndjson`.
- `write_ipc.lua` — атомарная запись событий + чтение `strategy.id` / `strategy.gen`.
- `init.lua` — таймерный фолбэк для случаев, когда ClientHello не проходит
  через nfqws2 (порт/протокол вне фильтра).
- `geneva.lua` — custom `fool=bs_*` функции (Geneva-атаки). Входит в
  дефолтную blockchecks `--lua-init` цепочку (`get_blockchecks_lua_scripts`).

`lua/custom/` — кастомные nfqws2 Lua-скрипты, которые выносите на
роутер/внешний хост (например `dupfake.lua`). Экспорт конфигов
(`bc-nfconf`, MCP `generate_router_config`) добавляет `# COPY lua: <abs> ->
/opt/etc/nfqws2/lua/<file>` и рабочий `--lua-init=@/opt/etc/nfqws2/lua/<file>`,
если стратегия использует такую функцию. См. `lua/custom/README.md`.

## Backend map: lua_bridge (campaign) vs one-shot

Campaign TCP always uses lua_bridge (`config.resolve_probe_backend` maps `--classic` away).

```
┌─ Lua bridge (persistent nfqws2, /dev/shm IPC, один демон на батч) ─┐
│  • TCP массовый батч  bs scan / pair / full sequential / AQ         │
│  • QUIC/HTTP3 батч    bs full QUIC-фаза → _run_probe_batch          │
└─────────────────────────────────────────────────────────────────────┘

┌─ One-shot nfqws2 (start_daemon, не campaign-batch) ───────────────┐
│  • bs tcp / bs composite / fan-out (одна стратегия × N доменов)    │
│  • pair matrix UDP + bs udp / voice                                │
└───────────────────────────────────────────────────────────────────┘
```

### Почему так

- **Lua bridge** — массовый TCP/QUIC батч (scan/pair/full).
- **One-shot** (`start_daemon`) — `bs tcp`/`bs udp`, fan-out, pair UDP, voice.
- **QUIC fallback** (`fake→badsum→ip_ttl`) живёт в one-shot `test_quic`;
  при bridge-батче fallback не применяется.
