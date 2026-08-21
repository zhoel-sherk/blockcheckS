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

## Backend map: что через Lua bridge, что через classic

Выбор backend: `--classic` > `--probe-backend` > `--lua-bridge` >
`BLOCKCHECKS_PROBE_BACKEND` > default `lua_bridge` (`config.resolve_probe_backend`).

```
┌─ Lua bridge (persistent nfqws2, /dev/shm IPC, один демон на батч) ─┐
│                                                                     │
│  • TCP массовый батч                                                │
│      bs scan / bs pair        → test_batch_tcp  → lua_bridge        │
│      bs full sequential       → _run_tcp_sequential_bridge          │
│      bs full adaptive (AQ)    → run_adaptive_tcp_bridge             │
│      --lua-bridge-compare     → dual (classic + bridge) + drift     │
│  • QUIC/HTTP3 батч (при --lua-bridge)                               │
│      bs full QUIC-фаза        → _run_probe_batch("lua_bridge")      │
│        (bridge conf: --filter-udp=443 --filter-l7=quic              │
│         --payload=quic_initial; probe через check_http3)            │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

┌─ Classic (per-strategy nfqws2 restart) ───────────────────────────┐
│                                                                   │
│  • single TCP   bs tcp             → test_tcp → _run_tcp_check     │
│  • fan-out      (несовместим с bridge)                             │
│                  bs full --fan-out → test_tcp_domains              │
│  • QUIC/HTTP3   bs full QUIC (classic)                             │
│                  → test_quic → _run_quic_check (+ fallback         │
│                    fake→badsum→ip_ttl при дропе)                   │
│  • pair matrix  bs full / bs pair  → test_pair_matrix              │
│                  (_run_tcp_check + _run_udp_check)                 │
│  • UDP voice    discover / bs udp  → voice_udp_probe               │
│                  (STUN → IP-discovery → burst >16KB)               │
│                                                                   │
└───────────────────────────────────────────────────────────────────┘
```

### Почему так

- **Lua bridge** даёт выигрыш там, где много стратегий и их можно хот-свопить
  в одном nfqws2: массовый TCP-батч (scan/pair/full), и теперь QUIC-батч.
- **Classic остаётся** для:
  - одиночных тестов (`bs tcp`/`bs udp`) — bridge не нужен;
  - fan-out (одна стратегия × много доменов с curl_parallel — bridge
    domain-agnostic, но fanout-волны несовместимы);
  - pair matrix (нужны TCP- и UDP-демоны одновременно);
  - UDP voice (единичный UDP-probe, не стратегия).
- **QUIC fallback** (`fake→badsum→ip_ttl`) живёт в classic `test_quic`;
  при bridge-батче fallback не применяется (используется базовая стратегия).
