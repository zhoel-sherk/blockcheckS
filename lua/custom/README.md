# blockcheckS custom Lua (для экспорта на Keenetic / внешний хост)

Этот каталог — **дом для кастомных nfqws2 Lua-скриптов**, которые выносите
на роутер/внешний хост (в отличие от `lua/blockchecks/`, который живёт в
bridge-цепочке прогона).

## Что здесь

| Файл | Назначение | Стратегия | Проверено |
|---|---|---|---|
| `dupfake.lua` | `dupfake:` — atomic multi-blob fake (аналог winws `--dpi-desync=fake --repeats=N`) | `dupfake:blob=tls_clienthello:repeats=6:tcp_ts=-1000` | Keenetic prod (YouTube ✅ / Discord ❌) |
| `manifest.toml` | Реестр кастомных lua (файл + included/excluded параметры) | — | — |

## Как подключить

### На Keenetic / внешний nfqws2

Скопировать на хост и добавить в `--lua-init`-цепочку **после** `zapret-auto.lua`:

```bash
# на роутере (пример): scp lua/custom/dupfake.lua root@192.168.1.1:/opt/etc/nfqws2/lua/
# в конфиге nfqws2 (порядок имеет значение):
#   --lua-init=@/opt/etc/nfqws2/lua/zapret-lib.lua
#   --lua-init=@/opt/etc/nfqws2/lua/zapret-antidpi.lua
#   --lua-init=@/opt/etc/nfqws2/lua/zapret-auto.lua
#   --lua-init=@/opt/etc/nfqws2/lua/dupfake.lua
```

### В blockcheckS (для прогона/экспорта)

```bash
# прогон с кастомным lua:
BLOCKCHECKS_LUA_EXTRA=$PWD/lua/custom/dupfake.lua sudo -E bs scan -d youtube.com -M gp-custom-dupfake

# экспорт: bc-nfconf пишет COPY-комментарий + рабочий --lua-init:
#   # COPY lua: …/lua/custom/dupfake.lua -> /opt/etc/nfqws2/lua/dupfake.lua
#   --lua-init=@/opt/etc/nfqws2/lua/dupfake.lua
```

## Экспорт: COPY + `--lua-init`

При экспорте конфигов (`bc-nfconf`, `bs full`, MCP `generate_router_config`)
стратегия с кастомной lua получает:

```conf
# COPY lua: /home/…/blockcheckS/lua/custom/dupfake.lua -> /opt/etc/nfqws2/lua/dupfake.lua
--lua-init=@/opt/etc/nfqws2/lua/dupfake.lua
--lua-desync=dupfake:blob=tls_clienthello:repeats=6:tcp_ts=-1000
```

`# COPY` — откуда взять файл на скан-хосте. Рабочая строка — путь на роутере.
Маппинг функция → файл задаётся в `lua/custom/manifest.toml`.

## Реестр кастомных lua (`manifest.toml`)

`lua/custom/manifest.toml` описывает каждую кастомную функцию: какой файл
нужен на хосте и какие параметры стратегии с ней совместимы.

```toml
[[lua]]
name = "dupfake"              # имя функции в стратегии (dupfake:blob=...)
file = "dupfake.lua"          # файл в lua/custom/ (для --lua-customN комментария)
description = "..."
included = ["blob", "repeats", "tcp_ts", "..."]   # поддерживаемые параметры
excluded = ["pos", "seqovl", "wssize", "wsize"]   # несовместимые (конфликт)
```

Правила валидации (применяются к стратегии через `static_validator` и
`conf_builder`):
- **excluded** параметр в стратегии → `error` (`custom_lua_excluded`);
- параметр ни в included, ни в excluded → `warning` (`custom_lua_undocumented`);
- `optional` всегда допускается.

## Как добавить свой кастомный скрипт

1. Положить `lua/custom/lua-customN.lua` (N = следующий номер).
2. Добавить запись `[[lua]]` в `lua/custom/manifest.toml` (name/file/
   included/excluded).
3. Обновить таблицу выше и `presets/strategies/` при необходимости.
