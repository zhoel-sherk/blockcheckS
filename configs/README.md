# configs/ — готовые nfqws2-конфиги (исходники)

## Что это

Репозиторий **готовых к использованию** nfqws2-конфигов (raw-формат, `--qnum=…`).
Каждый `.conf` — полный набор фильтров + blobs + hostlist + `--lua-desync`
для одной стратегии или протокола. Это **исходники** для прогона и ручных тестов,
НЕ output-каталог.

| Тип | Файлов | Назначение |
|---|---|---|
| TCP | 22 | Одиночные стратегии (`fake`, `hostfakesplit`, `multisplit`, …) |
| UDP voice | 5 | Discord Voice (`udp_voice__*.conf`) |
| Composite | 1 | TCP + UDP в одном nfqws2 (`composite_discord.conf`) |

Формат соответствует выводу `build_raw_conf()` (`src/blockchecks/engine/conf_builder.py`).

## Как используется

```bash
# 1. Как источник стратегий для прогона (default для scan/pair/full)
bs scan -d discord.com --generate --tcp-sources configs
bs full --tcp-sources configs

# 2. Ручной тест одного конфига
bs tcp  -d discord.com -c configs/simple_fake__fake_ts.conf
bs udp  -d discord.com -c configs/udp_voice__fake_r6.conf

# 3. Композитный конфиг (TCP+UDP)
bs composite -c configs/composite_discord.conf
```

`CONFIGS_DIR` = `configs/` в репо (или `blockchecks/configs` в wheel);
загрузка через `StrategyLoader.from_config_dir()`.

## Где генерируемый best-экспорт

**НЕ сюда.** После прогона blockcheckS генерирует конфиги из best-стратегий в
state.db и пишет их в XDG-каталог:

```bash
# Путь по умолчанию:
~/.local/share/blockcheckS/export/nfqws2_<timestamp>.conf    # keenetic-стиль
~/.local/share/blockcheckS/export/nfqws2_raw_<timestamp>.conf # raw
~/.local/share/blockcheckS/export/user.list

# Или явно:
bs full --out-dir /path/to/out
bc-nfconf --db logs/run.db --out-dir /path/to/out
```

Это и есть «готовый конфиг для роутера». На Keenetic скопируйте
`nfqws2_*.conf` в `/opt/etc/nfqws2/nfqws2.conf` (или через
`etc/nfqws2/nfqws2.conf` в init-скрипте).

## Отличие от presets/strategies/

| | `configs/*.conf` | `presets/strategies/*.tls/.txt/.http/.quic/.udp` |
|---|---|---|
| Формат | Полный nfqws2-конфиг (фильтры+blobs+hostlist) | Только `--lua-desync`-строки (user-matrix) |
| Потребление | `-c` / `-C` / `--tcp-sources configs` | `-M <name>` / `--strategy-preset` |
| Характер | Одна готовая стратегия/конфиг | Набор стратегий для перебора |

Это **разные форматы и разные резолверы** — они не взаимозаменяемы и не
сливаются в одну папку.
