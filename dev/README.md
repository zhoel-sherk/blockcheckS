# dev/ — смоки, гейты, отладка

Локальные скрипты разработчика. **Не** входят в пакет `blockchecks`, **не**
гоняются GitHub Actions. Предполагают `.venv` и запуск из **корня репо**.

Кампании A→F, systemd и блобы — в [scripts/](../scripts/README.md).
Сброс leftover netns/nfqws2: `scripts/cleanup_env.sh`.

## Требования

- **Passwordless sudo (`sudo -n`)** — почти все смоки вызывают его без пароля.
- nfqws2 на хосте (`/opt/zapret2/nfq2/nfqws2`) + сеть.
- ⚠️ `smoke_full_quick.sh`, `smoke_20min.sh`, `functional_smoke.sh`,
  `smoke_all.sh` стартуют с **host-wide reset** (`cleanup_env.sh` /
  `bs stop --force`) — не запускать параллельно с живой кампанией.
- После длинных марафонов (`smoke_all.sh`, `release_smoke.sh`) чистить мусор:
  `sudo .venv/bin/bs gc --apply` (debug-логи nfqws2, summary, harvest).

## Quality gates

| Скрипт | Что делает | Время |
|---|---|---|
| `gate_all.sh` | unit + quality + ruff + vulture; `--integration` — sudo E2E | 1–5 мин (+10–15 с интеграцией) |
| `mutmut_gate.sh` | scoped `mutmut run` (`[tool.mutmut]` в pyproject); CI-джоба только workflow_dispatch | медленно |

```bash
bash dev/gate_all.sh
bash dev/gate_all.sh --integration    # sudo + nfqws2
bash dev/mutmut_gate.sh
```

## Смоки (живой хост)

| Скрипт | Что делает | Время | Примечания |
|---|---|---|---|
| `smoke_scan.sh` | Короткий `bs scan` на 3 fake-стратегиях × discord.com (`fast --quick`). Аргумент: `default\|classic\|bridge\|compare` | ~1 мин | минимальные риски |
| `smoke_full_quick.sh <домен> <N>` | Time-boxed `bs full` через всю вертикаль: пул netns → lua_bridge → deadline `--max-timem` → БД → экспорт conf/user.list/summary; EXIT-trap = полный reset хоста | 1–3 мин | лучший «жив ли стек» после правок |
| `smoke_backend_matrix.sh` | 6 прогонов одной матрицы: default / `--classic` / `--probe-backend *` / env / compare-drift | 3–6 мин | главный тест lua-моста |
| `smoke_flags.sh` | CLI-surface: `-h` всех подкоманд, отказ на мусорных флагах, ~18 live-прогонов редких флагов, `bs serve` + HTTP health/auth | 15–30 мин | каждый шаг делает `bs stop --force` |
| `smoke_20min.sh` | 9 шагов: backend-matrix, TLS-классификация 4xx, живой прогресс `[N/M]`, export, `--resume`, GV1, UDP voice+pair, HTTP plaintext, serve | 20–35 мин | без trap; `stop --force` на старте |
| `release_smoke.sh` | Релизный `bs full --fan-out` benchmark preset → chown → `aq_benchmark.py` → shortlist round-trip | ~20 мин | fan-out жёстче всех к хосту; внешний timeout есть |
| `smoke_all.sh` | Оркестратор: gate_all + все смоки по очереди между полными reset'ами; бюджет `SMOKE_ALL_BUDGET_SEC` (по умолчанию 5400 c), хвост бюджета уходит в SKIP штатно | до 90 мин | пре-релиз |
| `voice_smoke.sh` | UDP голос: `--discover-dns` + проба `discord_udp`; опционально pair `--full-voice` при найденном токене | 1–2 мин | запускать от юзера (sudo внутри) |
| `gv1_smoke.sh` | googlevideo через `bs full` (GGC binary probe по умолчанию; yt-dlp нужен только при `BLOCKCHECKS_GV_GGC=0`) | 2–4 мин | постоянная БД `logs/gv1_smoke.db` |
| `functional_smoke.sh` | По одной живой пробе каждой CLI-подкоманды + report | 6–12 мин | host-wide reset на старте |

```bash
# Быстрая проверка после правок (~8 мин):
sudo bash scripts/cleanup_env.sh          # если кампания точно остановлена
bash dev/smoke_full_quick.sh discord.com 3
bash dev/smoke_backend_matrix.sh

# Точечные:
bash dev/smoke_scan.sh                    # или: classic|bridge|compare
sudo bash dev/voice_smoke.sh              # см. замечание ниже
SMOKE_ALL_BUDGET_SEC=7200 bash dev/smoke_all.sh
```

### Переменные окружения

| Переменная | Где используется | По умолчанию |
|---|---|---|
| `SMOKE_ALL_BUDGET_SEC` | smoke_all.sh — общий бюджет оркестратора | `5400` |
| `BS`, `PY`, `NF` | переопределение путей к `.venv/bin/bs`, python, nfqws2 в release_smoke/smoke_20min | из репо/PATH |
| `UDP_CONF`, `DISCOVER_N` | voice_smoke.sh — конфиг UDP-пробы и число DNS-discover | `configs/udp_voice__fake_r6.conf`, `2` |
| `BLOCKCHECKS_GV_GGC=0` | gv1/smoke_20min — откат GGC-детектора на yt-dlp | `1` (GGC) |
| `DPI_TESTER_SETTINGS` | voice_smoke.sh — где искать Discord-токен для опционального `--full-voice` | env или `settings.ini` рядом |

### Не покрыто смоками (добавить при случае)

- `bs gc` и `bs harvest-batch` (нет в help-цикле `smoke_flags.sh` — скрипты
  новее смоков);
- флаги карантина `--no-quarantine/--quarantine-min/--quarantine-auto-denylist`;
- `--no-export-on-stop`, `--lua-extra`, `--voice-burst`, `--offline`;
- assert на отсутствие `[bridge] no heartbeat` / BRIDGE_DRIFT в логах прогонов.

## Отладка и бенчи

| Скрипт | Что делает |
|---|---|
| `run_bs_tcp_debug.sh` | Одна известная TCP-стратегия с `--debug` nfqws2 |
| `run_gp_debug.sh` | GP-подтверждённые стратегии + разбор лога |
| `strategy_debug_probe.py` | Одна стратегия nfqws2 без полного скана |
| `aq_benchmark.py` | Скорость нахождения PASS vs порядок очереди |
| `speed_benchmark.sh` | blockcheck2.sh vs classic vs lua_bridge |
| `byedpi_bench.py` | Микробенч byedpi/ciadpi vs nfqws2 |
| `complexity_report.py` | Гистограмма McCabe (ruff C90) |
| `diag_bridge_boot.py` | Boot-race харнесс моста (изоляция смертей демонов) |
| `capture_quic_blob.sh` | Захват QUIC Initial → блоб (на Fryazino только с VPS) |

```bash
bash dev/run_bs_tcp_debug.sh
python3 dev/strategy_debug_probe.py
python3 dev/complexity_report.py
```
