# dev/ — смоки, гейты, отладка

Локальные скрипты разработчика. **Не** входят в пакет `blockchecks`, **не**
гоняются GitHub Actions. Предполагают `.venv` и запуск из **корня репо**.

Кампании A→F, systemd и блобы — в [scripts/](../scripts/README.md).
Сброс leftover netns/nfqws2: `scripts/cleanup_env.sh`.

## Три яруса (после triple_audit)

1. **Флаги (CI, без sudo)** — `pytest` `test_cli_modernization` / `test_dead_cli_flags` / `test_cliapp`. Help, reject, `--classic`→lua_bridge, `--curl-parallel` 1 и 8, dests `gc`/`harvest-batch`/`mcp`.
2. **Смок (Xeon, 3–8 мин)** — `smoke_full_quick.sh` + `smoke_scan.sh default`. `assert_smoke_db.py`: нет PASS без `bridge_applied=1`, лог `backend=lua_bridge`.
3. **Функциональные (Xeon, 15–30 мин)** — `functional_smoke.sh` (все команды + `tcp --ns` + gc/harvest/карантин) и `smoke_flags.sh` live.

Живые nfqws2-пробы **не** идут на GitHub `ubuntu-latest`.

## Требования

- **Passwordless sudo (`sudo -n`)** — почти все смоки вызывают его без пароля.
- nfqws2 на хосте (`/opt/zapret2/nfq2/nfqws2`) + сеть.
- ⚠️ `smoke_full_quick.sh`, `smoke_20min.sh`, `functional_smoke.sh`,
  `smoke_all.sh` стартуют с **host-wide reset** (`cleanup_env.sh` /
  `bs stop --force`) — **не** запускать при живом `run.lock` (week_cov).
  Скрипты сами выходят с кодом 2, если lock есть.
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
| `smoke_scan.sh` | Короткий `bs scan` на 3 fake × discord.com. Default lua_bridge; `--classic`/`--probe-backend classic` warn+map к lua_bridge, `--lua-bridge-compare` удалён. | ~1 мин | + `assert_smoke_db.py` |
| `smoke_full_quick.sh <домен> <N>` | Time-boxed `bs full` + APPLIED gate в БД | 1–3 мин | EXIT-trap = полный reset хоста |
| `smoke_backend_matrix.sh` | Функциональный тест выбора backend: default→lua_bridge, `--classic`/`--probe-backend classic` warn+map, env override; `--lua-bridge-compare` удалён. | 3–6 мин | не «два бэкенда» |
| `smoke_flags.sh` | CLI `-h` + reject + live флаги + gc/harvest-batch + serve HTTP | 15–30 мин | `bs stop --force` между шагами |
| `smoke_all.sh` | gate_all → flags pytest → smoke_full_quick → functional_smoke → smoke_flags → backend_matrix → … | до 90 мин | отказ при `run.lock` |
| `functional_smoke.sh` | Все подкоманды + `tcp --ns` + harvest APPLIED + gc/harvest/карантин | 6–15 мин | отказ при `run.lock` |
| `smoke_20min.sh` | 9 шагов: backend-matrix, TLS 4xx, прогресс, export, `--resume`, GV1, UDP, HTTP, serve | 20–35 мин | `stop --force` на старте |
| `release_smoke.sh` | Релизный `bs full --fan-out` → shortlist round-trip | ~20 мин | fan-out жёстче к хосту |
| `voice_smoke.sh` | UDP голос `--discover-dns` + `discord_udp` | 1–2 мин | от юзера (sudo внутри) |
| `gv1_smoke.sh` | googlevideo через `bs full` | 2–4 мин | `logs/gv1_smoke.db` |

```bash
# Быстрая проверка после правок (~8 мин):
sudo bash scripts/cleanup_env.sh          # если кампания точно остановлена
bash dev/smoke_full_quick.sh discord.com 3
bash dev/smoke_backend_matrix.sh

# Точечные:
bash dev/smoke_scan.sh                    # default lua_bridge; --classic warn+map, compare removed
sudo bash dev/voice_smoke.sh
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

### Не покрыто смоками

- `--no-export-on-stop`, `--lua-extra`, `--voice-burst`, `--offline` (live)
- assert `[bridge] no heartbeat` / BRIDGE_DRIFT как отдельный grep (есть порог `PASS without APPLIED` в `assert_smoke_db.py`)

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
