# Guide — blockcheckS

## Что это

`blockchecks` — Python-пакет для быстрого перебора DPI-стратегий под
**zapret2/nfqws2**. Цель: подборщик, который **не врёт** (в отличие от
наивных PASS в `blockcheck.sh` / blockcheckw): браузерный TLS, проверка
тела/DPI-заглушек, изоляция netns, TCP×UDP пары, resume по fingerprint.

## Установка

```bash
git clone <repo> && cd blockcheckS
python -m venv .venv
# Linux:
source .venv/bin/activate
pip install -e ".[dev,discovery]"
```

Требования на host (для реального прогона, не для unit):

- Linux, root/sudo
- `nfqws2` (по умолчанию `/opt/zapret2/nfq2/nfqws2`)
- Lua/blobs zapret2
- опционально sing-box + Discord token для full voice discovery

Переменные: `BLOCKCHECKS_NFQWS2`, `BLOCKCHECKS_PYTHON`, `BLOCKCHECKS_SETTINGS`, …
См. [`settings.example.env`](../settings.example.env).

Документация для разработчиков: [CONTRIBUTING.md](../CONTRIBUTING.md),
[architecture.md](architecture.md), [database.md](database.md),
[cookbook/](cookbook/).

## CLI

Entry point: `bs` → `blockchecks.bs:main`.

| Команда | Назначение |
|---------|------------|
| `bs tcp` | одна TCP-стратегия / configs-dir (sync) |
| `bs udp` | STUN-probe UDP voice |
| `bs scan` | async TCP batch (`pair --tcp-only`) |
| `bs pair` | TCP×UDP matrix, resume, auto-discover |
| `bs composite` | один composite .conf × список доменов |
| `bs full` | mass strategy×coverage + voice/QUIC/pairs + conf export |
| `bc-nfconf` | export keenetic+raw conf from existing `state.db` |

Примеры:

```bash
sudo bs scan -d discord.com --generate custom,configs --max 50 --parallel 4
sudo bs pair -d discord.com --generate --scan-level fast --auto-discover 5
sudo bs pair -d discord.com -c configs/alt__fake_fakedsplit_ts.conf -u configs/udp_voice__fake_r6.conf
sudo bs pair -d discord.com --resume   # откажется, если matrix fingerprint сменился

# Mass run (intentionally huge — GP-scale strategy×domain). Defaults = max.
sudo bs full
sudo bs full --parallel 2 --resume
sudo bs full --max 500 --domains-file presets/domains/critical.txt
bc-nfconf --db state.db --limit 3 --out-dir output
```

`bs full` writes `output/nfqws2_<ts>.conf` (keenetic), `nfqws2_raw_<ts>.conf`,
and `user.list`. ETA printed as `N_strat × N_domains / parallel`. Resume skips
`(strategy, domain)` already in DB. STUN discover concurrency is capped at 4.

`--auto-discover N` — DNS bulk `finland{N}.discord.gg` (+ опционально gateway).
Сейчас в matrix берётся **первый** найденный endpoint (multi-EP loop — в todo).

## Curl repeats (BC2 / GP parity)

Three levels — see [glossary.md](glossary.md):

| Flag | GP / BC2 | Meaning |
|------|----------|---------|
| `--repeats N` | `REPEATS` / `repeats` | N curl attempts per strategy×domain (1–10) |
| `--parallel-repeats` | `PARALLEL` / `repeat_parallel` | Run repeats concurrently |
| `--repeats-mode fast\|stable` | — | `fast`=first PASS; `stable`=all N like blockcheck2 |
| `--curl-parallel N` | `curl_parallelism` | Multi-domain fan-out (B2, **not** repeats) |

GP bridge workflow: [cookbook/gp-bridge.md](cookbook/gp-bridge.md).

## Тесты

```bash
pip install -e ".[dev]"
pytest -m "not integration"    # Windows/Linux без root
sudo pytest -m integration     # Linux + nfqws2
```

Конфиг pytest — в `pyproject.toml` (`addopts = -m "not integration"`).

Unit покрывает контракты: `PYTHON_BIN`, checkpoint/resume, `run_set`,
sqlite single-connection, UA, stale PASS, package imports.

## Layout после packaging

| Путь | Роль |
|------|------|
| `src/blockchecks/` | единственный source of truth |
| `src/blockchecks/cli/` | argparse + command handlers |
| `src/blockchecks/engine/generators/` | strategy matrix generators |
| `configs/` | в **корне репо** (editable); `CONFIGS_DIR` резолвится от `PROJECT_DIR` |
| `tests/` | unit + integration |
| `docs/` | guide, architecture, database, cookbook, todo, package |

Полный разбор: [architecture.md](architecture.md), [package.md](package.md).

Не запускайте устаревшие копии `engine/` / `checkers/` из корня — их больше
нет в git; рабочий код только под `src/blockchecks/`.

## Dev quality

```bash
pip install -e ".[dev]"
ruff check src tests
pytest -m "not integration"
```

## Известные ограничения (post-package audit)

1. `bs scan` сейчас принудительно ставит `auto_discover=False` — флаг на scan
   бесполезен, пока это не уберут.
2. Multi-endpoint discovery сохраняет список, но pair гоняет только `eps[0]`.
3. `stderr=PIPE` у nfqws2 без drain на success — риск pipe fill на болтливом бинаре.
4. В git лучше не держать `state.db` и `*.egg-info` (gitignore + untrack).
5. На Windows `bs --help` падал на `×` в argparse (cp1251) — заменено на `x`.

## Troubleshooting

**nfqws2 not found / command not found**
- Проверь `/opt/zapret2/nfq2/nfqws2` или разреши авто-фетч: удали `--no-fetch-deps`.
- Вручную: `export BLOCKCHECKS_NFQWS2=/path/to/nfqws2`.
- Или пропиши в `~/.config/blockcheckS/config.toml` → `[tools] nfqws2`.

**Permission denied / sudo password prompt**
- blockcheckS требует **passwordless sudo** (`sudo -n`).
- Добавь в `/etc/sudoers.d/blockchecks`: `username ALL=(ALL) NOPASSWD: ALL`.
- Юнит-тесты (`pytest`) запускаются БЕЗ sudo.

**Все стратегии FAIL / parse: / timeout**
- nfqws2 крашнулся при старте? Проверь `BLOCKCHECKS_NFQWS2_DEBUG=1 bs tcp ...`.
- Увеличь таймаут: `--timeout 20` (дефолт 10).
- Проверь iptables: `sudo iptables -L OUTPUT -n | grep NFQUEUE`.
- Для googlevideo.com: это известная проблема — IP `142.251.x.x` блокируется на уровне IP (не SNI).

**STUN probe всегда timeout**
- GCP Discord-сервера требуют активную WebSocket-сессию для ответа на STUN.
- Без `--full-voice` (gateway WS + voice WS) STUN таймаутит — это ожидаемо.

**Database is locked**
- SQLite под нагрузкой нескольких воркеров. `bs full` автоматически ставит `busy_timeout=5000`.
- При ручном конкурентном доступе к `state.db` используй отдельные копии.

**netns: RTNETLINK answers: Operation not permitted**
- Убедись что модуль `veth` загружен: `sudo modprobe veth`.
- Проверь `sysctl net.ipv4.ip_forward=1`.

## Packaging check

```bash
python -c "from blockchecks.engine.config import PROJECT_DIR, CONFIGS_DIR; import os; print(PROJECT_DIR); assert os.path.isdir(CONFIGS_DIR)"
bs pair -h
pytest -m "not integration" -q
```
