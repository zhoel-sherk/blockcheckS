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

## CLI

Entry point: `bs` → `blockchecks.bs:main`.

| Команда | Назначение |
|---------|------------|
| `bs tcp` | одна TCP-стратегия / configs-dir (sync) |
| `bs udp` | STUN-probe UDP voice |
| `bs scan` | async TCP batch (`pair --tcp-only`) |
| `bs pair` | TCP×UDP matrix, resume, auto-discover |
| `bs composite` | один composite .conf × список доменов |

Примеры:

```bash
sudo bs scan -d discord.com --generate custom,configs --max 50 --parallel 4
sudo bs pair -d discord.com --generate --scan-level fast --auto-discover 5
sudo bs pair -d discord.com -c configs/alt__fake_fakedsplit_ts.conf -u configs/udp_voice__fake_r6.conf
sudo bs pair -d discord.com --resume   # откажется, если matrix fingerprint сменился
```

`--auto-discover N` — DNS bulk `finland{N}.discord.gg` (+ опционально gateway).
Сейчас в matrix берётся **первый** найденный endpoint (multi-EP loop — в todo).

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
| `configs/` | в **корне репо** (editable); `CONFIGS_DIR` резолвится от `PROJECT_DIR` |
| `tests/` | unit + integration |
| `docs/` | guide / todo |

Не запускайте устаревшие копии `engine/` / `checkers/` из корня — их больше
нет в git; рабочий код только под `src/blockchecks/`.

## Известные ограничения (post-package audit)

1. `bs scan` сейчас принудительно ставит `auto_discover=False` — флаг на scan
   бесполезен, пока это не уберут.
2. Multi-endpoint discovery сохраняет список, но pair гоняет только `eps[0]`.
3. `stderr=PIPE` у nfqws2 без drain на success — риск pipe fill на болтливом бинаре.
4. В git лучше не держать `state.db` и `*.egg-info` (gitignore + untrack).
5. На Windows `bs --help` падал на `×` в argparse (cp1251) — заменено на `x`.

## Packaging check

```bash
python -c "from blockchecks.engine.config import PROJECT_DIR, CONFIGS_DIR; import os; print(PROJECT_DIR); assert os.path.isdir(CONFIGS_DIR)"
bs pair -h
pytest -m "not integration" -q
```
