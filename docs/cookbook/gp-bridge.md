# GP ↔ blockcheckS bridge

Shortlist export/import and flag mapping between GP-control-plane (движок
`discovery_engine=blockchecks`) and blockcheckS. Полный API-контракт — в
`docs/api.md` (§10a).

## Flag mapping

| GP (`DiscoveryOptions`) | blockcheck2 env | blockcheckS |
|-------------------------|-----------------|-------------|
| `repeats` (1..10) | `REPEATS` | `--repeats N` |
| `repeat_parallel` | `PARALLEL=1` | `--parallel-repeats` |
| `curl_parallelism` | `GP_MD_CURL_PARALLELISM` | `--curl-parallel N` (B2 fan-out) |
| `scan_level` quick/standard/force | `SCANLEVEL` | `--scan-level single/fast/full` |

**Do not confuse:** `repeat_parallel` (N curl attempts per strategy) vs `curl_parallelism` / `--curl-parallel` (N domains per nfqws2 session).

## Repeats modes

| Mode | blockcheckS flag | BC2-like behavior |
|------|------------------|-----------------|
| fast (default) | `--repeats-mode fast` | Stop on first PASS (mass-scan speed) |
| stable | `--repeats-mode stable` | Run all N attempts; PASS if any succeeded |

With `--repeats-mode stable` and `--scan-level fast|single`, FAIL stops repeat loop early (BC2 `SCANLEVEL=quick`).

## Мульти-домен и скоуп (1.4.1+)

`bs scan`/`pair` принимают **повторяемый `-d`** (тестируется весь набор), либо
`--preset`, либо **`--domains-file`** (файл bare FQDN, побеждает `-d`/`--preset`;
GP передаёт его для больших v2fly-списков — порог GP: >50 доменов):

```bash
sudo bs scan -d youtube.com -d discord.com -M gp-verified --scan-level fast \
  --repeats 3 --max 400 --db /tmp/gp-run.db --skip-dns-audit

sudo bs scan --domains-file /gp/state/google.txt -M gp-verified --db /tmp/gp-run.db
```

- **Матрица стратегий:** `-M/--strategy-preset` (`gp-verified`, `flowseal-fast`,
  `gp-custom-*`, …) — матрица строго из пресета. `--protocol tls12|tls13`,
  `--repeats-mode fast|stable`, `--no-adaptive`, `--skip-ip-block`, `--debug`
  — управляющие флаги прогона (GP-ключи `strategy_preset`/`repeats_mode`/
  `bs_adaptive`/`debug_stdout`/`skip_ipblock`).

## UDP и пары TCP×UDP (bs pair)

GP-режим «TCP + UDP/пары» вызывает `bs pair` по **одному домену** на
инвокацию (pair-матрица выполняется только на primary-домене). UDP-лейн
создаётся только если preflight домена показал `udp_blocked` (иначе UDP и так
работает, стратегии не нужны). Результаты: `udp_results` (без домена → GP
атрибутирует к домену запуска, кандидаты `protocol='udp'`) и `pair_results`
(пары `overall` PASS/THROTTLED → таблица GP `strategy_pairs`). Exit 1 у
`bs pair` при «TCP PASS есть, но UDP-обход не найден» — валидный отрицательный
результат, не сбой.

```bash
sudo bs pair -d discord.com --db /tmp/gp-run.db --out-dir /tmp/gp-out \
  --skip-dns-audit --skip-deps-check
```

- Завершение пишет `run_summary_<ts>.json` (`run_id`, `domains`, `db_path`) в
  `--out-dir` или XDG `~/.local/share/blockcheckS`. GP передаёт **свежий
  `--db`** на каждый run → чтение результата не пересекается с другими
  кампаниями.
- PASS-кандидаты: `tcp_results.status IN ('PASS','THROTTLED')` ∧
  `bridge_applied IS NULL OR = 1` (кампания строго `=1`), latest row per
  strategy×domain.
- **Аргументы стратегии = `strategies.config_path`** (`get_strategy_config`),
  НЕ `strategies.name` (это слаг). Для «Скопировать для zapret2» и экспорта
  используйте `bc-nfconf`/`export-nfconf` — они резолвят args и
  переименовывают цифровые blob-id (`4pda→b4pda`).

## Движок GP: blockcheck2 vs blockcheckS

`discovery_engine` в GP (панель «Движок подбора») переключает:

- **webui:** меняется панель подбора/preflight-ридинг/кнопки экспорта;
  HTTP-контракт `/api/core/...` тот же, меняется только `payload` пресета.
- **run:** GP вызывает `blockcheck2.sh` (root-helper) либо `bs scan`
  (subprocess, см. выше) по `discovery_engine`.
- **preflight:** `blockcheck2` → GP `check-install`; `blockchecks` →
  `bs preflight --json`/ридинг установки BS.
- **экспорт:** `bc-nfconf`/`export-nfconf` только при `engine=blockchecks`.

## Workflow: время-boxed scan → GP shortlist

```bash
# 1. blockcheckS adaptive mass scan (~2h)
sudo bs full --fan-out --allow-dns-hijack \
  --domains-file presets/domains/benchmark.txt \
  --max-timeh 2 --db logs/bs_run.db --out-dir logs/bs_export

# 2. Export shortlist JSON for GP
python3 -m blockchecks.shortlist_export --db logs/bs_run.db -o logs/shortlist.json

# 3. Optional: seed blockcheckS DB from shortlist
python3 -m blockchecks.shortlist_import -i logs/shortlist.json --seed-db --db logs/seed.db

# 3b. Or seed directly from GP provider_summary.json (P5-1)
python3 -m blockchecks.provider_import -i logs/provider_summary.json --seed-db logs/seed.db
```

## nfconf export

```bash
bc-nfconf --db logs/bs_run.db --limit 3 --out-dir logs/bs_export \
  --domains-file presets/domains/benchmark.txt
```

Produces `nfqws2_*.conf` (keenetic) + raw + user.list — deploy to Keenetic or use as GP seed.
