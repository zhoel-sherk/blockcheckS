# scripts/ — кампании, установка, пресеты

Боевые прогоны на хосте с nfqws2. **Не** входят в wheel и **не** гоняются CI.
Смоки, гейты качества и отладка — в [dev/](../dev/README.md).
Длинные серии: [docs/long_term_runs.md](../docs/long_term_runs.md).

Запускать из **корня репозитория**. Нужны `.venv` и, для live-прогонов, `sudo`.

## Кампании (подбор стратегий)

Долгие `bs full` / `bs pair` в tmux. По умолчанию 20 часов на вариант.

| Скрипт | Что делает |
|---|---|
| `run_variant.sh` | Один вариант A–F (`bs full`) или G (`bs pair`, Discord UDP) |
| `run_long_term_series.sh` | Последовательно A→F |
| `boot_resume_series.sh` | Старт серии с systemd, только если БД прогона уже не пустая |
| `run_coverage_new.sh` | Отдельный прогон B (полный пул + geneva.lua) |
| `run_full_coverage.sh` | `bs full` по `coverage.txt` (~40 доменов) |
| `run_full_20h.sh` | Один time-boxed `bs full` в tmux |
| `monitor_series.sh` | Прогресс/PASS по БД варианта A–G |

```bash
scripts/run_long_term_series.sh 20 A     # A→F, по 20 ч
scripts/run_variant.sh G 20               # только Discord-voice UDP
scripts/monitor_series.sh A
```

## Установка и сервис

| Скрипт | Что делает |
|---|---|
| `setup-standalone.sh` | venv + pip на Linux / Raspberry Pi |
| `install_systemd.sh` | Юниты `blockcheck-series` и `blockcheck-serve` |
| `uninstall_systemd.sh` | Снять эти юниты |
| `install_blobs.sh` | Дополнительные блобы на хост (`BLOCKCHECKS_BLOBS`) |
| `verify_blobs.py` | Проверка алиасов и файлов блобов |
| `gen_presets_manifest.py` | `check` / `counts` для `presets/manifest.toml` |

```bash
bash scripts/setup-standalone.sh
sudo bash scripts/install_systemd.sh
python3 scripts/verify_blobs.py
python3 scripts/gen_presets_manifest.py check
```

## Сброс хоста

`cleanup_env.sh` убивает leftover nfqws2 / netns / veth / shm IPC / `run.lock`.
Нужен `sudo`. Его же вызывают integration-тесты и смоки из `dev/`.

```bash
sudo bash scripts/cleanup_env.sh
```
