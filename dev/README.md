# dev/ — смоки, гейты, отладка

Локальные скрипты разработчика. **Не** входят в пакет `blockchecks`, **не**
гоняются GitHub Actions. Предполагают `.venv` и запуск из **корня репо**.

Кампании A→F, systemd и блобы — в [scripts/](../scripts/README.md).
Сброс leftover netns/nfqws2: `scripts/cleanup_env.sh`.

## Quality gates

| Скрипт | Что делает |
|---|---|
| `gate_all.sh` | unit + quality + ruff + vulture; `--integration` — sudo E2E |
| `mutmut_gate.sh` | scoped `mutmut run` (`[tool.mutmut]` в pyproject) |

```bash
bash dev/gate_all.sh
bash dev/gate_all.sh --integration    # sudo + nfqws2, ~10–15 мин
bash dev/mutmut_gate.sh               # медленно; джоба CI только workflow_dispatch
```

## Смоки (живой хост, sudo + nfqws2)

| Скрипт | Что делает |
|---|---|
| `smoke_all.sh` | Оркестратор: все смоки + `gate_all` (бюджет ~90 мин) |
| `smoke_scan.sh` | Короткий `bs scan` на известной матрице |
| `smoke_full_quick.sh` | Time-boxed `bs full`: deadline, export, summary |
| `smoke_backend_matrix.sh` | classic / lua_bridge / env / compare |
| `smoke_flags.sh` | CLI help + флаги, которые другие смоки не трогают |
| `smoke_20min.sh` | ~20 мин, ~90% путей `bs` |
| `release_smoke.sh` | Релизный прогон: benchmark preset + AQ + shortlist |
| `voice_smoke.sh` | UDP голос: dns-alive + `discord_udp` |
| `gv1_smoke.sh` | googlevideo через `bs full` (нужен yt-dlp) |
| `functional_smoke.sh` | По одной пробе каждой CLI-команды |

```bash
bash dev/smoke_scan.sh
sudo bash dev/voice_smoke.sh
bash dev/smoke_all.sh
```

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

```bash
bash dev/run_bs_tcp_debug.sh
python3 dev/strategy_debug_probe.py
python3 dev/complexity_report.py
```
