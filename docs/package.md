# Package structure — blockcheckS

Аудит layout после packaging + `bs full` (2026-07).

## Канон

Единственный source of truth:

```
blockcheckS/
├── src/blockchecks/           # installable package
│   ├── __init__.py            # __version__ = 0.3.0
│   ├── bs.py                  # CLI: tcp|udp|scan|pair|composite + full dispatch
│   ├── main.py                # bs full orchestrator
│   ├── nfconf.py              # bc-nfconf export
│   ├── engine/
│   │   ├── config.py          # paths, bins, constants (PROJECT_DIR = repo root)
│   │   ├── nfqws2.py          # process lifecycle
│   │   ├── firewall.py        # tracked iptables NFQUEUE
│   │   ├── netns_pool.py      # parallel netns workers
│   │   ├── strategy_loader.py
│   │   ├── matrix_generator.py  # StrategyItem + generators
│   │   ├── test_runner.py     # sync single-ns
│   │   ├── async_runner.py    # parallel TCP/UDP/pairs
│   │   ├── pair_manager.py    # DualNfqws2Manager
│   │   ├── pair_runner.py     # sync pair matrix (legacy path)
│   │   ├── db_logger.py       # aiosqlite + best/coverage
│   │   └── conf_builder.py    # keenetic + raw conf text
│   └── checkers/
│       ├── tcp_tls.py
│       ├── udp_voice.py       # STUN + Discord IP Discovery
│       ├── voice_dns.py       # discover-dns (concurrency=4)
│       ├── voice_discovery.py # token / gateway / sing-box
│       ├── youtube_url.py
│       └── composite_runner.py
├── configs/                   # repo-root .conf (CONFIGS_DIR)
├── presets/                   # domains + strategies (+ voice lists)
├── tests/unit|integration/
├── docs/                      # guide, todo, package
├── tmp-scripts/               # ad-hoc diagnostics (not packaged)
└── pyproject.toml
```

Entry points (`pyproject.toml`):

| Script | Target |
|--------|--------|
| `bs` | `blockchecks.bs:main` |
| `bc-main` | `blockchecks.main:main` |
| `bc-nfconf` | `blockchecks.nfconf:main` |

## Path resolution

`PROJECT_DIR` в `engine/config.py` — **корень репозитория** (родитель `src/`),
не `site-packages`. Поэтому editable install ищет:

- `configs/*.conf`
- `presets/...`
- `state.db` / `output/` в CWD (обычно repo root)

`package-data` объявляет `blockchecks/configs/*.conf`, но файлы лежат в
**repo `configs/`**, не под `src/blockchecks/configs/`. Wheel без editable
сейчас **не** несёт рабочие conf — это сознательный tech debt (см. todo).

## Что убрать / не трогать

| Путь | Вердикт |
|------|---------|
| Root `checkers/`, `engine/` | Только мёртвый `__pycache__` от pre-src layout → удалить |
| Root `research.md`, `GOALS.md` | Stubs → `docs/todo.md` |
| `tmp-scripts/` | Оставить; вне ruff/pytest |
| `src/logs/`, root `logs/` | Runtime cache; gitignored |
| `state.db` | Local; gitignored |
| Duplicate `StrategyItem` | Исправлено: определение в `matrix_generator`, re-export из `async_runner` |

## Зависимости качества кода

```bash
pip install -e ".[dev,discovery]"
ruff check src tests
ruff format src tests   # optional
pytest -m "not integration"
```

Ruff: `E/W/F/I/UP/B/SIM` с точечными ignores (E501, process-cleanup SIM105, …).
`E402` пока на модулях с `colorama_init()` до локальных импортов.

## Импорт-граф (упрощённо)

```
bs ──► async_runner / test_runner / matrix_generator / db_logger
main ──► async_runner + nfconf.export_configs
nfconf ──► conf_builder + db_logger (get_best_*)
async_runner ──► checkers.tcp_tls / udp_voice + netns_pool + nfqws2
voice_dns ──► udp_voice.voice_udp_probe + optional bootstrap nfqws2
```

## Риски / next tidy

1. **Два pair path**: `pair_runner` (sync) и `async_runner.test_pair_matrix` —
   документировать какой CLI путь канонический (`bs pair` → async).
2. **Пустые `__init__.py`** в engine/checkers — можно реэкспортировать публичный API.
3. **configs in wheel** — либо копировать в пакет, либо `package-data` убрать и
   явно требовать editable/repo checkout в guide.
4. Не запускать код из устаревших корневых `engine/`/`checkers/` — их больше нет.
