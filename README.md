# blockcheckS — подбор стратегий обхода DPI

[![version](https://img.shields.io/badge/version-1.3.8-green)](#)
[![python](https://img.shields.io/badge/python-3.10%2B-green)](#)
[![license](https://img.shields.io/badge/license-MIT-brightgreen)](LICENSE)
[![tests](https://img.shields.io/badge/tests-1528%20unit-success)](#)

Программа на Linux перебирает стратегии **nfqws2 / zapret2** и показывает,
какие из них реально открывают заблокированный сайт у твоего провайдера.
Результат можно выгрузить в готовый конфиг для роутера (Keenetic, OpenWrt, Linux).

Нужны **Linux и root** (network namespaces + iptables). Python 3.10+.

В отличие от остальных подборщиков использует curl_cffi для получения валидных результатов с помощью имитации слепка браузера, 
стратегии полученные таким путём проверены и они работают в 99 случаях из 100 в отличии от стандартного blockcheck2.sh из комплекса zapret2 или blockcheckw который написан на Rust - респект чуваку за скорость но возиться долго не хочется с роутером из-за того что стратегии не подходят и нужен ручной перебор. 
Так-же программа умеет определять DNS-hijack, резолвить на подборе валидный ip с игнором домена, что тоже плюс - ты не дёргаешь мёртвую сосиску просто так 20 часов. Так-же в проекте есть проверки по UDP - дискордик будет работать, остальных я потом прикручу по возможности.
Кто дочитал досюда - да, этот проект написан на сто процентов нейросетсями - дипсик в4, грок4.6, гемини3.7 - мне не стыдно, когда-нибудь сам научусь.

Очень помогли:
[byedpi](https://github.com/hufrea/byedpi)
[zapret2](https://github.com/bol-van/zapret2)
[zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube)
[blockcheckw](https://github.com/rcd27/blockcheckw)
[discord-servers](https://github.com/Maks-gaming/discord-servers)
[geneva](https://github.com/Kkevsterrr/geneva)
[curl-cffi](https://github.com/lexiforest/curl_cffi)


---

## Оглавление

1. [Как это работает](#как-это-работает)
2. [Быстрый старт](#быстрый-старт)
3. [Установка](#установка)
4. [Docker / Podman](#docker--podman)
5. [Команды](#команды)
6. [Пресеты](#пресеты)
7. [Экспорт для роутера](#экспорт-для-роутера)
8. [Документация](#документация)
9. [Для разработчиков](#для-разработчиков)
10. [Дисклеймер](#дисклеймер)

---

## Как это работает

Берёшь домен, запускаешь одну команду — получаешь список рабочих стратегий.
Каждая проба идёт в отдельном network namespace, чтобы не ломать сеть хоста.
Состояние пишется в SQLite: можно остановить прогон и продолжить позже.

```bash
sudo bs scan -d discord.com --generate --parallel 4
```

По сравнению с оригинальным `blockcheck.sh` тот же перебор быстрее (параллельные
пробы) и умеет не только TCP, но и голос Discord (UDP).

---

## Быстрый старт

```bash
pip install -e ".[dev,discovery]"

# проверить, что nfqws2 и sudo живы (~минуты)
sudo bs scan --preset benchmark --profile smoke --generate

# YouTube + Discord + соседние сервисы (часы, с resume)
sudo bs full --preset coverage-tcp --resume --parallel 4
```

Подробности и экспорт: [docs/guide.md](docs/guide.md).

---

## Установка

```bash
git clone https://github.com/zhoel-sherk/blockcheckS.git
cd blockcheckS
pip install -e ".[dev,discovery]"
```

С версии 1.2.1a пакет с PyPI тоже самодостаточен (`pip install blockchecks`):
в wheel входят `configs/`, `presets/`, `blobs/` и `lua/`.

**nfqws2.** Если бинаря нет, blockcheckS скачает релиз
[bol-van/zapret2](https://github.com/bol-van/zapret2) в
`~/.local/share/blockcheckS/zapret2/`. Уже стоит `/opt/zapret2` — использует его.
Отключить скачивание: `--no-fetch-deps`.

**Блобы** лежат в репо (`blobs/`). Другой каталог: `BLOCKCHECKS_BLOBS`.
Дополнительно на хост: `scripts/install_blobs.sh`. Flowseal-наборы:
`--tcp-sources flowseal` / `-M flowseal-fast`
([howto](docs/cookbook/blobs.md)).

**Raspberry Pi 2+ (armv7l)** — установка без компиляции:

```bash
bash scripts/setup-standalone.sh
```

Подробности: [docs/install-rpi.md](docs/install-rpi.md).

Юнит-тесты **без root**:

```bash
pytest -m "not integration"
```

---

## Docker / Podman

Контейнер проверяет пакет (CLI, configs/blobs), не живой DPI.
Для `bs scan` нужен Linux-хост с root.

```bash
podman run --rm -v "$PWD":/src:ro -w /src python:3.12-slim \
  bash -c 'pip install . && bs --help'

podman run --rm python:3.12-slim \
  bash -c 'pip install blockchecks && bs --help'
```

Локальный CI как на GitHub — [nektos/act](https://github.com/nektos/act) + socket
podman. Монолитный `pytest tests/` в CI не гонять (шарды S1/S2/S3).

```bash
systemctl --user enable --now podman.socket
export DOCKER_HOST="unix://${XDG_RUNTIME_DIR:-/run/user/$UID}/podman/podman.sock"
./bin/act -j lint-and-quality -P ubuntu-latest=catthehacker/ubuntu:act-latest
./bin/act -j unit-tests       -P ubuntu-latest=catthehacker/ubuntu:act-latest
```

---

## Команды

| Команда | Простыми словами | Пример |
|---|---|---|
| `bs scan` | Подобрать TCP-стратегии | `sudo bs scan -d discord.com --generate --parallel 4` |
| `bs pair` | То же + голос Discord (UDP) | `sudo bs pair -d discord.com --generate --auto-discover 5` |
| `bs full` | Длинная кампания и экспорт | `sudo bs full --profile 20h` |
| `bs tcp` / `bs udp` | Проверить одну готовую стратегию | `sudo bs tcp -d discord.com -c configs/simple_fake__fake_ts.conf` |
| `bs preflight` | Только диагноз DPI, без перебора | `sudo bs preflight -d youtube.com` |
| `bs serve` | Демон для повторных проб | `sudo bs serve --pool 2` |
| `bs mcp` | Мост для Cursor / Claude / opencode | `bs-mcp` — [docs/mcp.md](docs/mcp.md) |
| `bc-nfconf` | Собрать конфиг роутера из БД | `bc-nfconf --db state.db --out-dir output` |

Готовые наборы флагов: `--profile smoke` (20 стратегий), `fast` (100),
`20h` (длинная серия). Работают в `scan`, `pair`, `full`.

Полезные вещи включены по умолчанию. Выключить явно:
`--no-adaptive`, `--no-preflight` (или `--quick`), `--no-ech`, `--no-wssize`,
`--no-voice`.

Полный справочник: [docs/guide.md](docs/guide.md).

---

## Пресеты

Готовые списки доменов и стратегий:

```bash
bs scan --preset benchmark --generate        # 6 доменов, быстрая проверка
bs scan --preset discord --generate          # Discord
bs scan --preset google-youtube --generate   # YouTube
bs scan -d discord.com -M blockcheckS-best   # проверенные стратегии
```

Список: `bs scan --list-presets`. Подробности: [presets/README.md](presets/README.md).

---

## Экспорт для роутера

После прогона лучшие стратегии можно выгрузить в nfqws2-конфиг:

```bash
bc-nfconf --db logs/run.db --out-dir /path/to/out
bc-nfconf --db logs/run.db --out-dir /path/to/out --ipset   # плюс IP-фильтр
```

На Keenetic: `nfqws2_*.conf` → `/opt/etc/nfqws2/nfqws2.conf`.
См. [configs/README.md](configs/README.md).

---

## Документация

| Документ | О чём |
|---|---|
| [User Guide](docs/guide.md) | Команды, примеры, ограничения |
| [Architecture](docs/architecture.md) | Как устроен прогон |
| [Package Layout](docs/package.md) | Дерево репозитория, пути |
| [Database](docs/database.md) | SQLite, resume |
| [MCP](docs/mcp.md) | Подключение к LLM-клиентам |
| [Raspberry Pi](docs/install-rpi.md) | Установка на armv7l |
| [Glossary](docs/glossary.md) | Термины |
| [API](docs/api.md) | HTTP / сокет / MCP |
| [Changelog](changelog.md) | История (1.3.7 и ранее) |
| [Roadmap](docs/todo.md) | Что ещё не сделано |

Скрипты кампаний: [scripts/README.md](scripts/README.md).
Смоки и гейты качества: [dev/README.md](dev/README.md).

Cookbook: [checker](docs/cookbook/add-checker.md) ·
[generator](docs/cookbook/add-generator.md) ·
[CLI-флаг](docs/cookbook/add-cli-flag.md) ·
[GP](docs/cookbook/gp-bridge.md).

---

## Для разработчиков

- [CONTRIBUTING.md](CONTRIBUTING.md) — установка, тесты, PR
- [docs/architecture.md](docs/architecture.md) — устройство кода

```bash
pip install -e ".[dev,discovery]"
ruff check src tests
pytest -m "not integration"          # юнит, без root
bash dev/gate_all.sh                 # unit + quality + ruff + vulture
```

---

## Дисклеймер

### English
This software is provided "as is", without warranty of any kind, express or
implied. **blockcheckS** is an open-source analytical tool designed strictly for
educational, academic, and network research purposes. It is intended for network
administrators and systems engineers to analyze Deep Packet Inspection (DPI)
behaviors and diagnose network topologies.

*   The author(s) do not encourage, facilitate, or promote any illegal
    activities or violations of local telecommunication laws.
*   This software does not contain any malicious code, malware, or exploits
    designed to compromise computer security or bypass information protection
    systems (in compliance with Art. 273 of the Criminal Code of the Russian
    Federation).
*   The use of this tool is entirely **at your own risk**. The author(s) shall
    not be held liable for any direct, indirect, incidental, or consequential
    damages, service disruptions, or legal actions resulting from the use or
    misuse of this software.

### Русский
Данное программное обеспечение предоставляется по принципу «как есть» (as is).
**blockcheckS** является аналитическим инструментом и распространяется
исключительно в ознакомительных, научно-исследовательских и диагностических
целях для системных инженеров и сетевых администраторов.

*   **Исключительно исследовательский характер**: Программа предназначена для
    изучения механизмов работы систем глубокого анализа пакетов (DPI) и не
    содержит вредоносного функционала, средств обхода систем защиты информации
    или вирусов (соответствует требованиям **Ст. 273 УК РФ**). Утилита
    оперирует стандартными сетевыми вызовами и легитимными механизмами ядра
    Linux.
*   **Соблюдение законодательства**: Автор(ы) не призывают к нарушению
    действующего законодательства Российской Федерации, включая Федеральный
    закон «О связи» № 126-ФЗ и Федеральный закон «Об информации, информационных
    технологиях и о защите информации» № 149-ФЗ.
*   **Отказ от ответственности**: Вы используете данное ПО **на свой страх и
    риск**. Автор(ы) не несут ответственности за любые ограничения связи,
    блокировки, штрафы, потерю данных или иные прямые или косвенные
    последствия, возникшие в результате работы или неправильной настройки
    данной утилиты.
