# blockcheckS — lightspeed DPI strategy tester

[![version](https://img.shields.io/badge/version-1.1.0-blue)](#)
[![python](https://img.shields.io/badge/python-3.10%2B-green)](#)
[![license](https://img.shields.io/badge/license-MIT-brightgreen)](LICENSE)
[![tests](https://img.shields.io/badge/tests-389%20passed-success)](#)

**Твой провайдер режет YouTube, Discord и Telegram через DPI?**
*blockcheckS за 10 минут найдёт работающий обход из 10 000+ комбинаций,
пока ты пьёшь кофе. В 33 раза быстрее, чем blockcheck.sh.*

> Асинхронный подбор стратегий nfqws2/zapret2 в изолированных network
> namespaces. HTTP/2 и HTTP/3 через браузерный TLS-отпечаток (JA4),
> TCP×UDP pair matrix с авто-дискавери голосовых эндпоинтов Discord,
> checkpoint/resume, SQLite-стейт и экспорт готового конфига для Keenetic.

- ⚡ **1 тест/сек** — 33× быстрее blockcheck.sh (0.43 тест/сек)
- 🔍 **10 886 стратегий** — StandardGenerator: 17 TCP-семей + HTTP :80 + QUIC + UDP voice
- 🎭 **Браузерный JA4** — curl_cffi с Chrome 124 BoringSSL (не палится как скрипт)
- 🏊 **Netns pool** — пресозданные изолированные namespace'ы, ни один пакет не уходит мимо
- 📊 **TCP×UDP матрицы** — ищет пары стратегий для голоса Discord
- 💾 **Checkpoint/resume** — упал роутер? Продолжи с места, SQLite помнит всё
- 📦 **nfconf export** — готовый конфиг для Keenetic, Linux, OpenWrt
- 🤖 **Zapret2 auto-fetch** — сам скачает nfqws2 с GitHub, если нет локально

---

## Оглавление

1. [Что такое blockcheckS? (30 секунд)](#что-такое-blockchecks-30-секунд)
2. [Сравнение с blockcheck.sh](#сравнение-с-blockchecksh)
3. [Быстрый старт](#быстрый-старт)
4. [Установка](#установка)
5. [CLI команды](#cli-команды)
6. [Пресеты](#пресеты)
7. [Документация](#документация)
8. [For contributors](#for-contributors)
9. [Дисклеймер](#дисклеймер)

---

## Что такое blockcheckS? (30 секунд)

Берёшь домен (скажем, `discord.com`), запускаешь одну команду — и через пару
минут получаешь список стратегий nfqws2, которые **реально работают** на твоём
провайдере. Никакого гадания на кофейной гуще с `badsum`/`fakedsplit` — только
холодный, циничный перебор через изолированные netns с браузерным JA4.

```bash
sudo bs scan -d discord.com --generate --parallel 4
# → 29 стратегий за 8 секунд, 3 PASS
```

Под капотом: asyncio + NetNsPool + curl_cffi + nfqws2 + SQLite + немного магии.

---

## Сравнение с blockcheck.sh

| blockcheck.sh (оригинал) | blockcheckS (этот парень) |
|---|---|
| ~60–120 сек на стратегию | ~3–5 сек на стратегию (async parallel) |
| System curl / OpenSSL | curl_cffi с браузерным JA4 (Chrome 124 BoringSSL) |
| Только TCP | TCP + UDP voice (STUN + IP Discovery) |
| Последовательный shell | asyncio + NetNsPool (netns переиспользуются) |
| Легко «ложно-зелёный» | Content validation + DPI fake detection |
| 32 000+ комбинаций, медленно | 10 886 комбинаций, **быстро** (покрытие ≥90% BC2) |
| Только bash | Python-пакет, `pip install`, pytest, ruff |

---

## Быстрый старт

Три команды — и ты в деле:

```bash
# 1. Установка (editable, см. ниже почему)
pip install -e ".[dev,discovery]"

# 2. Первый скан — 29 стратегий на discord.com
sudo bs scan -d discord.com --generate --parallel 4

# 3. Продолжить после обрыва (checkpoint/resume)
sudo bs scan -d discord.com --generate --resume
```

Больше примеров в [User Guide](docs/guide.md).

---

## Установка

**Linux с root** (нужен для netns + iptables). Python 3.10+.

```bash
git clone https://github.com/zhoel-sherk/blockcheckS.git
cd blockcheckS
pip install -e ".[dev,discovery]"
```

Почему **editable** (`-e`)? `configs/` и `presets/` лежат в корне репо —
plain wheel их не найдёт. Это осознанное решение (см. [ONB-7](docs/package.md)).

**nfqws2 / zapret2** — blockcheckS сам скачает официальный релиз
[bol-van/zapret2](https://github.com/bol-van/zapret2) при первом запуске в
`~/.local/share/blockcheckS/zapret2/`. Если nfqws2 уже стоит в `/opt/zapret2` —
использует его. Отключить авто-фетч: `--no-fetch-deps`.

**Блобы** (fake payloads) — в репо `blobs/` (без скачивания). Override:
`BLOCKCHECKS_BLOBS`. Опционально: `scripts/install_blobs.sh` для extras на хосте.
Flowseal-техники: `--tcp-sources flowseal` / `-M flowseal-fast`
([Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube);
howto: [docs/cookbook/blobs.md](docs/cookbook/blobs.md)).

Юнит-тесты запускаются **без root**:
```bash
pytest -m "not integration"
```

---

## CLI команды

| Команда | Что делает | Пример |
|---|---|---|
| `bs scan` | Асинхронный TCP-батч | `sudo bs scan -d discord.com --generate --parallel 4` |
| `bs pair` | TCP×UDP pair matrix | `sudo bs pair -d discord.com --generate --auto-discover 5` |
| `bs full` | Масс-скан + экспорт (долгий) | `sudo bs full --parallel 4 --max-timeh 2` |
| `bs tcp` | Одна TCP-стратегия (sync) | `sudo bs tcp -d discord.com -c configs/simple_fake__fake_ts.conf` |
| `bs udp` | Один UDP-конфиг (sync) | `sudo bs udp -c configs/udp_voice__fake_r6.conf` |
| `bs composite` | Композитный TCP+UDP конфиг | `sudo bs composite -c configs/composite_discord.conf` |
| `bs bench-settle` | Калибровка settle/curl таймаутов | `sudo bs bench-settle -d discord.com` |
| `bc-nfconf` | Экспорт nfqws2-конфигов из БД | `bc-nfconf --db state.db --out-dir output` |

Флаги, которые стоит знать: `--resume`, `--preset`, `-M`, `--generate`,
`--tcp-sources`, `--parallel`, `--max`, `--scan-level`, `--repeats`,
`--disable-ech`, `--max-timeh`. Bare `--generate` (без значения) =
`custom,configs`; явно: `--generate fake,configs`.

Подробный CLI reference: [docs/guide.md](docs/guide.md).

---

## Пресеты

Готовые списки доменов и стратегий из GP control-plane:

```bash
# Домены
bs scan --preset benchmark --generate        # 6 доменов для быстрой проверки
bs scan --preset discord --generate          # голый Discord (22 домена)
bs scan --preset google-youtube --generate   # YouTube CDN (23 домена)
bs scan --preset critical --generate         # критичные: YT + Discord + GV

# Стратегии
bs scan -d discord.com -M blockcheckS-best   # 9 проверенных стратегий
bs scan -d discord.com -M gp-verified        # 12 GP-подтверждённых
bs pair -d discord.com -M gp-voice           # голосовые UDP-стратегии
```

Посмотреть всё: `bs scan --list-presets`.  
Детали: [presets/README.md](presets/README.md).

---

## Документация

| Документ | О чём |
|---|---|
| [User Guide](docs/guide.md) | CLI reference, примеры, known limitations |
| [Architecture](docs/architecture.md) | Data flow, module map, voice discovery flow |
| [Package Layout](docs/package.md) | XDG-пути, деревья, import graph |
| [Database Schema](docs/database.md) | ER-диаграмма, SQL examples, checkpoint logic |
| [Glossary](docs/glossary.md) | Терминология: netns, NFQUEUE, pair matrix, ... |
| [Changelog](changelog.md) | История версий (1.0.0 → 1.0.2) |
| [Roadmap](docs/todo.md) | Бэклог: P1 (скорость), P2 (voice/GP), P3 (ML) |

Cookbook: [add checker](docs/cookbook/add-checker.md) ·
[add generator](docs/cookbook/add-generator.md) ·
[add CLI flag](docs/cookbook/add-cli-flag.md) ·
[GP bridge](docs/cookbook/gp-bridge.md).

---

## For contributors

- [CONTRIBUTING.md](CONTRIBUTING.md) — setup, тесты, PR flow, что коммитить а что нет
- [docs/architecture.md](docs/architecture.md) — data flow, module map
- [docs/cookbook/](docs/cookbook/) — как добавить checker / generator / CLI flag

Быстрый старт для разработчика:
```bash
pip install -e ".[dev,discovery]"
ruff check src tests    # линтер
pytest -m "not integration"   # юнит-тесты (без root)
```

---

## ⚖️ Legal Disclaimer / Дисклеймер

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
