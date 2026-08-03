# blockcheckS — lightspeed DPI strategy tester

Замена `blockcheck.sh` / blockcheckw: быстрый подбор DPI-стратегий для
zapret2/nfqws2 с репрезентативными проверками (curl_cffi JA4, netns,
TCP×UDP matrix, checkpoint/resume).

## Установка

Канон (ONB-7): **editable install из git checkout** — так `configs/` и `presets/`
резолвятся с корня репо. Plain wheel без checkout configs не находит.
Нужны host **nfqws2** (`/opt/zapret2`) и **blobs** (`/opt/zapret2/blobs/` или `scripts/install_blobs.sh`).

```bash
pip install -e ".[dev,discovery]"
# CLI:
bs --help
# или
python -m blockchecks.bs --help
```

Linux host с zapret2/nfqws2 и root (netns + iptables). Unit-тесты — без root.

## Отличия от blockcheck.sh

| blockcheck.sh | blockcheckS |
|--------------|-------------|
| ~60-120s на стратегию | ~3-5s на стратегию (parallel netns) |
| Curl/OpenSSL | curl_cffi / BoringSSL (браузерный JA4) |
| В основном TCP | TCP + UDP voice (STUN) |
| Последовательный shell | asyncio + NetNsPool |
| Легко «ложно-зелёный» | Контрактные pytest + content/DPI checks |

## Структура (v1.0)

```
src/blockchecks/   # пакет (bs, main, nfconf, engine/, checkers/)
configs/           # nfqws2 .conf (repo root)
presets/           # domains + strategies
tests/ docs/       # unit/integration + guide/todo/package
```

Подробный аудит: [docs/package.md](docs/package.md). Roadmap: [docs/todo.md](docs/todo.md).

## For contributors

- [CONTRIBUTING.md](CONTRIBUTING.md) — setup, tests, PR flow
- [docs/architecture.md](docs/architecture.md) — data flow and module map
- [docs/cookbook/](docs/cookbook/) — add checker / generator / CLI flag

Use **editable install** (`pip install -e .`) so `configs/` resolves from repo root.

## Быстрый старт

```bash
# TCP batch
sudo bs scan -d discord.com --generate --parallel 4

# TCP×UDP pair matrix
sudo bs pair -d discord.com --generate --auto-discover 5

# Mass strategy×coverage + keenetic/raw export (long run; use --resume)
sudo bs full
sudo bs full --parallel 4 --fan-out --max-timeh 2 \
  --domains-file presets/domains/benchmark.txt \
  --db logs/run.db --out-dir logs/export
bc-nfconf --db state.db --out-dir output

# BC2/GP-style curl repeats
sudo bs scan -d discord.com --generate --repeats 3 --repeats-mode stable

# Один .conf
sudo bs tcp -d discord.com -c configs/simple_fake__fake_ts.conf
sudo bs composite -c configs/composite_discord.conf

# Тесты (Windows/dev OK)
pytest -m "not integration"
```

Подробнее: [docs/guide.md](docs/guide.md). Архитектура: [docs/architecture.md](docs/architecture.md).
Roadmap: [docs/todo.md](docs/todo.md).

## Status

Пакет `blockchecks` 1.0.0: scan/pair/async, `bs full` + nfconf export, ruff clean.
Roadmap: [docs/todo.md](docs/todo.md). Layout: [docs/package.md](docs/package.md).

---

## ⚖️ Legal Disclaimer / Дисклеймер

### English
This software is provided "as is", without warranty of any kind, express or implied. **blockcheckS** is an open-source analytical tool designed strictly for educational, academic, and network research purposes. It is intended for network administrators and systems engineers to analyze Deep Packet Inspection (DPI) behaviors and diagnose network topologies.

*   The author(s) do not encourage, facilitate, or promote any illegal activities or violations of local telecommunication laws.
*   This software does not contain any malicious code, malware, or exploits designed to compromise computer security or bypass information protection systems (in compliance with Art. 273 of the Criminal Code of the Russian Federation).
*   The use of this tool is entirely **at your own risk**. The author(s) shall not be held liable for any direct, indirect, incidental, or consequential damages, service disruptions, or legal actions resulting from the use or misuse of this software.

### Русский
Данное программное обеспечение предоставляется по принципу «как есть» (as is). **blockcheckS** является аналитическим инструментом и распространяется исключительно в ознакомительных, научно-исследовательских и диагностических целях для системных инженеров и сетевых администраторов.

*   **Исключительно исследовательский характер**: Программа предназначена для изучения механизмов работы систем глубокого анализа пакетов (DPI) и не содержит вредоносного функционала, средств обхода систем защиты информации или вирусов (соответствует требованиям **Ст. 273 УК РФ**). Утилита оперирует стандартными сетевыми вызовами и легитимными механизмами ядра Linux.
*   **Соблюдение законодательства**: Автор(ы) не призывают к нарушению действующего законодательства Российской Федерации, включая Федеральный закон «О связи» № 126-ФЗ и Федеральный закон «Об информации, информационных технологиях и о защите информации» № 149-ФЗ.
*   **Отказ от ответственности**: Вы используете данное ПО **на свой страх и риск**. Автор(ы) не несут ответственности за любые ограничения связи, блокировки, штрафы, потерю данных или иные прямые или косвенные последствия, возникшие в результате работы или неправильной настройки данной утилиты.
