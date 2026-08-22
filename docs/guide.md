# Guide — blockcheckS

Перебор стратегий **nfqws2 / zapret2**: какие реально открывают сайты у твоего
провайдера. Пробы в network namespace, результат в SQLite, экспорт в конфиг
роутера.

Нужны **Linux и root**. Юнит-тесты — без sudo.

---

## Оглавление

1. [Быстрый старт](#быстрый-старт) — команда для 99% случаев
2. [Установка](#установка)
3. [Команды](#команды)
4. [Пресеты](#пресеты)
5. [Профили](#профили)
6. [Что включено по умолчанию](#что-включено-по-умолчанию)
7. [Бэкенд пробы](#бэкенд-пробы)
8. [Голос Discord (UDP)](#голос-discord-udp)
9. [Экспорт конфига](#экспорт-конфига)
10. [Повторы curl](#повторы-curl)
11. [Память и Raspberry Pi](#память-и-raspberry-pi)
12. [Логи и debug](#логи-и-debug)
13. [Проблемы](#проблемы)
14. [Для разработчиков](#для-разработчиков)
15. [Ограничения](#ограничения)

Архитектура: [architecture.md](architecture.md). Серии A→F на сутки:
[long_term_runs.md](long_term_runs.md).

---

## Быстрый старт

Для почти всех, кто хочет **YouTube + Discord + несколько соседних сервисов**
(Google API, googlevideo, Signal, ECH-проверка):

```bash
sudo bs full --preset coverage-tcp --resume --parallel 4
```

Что это делает:

- **14 доменов** из [`presets/domains/coverage-tcp.txt`](../presets/domains/coverage-tcp.txt):
  `youtube.com`, `googlevideo.com`, `discord.com` / CDN, `signal.org`, …
- генерирует TCP-матрицу (standard + custom + configs + flowseal), затем HTTP,
  QUIC и голос Discord, если их не выключили;
- adaptive queue и preflight **включены**;
- `--resume` — после обрыва продолжит с той же БД;
- `--parallel 4` — типичный десктоп/Xeon (на Pi2 оставь 1).

Прогон **часы**, не минуты. Оборвался — та же команда ещё раз. Когда закончится:

```bash
bc-nfconf --db ~/.local/state/blockcheckS/state.db --out-dir ~/nfqws2-export
```

Keenetic: скопируй `nfqws2_*.conf` → `/opt/etc/nfqws2/nfqws2.conf`.

Перед длинным прогоном имеет смысл 5-минутная проверка, что nfqws2 и sudo живы:

```bash
sudo bs scan --preset benchmark --profile smoke --generate
```

Не путать с `--profile 20h`: это пакет для исследовательских серий A→F
(полный scan-level, без preflight). Для домашнего «найти рабочий обход» он не нужен.

---

## Установка

```bash
git clone https://github.com/zhoel-sherk/blockcheckS.git
cd blockcheckS
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,discovery]"
```

Или `pip install blockchecks` (wheel с 1.2.1a самодостаточен: configs/blobs/lua/presets).

**На хосте для живого прогона:** Linux, passwordless sudo (`sudo -n`), nfqws2.
Бинарник по умолчанию `/opt/zapret2/nfq2/nfqws2`. Если его нет — скачается
[bol-van/zapret2](https://github.com/bol-van/zapret2) в
`~/.local/share/blockcheckS/zapret2/`. Отключить: `--no-fetch-deps`.

Переменные: `BLOCKCHECKS_NFQWS2`, `BLOCKCHECKS_BLOBS`, `BLOCKCHECKS_SETTINGS`,
`BLOCKCHECKS_PROXY`. Шаблон: [`settings.example.env`](../settings.example.env).

Raspberry Pi 2: [install-rpi.md](install-rpi.md) и раздел [Память](#память-и-raspberry-pi).

---

## Команды

| Команда | Когда | Пример |
|---|---|---|
| `bs full` | основной прогон: матрица × домены + голос/QUIC + экспорт | см. [быстрый старт](#быстрый-старт) |
| `bs scan` | только TCP, без голоса | `sudo bs scan --preset discord --generate --parallel 4` |
| `bs pair` | TCP + UDP-голос | `sudo bs pair -d discord.com --generate --discover-dns 5` |
| `bs tcp` / `bs udp` | одна готовая стратегия / `.conf` | `sudo bs tcp -d youtube.com -c configs/simple_fake__fake_ts.conf` |
| `bs preflight` | только диагноз DPI, без перебора | `sudo bs preflight --preset discord` |
| `bs composite` | один составной `.conf` на пачку доменов | `sudo bs composite -c configs/composite_discord.conf` |
| `bs bench-settle` | подобрать settle/curl таймауты | `sudo bs bench-settle -d discord.com` |
| `bs serve` | демон для повторных проб | `sudo bs serve --pool 2` |
| `bs mcp` | мост для Cursor/Claude (`pip install 'blockchecks[mcp]'`) | `bs-mcp` |
| `bs stop` | снять `run.lock` | `bs stop --force` |
| `bs data-block` | снимок XDG-провайдера в git `data_block/` | `bs data-block --out ./data_block --git` |
| `bc-nfconf` | конфиг роутера из уже готовой БД | `bc-nfconf --db state.db --out-dir out` |

`bs scan` — TCP-only обёртка над `pair`: UDP и `--auto-discover` на scan
сбрасываются **намеренно**. Голос — `pair` или `full`.

Список пресетов: `bs scan --list-presets`. Справка команды: `bs full -h`.

---

## Пресеты

### Домены (`--preset`)

| Пресет | Доменов | Зачем |
|---|---:|---|
| `coverage-tcp` | 14 | **дефолт `bs full`**: YouTube + Discord + Signal/ECH |
| `critical` | 4 | youtube, discord, discordcdn, signal — самый короткий «боевой» набор |
| `benchmark` | 6 | дымовой прогон |
| `discord` / `google-youtube` | ~22 / ~23 | один сервис целиком |
| `coverage` | ~40 | полный GP-список (тяжелее; часть доменов в denylist) |
| `pi2` | 3 | мало RAM |

```bash
sudo bs full --preset coverage-tcp --resume --parallel 4
sudo bs scan --preset discord --generate
```

`denylist.txt` — фильтр, не пресет. Каталог: [presets/README.md](../presets/README.md).

CIDR-классификаторы (`presets/ipset/`: sinkhole, CDN-семьи, fallbacks) — **не**
то же самое, что `bc-nfconf --ipset` (фильтр nfqws2 из DNS-кэша). Overlay:
`~/.config/blockcheckS/presets/ipset/`. Живые пины auto-pin пишутся в
`~/.local/share/blockcheckS/data_block/providers/<slug>/hosts`.

### Стратегии (`-M`)

Это списки `--lua-desync` строк, не готовые `.conf`. Конфиги nfqws2 — в
[`configs/`](../configs/README.md), флаг `-c`.

```bash
sudo bs scan -d discord.com -M blockcheckS-best
sudo bs scan -d discord.com -M gp-verified
sudo bs pair -d discord.com -M gp-voice --discover-dns 2
```

Полный Flowseal-перебор: `--tcp-sources flowseal` (у `bs full` flowseal уже
в дефолтных источниках).

---

## Профили

Готовый пакет флагов. То, что указано вручную, побеждает профиль.

| Профиль | Что внутри | Кому |
|---|---|---|
| `smoke` | max 20, scan-level fast, parallel 1, timeout 2, `--quick` | проверить, что стек жив |
| `fast` | max 100, scan-level fast, timeout 3 | укороченный скан |
| `20h` | scan-level full, resume, `--no-preflight`, `--no-wssize`, fan-out, `--allow-dns-hijack` | серии A→F, не домашний первый запуск |

```bash
sudo bs scan --preset benchmark --profile smoke --generate
sudo bs full --preset coverage-tcp --profile 20h   # только если нужна 20-часовая серия
```

---

## Что включено по умолчанию

Кампании `scan` / `pair` / `full` делят парсер (`add_campaign_args`). Полезное
**включено**; выключать явно `--no-*`.

| Фича | Дефолт | Выключить |
|---|---|---|
| Adaptive queue | ON | `--no-adaptive` |
| Preflight | ON | `--no-preflight` (всё) или `--quick` (только prolog) |
| ECH | ON | `--no-ech` |
| Wssize (TLS 1.2) | ON | `--no-wssize` |
| DoH + auto-pin | ON | `--no-secure-dns` / `--no-auto-pin` |
| Голос / QUIC / HTTP в `full` | ON | `--no-voice` / `--no-quic` / `--no-http` / `--tcp-only` |
| `--dpi-diag` | OFF | включить флагом (SNI WL, FAT, l4-25; **не** ставит `dns_sinkhole`) |

Точечные `--skip-baseline`, `--skip-ip-block`, `--skip-port-block`,
`--skip-prolog`, `--skip-dns-audit` — для скриптов. `--adaptive` оставлен как
алиас «AQ on» (нужен, только чтобы отменить `--no-adaptive` в той же строке).

`--dpi-diag` пишет `[dpi_diag]` и `viable.hosts` в triage. Без флага старые
`viable.hosts` в генераторы не подмешиваются.

---

## Бэкенд пробы

Дефолт с 1.3.1 — **lua_bridge**: один nfqws2 на батч, стратегия выбирается через
`/dev/shm`. Старый путь (рестарт демона на каждую стратегию): `--classic`.

```bash
sudo bs scan -d discord.com --generate --max 50          # lua_bridge
sudo bs scan -d discord.com --generate --classic --max 50
```

Приоритет: `--classic` > `--probe-backend` > `--lua-bridge` >
`BLOCKCHECKS_PROBE_BACKEND`. Fan-out волны всегда classic. Сравнение обоих:
`--lua-bridge-compare` (для `dev/release_smoke.sh`, не для ежедневного скана).

Как это устроено: [architecture.md](architecture.md), Lua IPC:
[custom_lua.md](custom_lua.md).

---

## Голос Discord (UDP)

Не путать с HTTPS `curl` на `discord.com`. Три контура:

| Команда | Что проверяет |
|---|---|
| `bs udp -c configs/udp_voice__*.conf` | только UDP на **хосте** (STUN + IP Discovery) |
| `bs pair --generate` | TCP в netns × UDP voice (q200 + q201) |
| `bs full` | то же UDP-пул в конце (`custom,standard_udp`) |

Цель: `finland*.discord.gg` → GCP `35.217.*` UDP `50000–50100`.
`finland*.discord.media` — TLS voice WS (Cloudflare), не этот пул.

Дискавери **взаимоисключающе**:

```bash
# без VPN: DNS finland* + STUN (bootstrap nfqws2 q201 по умолчанию)
sudo bs pair -d discord.com --generate --discover-dns 5

# через SOCKS5 (BLOCKCHECKS_PROXY): Gateway WS → Voice WS
sudo bs pair -d discord.com --generate --auto-discover 5
```

Не комбинировать `--discover-dns` и `--auto-discover`. В матрицу идёт **первый**
живой endpoint. PASS на хосте (`bs udp`) не гарантирует PASS в `pair`.

Игровой UDP: `--udp-sources game`. Smoke: `./dev/voice_smoke.sh`.

```bash
sudo bs udp -c configs/udp_voice__fake_r6.conf --discover-dns 2
sudo bs pair -d discord.com --generate --udp-sources custom,standard_udp \
  --ip 35.217.48.152 --port 50004 --udp-bypass --max 1
```

---

## Экспорт конфига

`bs full` и `bc-nfconf` пишут два файла плюс бандл (`user.list`, blobs, lua):

| Файл | Куда |
|---|---|
| `nfqws2_<ts>.conf` (keenetic) | роутер: пути только `/opt/etc/nfqws2/…` |
| `nfqws2_raw_<ts>.conf` | хостовый dpi-tester (`nfqws2 @file`). **Не** на Keenetic |

```bash
bc-nfconf --db ~/.local/state/blockcheckS/state.db --out-dir ~/nfqws2-export
bc-nfconf --db state.db --out-dir out --ipset    # + IP-фильтр из DNS-кэша
```

`--ipset`: мало адресов → `--ipset-ip` inline; много → `lists/user.ipset`.
Если есть `ip2net`, схлопнет в CIDR. `--filter-l7` = протокол потока;
`--payload` липкий до следующего `--payload=`. Не путать с каталогом
`presets/ipset/*.txt` (классификация DNS/CDN).

После прогона pip-пользователь собирает git-снимок провайдера так:

```bash
git clone https://github.com/zhoel-sherk/data_block.git
bs data-block --out ./data_block --git
```

`--data-block-sync` на `full`/`scan` делает тот же export+commit, если рядом
есть `data_block/.git`; иначе warning, скан не падает.

Подробности путей: [configs/README.md](../configs/README.md).

---

## Повторы curl

Совместимость с blockcheck2 / GP. Это **не** `--curl-parallel` (тот — несколько
доменов в одном батче).

| Флаг | Смысл |
|---|---|
| `--repeats N` | N попыток на пару стратегия×домен (1–10) |
| `--parallel-repeats` | эти N параллельно |
| `--repeats-mode fast\|stable` | `fast` — стоп на первом PASS; `stable` — все N |
| `--curl-parallel N` | fan-out по доменам (B2) |

GP: [cookbook/gp-bridge.md](cookbook/gp-bridge.md). Блобы:
[cookbook/blobs.md](cookbook/blobs.md).

---

## Память и Raspberry Pi

Дефолт `--parallel` = `BLOCKCHECKS_POOL` / размер пула (обычно 4). Если
`MemAvailable < ~1.5 GiB`, CLI сам ставит **1** (явный `--parallel` побеждает).

На Pi2 — **linux-arm** nfqws2, не x86/arm64:

```bash
sudo bs scan --preset pi2 -M timeout-benchmark \
  --parallel 1 --curl-parallel 1 --scan-level fast --max 20 --no-fetch-deps
```

Монитор RSS lua_bridge (`service/metrics.py`) перезапускает демон при утечке.
На ~256 MiB свободной RAM:

```bash
export BLOCKCHECKS_MEM_MAX_MIB=256
export BLOCKCHECKS_MEM_LEAK_SLOPE=8
export BLOCKCHECKS_MEM_PY_MAX_MIB=2048
export BLOCKCHECKS_MEM_MONITOR=1
```

Дефолты: MAX 512, slope 8, PY 2048, window 12, poll 2s. `MONITOR=0` выключает.

Больше воркеров = больше netns×nfqws2. На Xeon сначала поднимай `--parallel`,
не nftables vmap.

---

## Логи и debug

Логгер `blockchecks` (stdlib). INFO — stdout, WARNING/ERROR — stderr.
Файл: `~/.local/state/blockcheckS/logs/blockchecks.log` (10 MiB × 3).
`bs mcp` пишет консоль в **stderr**, stdout оставлен JSON-RPC.

| Как | Что |
|---|---|
| `--debug` | Python DEBUG + `BLOCKCHECKS_NFQWS2_DEBUG=1` |
| `--nfqws2-debug [1\|syslog\|@path]` | только nfqws2 |
| `BLOCKCHECKS_LOG_LEVEL=DEBUG` | уровень при старте |
| SIGUSR1 кампании / `bs serve` | toggle; nfqws2 подхватит на **следующем** probe |
| MCP `set_debug_mode` / `POST /api/set-debug` | то же через демон |

```bash
curl -H "Authorization: Bearer $TOKEN" \
  'http://127.0.0.1:8089/api/logs?source=python&tail=200'
```

`source`: `python` | `campaign` | `nfqws2`. После ротации `truncated: true`.

---

## Проблемы

### nfqws2 not found

Проверь `/opt/zapret2/nfq2/nfqws2` или убери `--no-fetch-deps`.
`export BLOCKCHECKS_NFQWS2=/path/to/nfqws2` либо `[tools] nfqws2` в
`~/.config/blockcheckS/config.toml`.

### sudo просит пароль

Нужен `sudo -n`. В `/etc/sudoers.d/blockchecks`:
`username ALL=(ALL) NOPASSWD: ALL`. Юнит-тесты sudo не требуют.

### `ERROR: no TCP strategies generated`

Preflight решил, что домен **непроходим на L3** (`unbypassable_l3`) и выкинул
все стратегии. На SNI silent-drop это ложный IP-block, если кросс-тест не
узнал CDN-префикс (YouTube/Google, Discord). Повтори с `--skip-ip-block` или
`--quick`. UDP≠DoH в audit — warning; `--allow-dns-hijack` нужен только при
sinkhole/bogon.

### Все стратегии FAIL / timeout / parse

- `bs tcp --debug …` или `BLOCKCHECKS_NFQWS2_DEBUG=1`; на лету `kill -USR1 <pid>`.
- `--timeout 20` (дефолт 3).
- `sudo iptables -L OUTPUT -n | grep NFQUEUE`.
- googlevideo: часть IP режется на L3, не по SNI — см. GGC ниже.
- `send:repeats=6` на DPI с нормализацией checksum (Fiord) → SSL 35. В матрице
  `send` остаётся у geneva (repeats 1–2). Чёрный список ISP:
  `[dead].foolings` в `data_block/providers/<slug>/triage.toml`.

### googlevideo: GGC вместо yt-dlp

Подписанные `videoplayback` живут 6 часов. Для стабильных прогонов:

```bash
BLOCKCHECKS_GV_GGC=1 sudo bs tcp -d googlevideo.com ...
```

Если в списке доменов есть googlevideo, GGC включается **сам**
(`BLOCKCHECKS_GV_GGC=0` вернёт yt-dlp). Идея: живой Google-кэш + SNI
`rr*.googlevideo.com` + `Range: bytes=0-1048575`. Настоящий CDN:
`Server: gws|scone|gvs`; заглушка ТСПУ: `nginx|nts`. Редирект должен остаться
на `*.googlevideo.com` / `*.google.com`.

Переменные: `BLOCKCHECKS_GGC_HOST`, `BLOCKCHECKS_GGC_IP`, `BLOCKCHECKS_PROXY`.
Код: `prepare_ggc_probe()` в `checkers/curl_probe.py`.

### QUIC / HTTP/3

На LLC Fiord QUIC как протокол **не** закрыт (Cloudflare проходит). Режется
**SNI** в QUIC Initial: `youtube.com` / `rr*.googlevideo.com` — drop на любом IP.
GGC для QUIC бесполезен. Fallback цепочка `test_quic`: `fake` → `+badsum` →
`+ip_ttl=1` (`BLOCKCHECKS_QUIC_FALLBACK=0` выключает). Отличие drop vs «дошёл до
CDN»: `_is_quic_dropped()` в `async_runner.py`.

### STUN всегда timeout

GCP Discord отвечает на STUN при живой Voice WS. Без `--full-voice` таймаут —
ожидаемо.

### Database is locked

`bs full` ставит `busy_timeout=5000`. Параллельный ручной доступ — разные копии БД.

### netns: Operation not permitted

`sudo modprobe veth` и `sysctl net.ipv4.ip_forward=1`.

---

## Для разработчиков

```bash
pip install -e ".[dev,discovery]"
ruff check src tests
pytest -m "not integration"     # без root
bash dev/gate_all.sh            # unit + quality + ruff + vulture
sudo pytest -m integration -q   # Linux + nfqws2
```

Маркеры pytest: `addopts = -m "not integration and not quality and not mutation"`.

| Путь | Роль |
|---|---|
| `src/blockchecks/` | код |
| `configs/` | готовые `.conf` |
| `scripts/` | кампании A→F, systemd, blobs |
| `dev/` | смоки и гейты |
| `docs/` | этот гайд и остальное |

PR: [CONTRIBUTING.md](../CONTRIBUTING.md). Устройство прогона:
[architecture.md](architecture.md), дерево: [package.md](package.md).

---

## Ограничения

1. `bs scan` не тестирует голос (`auto_discover` сбрасывается).
2. Discover/pair использует только `eps[0]`.
3. `stderr=PIPE` у nfqws2 без drain — риск заполнения pipe на болтливом `--debug`.
4. Не коммитить `state.db` и `*.egg-info`.
5. Windows: только юнит-тесты; CLI больше не падает на `×` в cp1251.
