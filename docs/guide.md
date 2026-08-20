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
[custom_lua.md](custom_lua.md), [cookbook/](cookbook/).

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
| `bs serve` | резидентный probe server (Unix socket + HTTP) |
| `bs mcp` | MCP-сервер (stdio) для LLM, требует extra `[mcp]` |
| `bc-nfconf` | export keenetic+raw conf from existing `state.db` (с поддержкой `--ipset`) |

Примеры:

```bash
sudo bs scan -d discord.com --generate custom,configs --max 50 --parallel 4
# bare --generate still means custom,configs (CliApp preprocess):
sudo bs scan -d discord.com --generate --max 50 --parallel 4
sudo bs pair -d discord.com --generate --scan-level fast --auto-discover 5
sudo bs pair -d discord.com -c configs/alt__fake_fakedsplit_ts.conf -u configs/udp_voice__fake_r6.conf
sudo bs pair -d discord.com --resume   # откажется, если matrix fingerprint сменился

# Mass run (intentionally huge — GP-scale strategy×domain). Defaults = max.
# Default --tcp-sources includes flowseal (M8).
sudo bs full
sudo bs full --parallel 2 --resume
sudo bs full --max 500 --domains-file presets/domains/critical.txt

# Run profiles (--profile smoke|fast|20h) — predefined flag bundles:
sudo bs scan -d discord.com --profile smoke    # rapid 20-item smoke test
sudo bs scan -d discord.com --profile fast     # 100-item fast scan
sudo bs full --profile 20h                     # 20-hour mass campaign bundle

# Protective & intelligent features are ON by default (inverse flags to disable):
#   Adaptive queue: default ON (disable: --no-adaptive; --adaptive kept as inverse alias)
#   Preflight & triage: default ON (skip all: --no-preflight; prolog-only: --quick)
#   Encrypted Client Hello: default ON (disable: --no-ech; alias: --disable-ech)
#   Wssize fallback: default ON on scan/pair/full (disable: --no-wssize)
#   Secure DNS: default ON (disable: --no-secure-dns)

# Probe backend (default lua_bridge since 1.2.1a):
#   no flag  → lua_bridge (one nfqws2 per batch, /dev/shm IPC)
#   --classic / --probe-backend classic → legacy per-strategy restart
#   BLOCKCHECKS_PROBE_BACKEND=classic|lua_bridge → env override (scripts/CI)
sudo bs scan -d discord.com --generate --bridge-batch 500 --max 50
sudo bs scan -d discord.com --generate --classic --max 50           # legacy backend
sudo bs full -d discord.com --max 100 --tcp-only --no-http --no-quic --no-voice
# Fan-out waves always use classic per-strategy nfqws2 (WARN once under bridge).
sudo bs scan -d discord.com --generate --lua-bridge-compare --max 20  # A/B drift log
bc-nfconf --db state.db --limit 3 --out-dir output

# Voice UDP smoke (sudo + nfqws2 + discord_udp blob):
./scripts/voice_smoke.sh
```

### Run profiles (`--profile`)

Profiles apply a predefined bundle of flags via `cli/profiles.py` (after argparse,
before command dispatch). Granular flags still override profile values.

| Profile | Key settings |
|---------|----------------|
| `smoke` | `max=20`, `scan_level=fast`, `parallel=1`, `curl_parallel=1`, `timeout=2.0`, `quick=True` |
| `fast` | `max=100`, `scan_level=fast`, `timeout=3.0` |
| `20h` | `scan_level=full`, `resume=True`, `no_preflight=True`, `no_wssize=True`, `timeout=2.0`, `allow_dns_hijack=True`, `fan_out=True` |

The `20h` profile matches the long-term series A→F baseline; see
[long_term_runs.md](long_term_runs.md).

### Defaults & inverse flags (1.3.7)

Campaign commands (`scan`, `pair`, `full`) share a unified parser via
`add_campaign_args()` — flag names and defaults are synchronized across all three.

| Feature | Default | Disable / shortcut |
|---------|---------|-------------------|
| Adaptive queue (AQ) | ON | `--no-adaptive` |
| Preflight (full) | ON | `--no-preflight` (skip all) or `--quick` (prolog only) |
| ECH (Encrypted Client Hello) | ON | `--no-ech` (`--disable-ech` alias) |
| Wssize TLS 1.2 fallback | ON | `--no-wssize` |
| Secure DNS (DoH) | ON | `--no-secure-dns` |

Fine-grained preflight skips (`--skip-baseline`, `--skip-ip-block`,
`--skip-port-block`, `--skip-prolog`, `--skip-dns-audit`) remain for scripts and
partial control; `--no-preflight` and `--quick` cover the common cases.

`--adaptive` is kept as an inverse alias (sets `no_adaptive=False`); AQ is already
ON by default — explicit `--adaptive` is only needed to cancel a prior
`--no-adaptive` on the same command line.

## UDP vs Discord-UDP

Три разных контура — не смешивать с HTTPS `curl` на `discord.com`:

| Команда | Что тестирует |
|---|---|
| `bs udp -c configs/udp_voice__*.conf` | Только voice UDP (хост, без netns). STUN + IP Discovery. |
| `bs pair --generate` | TCP curl × UDP voice. Дефолт `--udp-sources custom,standard_udp`. |
| `bs full` | То же UDP-пул в конце прогона (`custom,standard_udp`). |

Цель Discord-voice: `finland*.discord.gg` → GCP `35.217.*` UDP `50000–50100` (листы Maks-gaming). Проба — RFC5389 STUN, затем Discord IP Discovery 74B. `finland*.discord.media` — это TLS voice WS (Cloudflare), не этот пул.

`udp_quic` / `udp_multiblob` живут в фазе HTTP/3 (`standard_quic`). Игровой UDP: `--udp-sources game` (`standard_udp_game`), не в Discord-дефолте.

`bs udp` на хосте и `bs pair` в netns — разные стеки (один nfqws2 vs TCP q200 + UDP q201 coexist). PASS на хосте не гарантирует PASS в паре.

```bash
sudo bs udp -c configs/udp_voice__fake_r6.conf --discover-dns 2
sudo bs pair -d discord.com --generate --udp-sources custom,standard_udp \
  --ip 35.217.48.152 --port 50004 --udp-bypass --max 1
```

## Память / мониторинг

Default `--parallel` comes from `BLOCKCHECKS_POOL` / `DEFAULT_POOL_SIZE` (usually 4).
On hosts with `MemAvailable < ~1.5 GiB` the CLI default is soft-capped to **1**
(override with an explicit `--parallel`).

### Raspberry Pi 2 (ARMv7)

Must use a **prebuilt `linux-arm`** nfqws2 (not x86_64 / not arm64). Suggested:

```bash
sudo bs scan --preset pi2 -M timeout-benchmark \
  --parallel 1 --curl-parallel 1 --scan-level fast --max 20 --no-fetch-deps
```

Transfer checklist: `nfqws2` + `lua/` + `blobs/` (`rsync --copy-links`); install
`curl_cffi` **on the Pi** (armv7l wheels). `system_deps` refuses wrong-arch ELF.

**Memory monitor / daemon recycle** (`service/metrics.py`, lua_bridge
backend only): samples nfqws2 RSS inside each netns and recycles the daemon
(when RSS or leak-slope is exceeded). On a **RPi2** with ~256 MiB free RAM,
lower the ceiling below the default:

```bash
export BLOCKCHECKS_MEM_MAX_MIB=256    # RSS ceiling for an nfqws2 daemon (MiB); recycle when exceeded
export BLOCKCHECKS_MEM_LEAK_SLOPE=8   # leak slope (MiB/s) over the window; recycle when exceeded
export BLOCKCHECKS_MEM_PY_MAX_MIB=2048 # Python worker RSS ceiling (MiB); warn only
export BLOCKCHECKS_MEM_WINDOW=12      # sliding-window size (samples)
export BLOCKCHECKS_MEM_POLL=2.0       # poll interval (s) between checks
export BLOCKCHECKS_MEM_MONITOR=1      # 0 disables sampling/recycle entirely
```

Defaults: `MAX_MIB=512`, `LEAK_SLOPE=8`, `PY_MAX_MIB=2048`, `WINDOW=12`,
`POLL=2.0`, `MONITOR=1`.

Scale note: more workers = more netns×nfqws2 (already isolated). Raising
`--parallel` on a Xeon is the first throughput lever; nftables vmap (B7) is for
host-shared designs, not a prerequisite for `parallel > 4` under netns.

`bs full` / `bc-nfconf` write two confs plus a bundle (`user.list`, custom `blobs/` / `lua/`):

- **keenetic** (`nfqws2_<ts>.conf`) — for the router. Working paths only
  `/opt/etc/nfqws2/{blobs,lua,lists}`; host abs paths only in `# COPY …`.
- **raw** (`nfqws2_raw_<ts>.conf`) — for **dpi-tester** (`--config`): flat
  `nfqws2 @file` with `--lua-init=@/opt/zapret2/lua/…` and host blob paths.
  Do not feed the keenetic/shell file to dpi-tester.

`--filter-l7` selects the **flow** protocol (`tls`/`http`/`quic`); `--payload`
selects the **packet** type and stays in effect until the next `--payload=`.

ETA printed as `N_strat × N_domains / parallel`. Resume skips
`(strategy, domain)` already in DB. STUN discover concurrency is capped at 4.

**Экспорт с фильтрацией по IP (`bc-nfconf --ipset`)**: если роутер не
перехватывает DNS, можно добавить IP-фильтр из кэша. Флаг `--ipset` возьмёт IPs
из `data_block` DNS-кэша. Малые наборы будут встроены как `--ipset-ip ip1,ip2`,
большие — `# COPY ipset:` + `--ipset=@/opt/etc/nfqws2/lists/user.ipset` (файл
кладётся в бандл `lists/user.ipset`). Если доступна утилита `ip2net`, адреса
схлопнутся в CIDR.

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
Blobs (add/bake): [cookbook/blobs.md](cookbook/blobs.md).

## Тесты

```bash
pip install -e ".[dev]"
pytest -m "not integration"    # Windows/Linux без root
sudo pytest -m integration     # Linux + nfqws2
```

Конфиг pytest — в `pyproject.toml` (`addopts = -m "not integration and not quality and not mutation"`).

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

1. `bs scan` сейчас принудительно ставит `auto_discover=None` — флаг на scan
   бесполезен, пока это не уберут (см. [architecture.md](architecture.md)).
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
- Увеличь таймаут: `--timeout 20` (дефолт 3).
- Проверь iptables: `sudo iptables -L OUTPUT -n | grep NFQUEUE`.
- Для googlevideo.com: это известная проблема — IP `142.251.x.x` блокируется на уровне IP (не SNI).
- **`send:repeats=6`** на DPI с нормализацией L4-checksum (Fryazino / Fiord) даёт SSL error 35.
  Preflight-грид из 5 ячеек её не меряет; в матрице `send:{fool}:repeats=N` остаётся
  только у geneva (`tamper._fam_geneva_fool`, repeats 1–2). ISP-blacklist —
  `[dead].foolings` в `data_block/providers/<slug>/triage.toml`.

**Детерминированный GGC-тест (обман ТСПУ, без 6h TTL)**
- Подписанные `*.googlevideo.com` URL живут ровно 6 часов (`expire=21600`). Для
  стабильных массовых прогонов можно не зависеть от yt-dlp и подписи:
  `BLOCKCHECKS_GV_GGC=1 bs tcp -d googlevideo.com ...`
- **Авто-fallback**: любой googlevideo-домен в списках тестирования
  автоматически проверяется через GGC (env `BLOCKCHECKS_GV_GGC` ставится при
  загрузке доменов). `BLOCKCHECKS_GV_GGC=0` — вернуть подписанный yt-dlp путь.
- Техника: берём IP живого Google-кэша (GGC, напр. `74.125.108.234`), шлём
  запрос на него, но в SNI подставляем `rr*.googlevideo.com` и принудительно
  ставим `Range: bytes=0-1048575` (1MiB) — ТСПУ включает эвристику «скачивания
  видео».
- **Отличие пробоя от блока** (детектор): настоящий Google CDN отвечает с
  уникальным заголовком `Server: gws | scone | gvs 1.0`; заглушка ТСПУ пишет
  `Server: nginx | nts` или не присылает его. При 302/307 проверяется
  `Location` — должен оставаться внутри `*.googlevideo.com`/`*.google.com`,
  иначе это региональный редирект ТСПУ.
- Настройки: `BLOCKCHECKS_GGC_HOST`, `BLOCKCHECKS_GGC_IP`,
  `BLOCKCHECKS_GV_GGC` (вкл/выкл), `BLOCKCHECKS_PROXY` (обход прямого egress).
- Детали: `prepare_ggc_probe()` / `_ggc_redirect_is_google()` в
  `src/blockchecks/checkers/curl_probe.py`.

**QUIC / HTTP-3 блокировка — механизм (исследовано 2026-08)**
- **QUIC как протокол НЕ заблокирован** на LLC Fiord: `check_http3('cloudflare.com')`
  → HTTP 301 (работает), низкоуровневый QUIC Initial к Cloudflare IP отвечает
  (1200B), до `vk.com` / голого `googlevideo.com` QUIC доходит.
- **Блокировка по SNI, не по IP**: тот же Google IP `74.125.108.234` (rr-диапазон)
  пропускает `cloudflare.com` / `cdn.example.com` / голый `googlevideo.com`
  (доходят до CDN → SSL-ошибка сертификата), но **дропает** `youtube.com`,
  `www.youtube.com`, `rr*.googlevideo.com` (timeout) на **любом** IP.
- ТСПУ анализирует SNI внутри первого UDP-пакета (QUIC Initial), поэтому
  применяет разные правила к разным сайтам в рамках одного протокола —
  «белый» SNI пролетает, заблокированный — весь UDP-поток сессии дропается.
- Следствие: **GGC-подход для QUIC бесполезен** (дроп не по IP), а подмена
  SNI на белый домен не даёт CDN-контента. Для обхода нужен SNI-маскинг или
  туннель (sing-box), не подмена IP.

**QUIC fallback при дропе (переключение механизма)**
- При постоянном FAIL (timeout = дроп ТСПУ) базовой QUIC-стратегии
  `test_quic` автоматически пробует fallback-цепочку: базовая
  `fake:blob=X` → `+badsum` → `+ip_ttl=1`. Отключается `BLOCKCHECKS_QUIC_FALLBACK=0`.
- Диагностика 2026-08: **fake-инъекции пробивают ТСПУ** для QUIC (QUIC Initial
  доходит до CDN — ошибка `ngtcp2_conn_writev_*`/`SSL cert`, НЕ timeout), тогда
  как `send:ipfrag` (split/disorder) дропается (timeout). `_is_quic_dropped()`
  отличает дроп от «дошёл до CDN».
- Детали: `_quic_fallback_variants()` / `_is_quic_dropped()` в
  `src/blockchecks/engine/async_runner.py`.

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
