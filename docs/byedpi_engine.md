# ByeDPI Engine — план интеграции в blockcheckS

> **Версия плана:** 2.0 (пересмотр 2026-08-11, по итогам глубокого изучения upstream)
> **Бинарник:** `ciadpi` (byedpi) — upstream [hufrea/byedpi](https://github.com/hufrea/byedpi) (MIT)
> **Код изучен:** `/tmp/opencode/byedpi_src` (main.c, proxy.c, params.h, README) + ByeByeDPI каталог
> **Статус:** Phase 1–1b реализованы (translator + matrix generator); Phases 2–6 — план

---

## Оглавление

1. [Мотивация и роль движка](#1-мотивация)
2. [Архитектурное решение](#2-архитектура)
3. [Изучение upstream: жизненный цикл ciadpi](#3-upstream)
4. [Модули интеграции](#4-модули)
   - 4.1 `byedpi_translator.py` — ядро перевода (✅ реализовано)
   - 4.2 `byedpi_matrix_generator.py` — отдельный пул стратегий (✅ реализовано)
   - 4.3 `ByedpiManager` — оркестрация процессов (план)
   - 4.4 `curl_probe.py` — proxy-поле (план)
   - 4.5 store: `byedpi_results` + `log_byedpi` (план)
   - 4.6 CLI: `--engine`, `--byedpi-bin` (план)
   - 4.7 `system_deps.py` — скачивание бинарника (план)
5. [Маппинг стратегий nfqws2 → byedpi](#5-маппинг)
6. [XDG / DAO / бинарники](#6-xdg)
7. [Roadmap](#7-roadmap)
8. [Ограничения byedpi](#8-ограничения)
9. [ByeByeDPI catalog (future)](#9-catalog)
10. [Критерии приёмки](#10-критерии)

---

## 1. Мотивация

| | nfqws2 (текущий) | byedpi (ciadpi) |
|---|---|---|
| Механизм | NFQUEUE, ядро (root, netns, iptables) | userspace SOCKS5-прокси |
| Root | Да (netns + settle ~3s/стратегия) | Нет |
| Старт процесса | ~3s (netns + settle) | ~50ms |
| Per-strategy total | 3–8s | 0.5–3s |
| 100 стратегий | ~80s | ~20s |
| Custom blobs | `--blob=NAME:@path` | `-l @file` |
| Multi-strategy | restart / `--new` | `--auto` groups (1 процесс) |

Проверено бенчмарком (2026-08-11): selection-speed **1.52× / 1.62×** (nfqws2/byedpi) на 5-стратегичном TCP-наборе. byedpi — быстрый **prescreen**, nfqws2 — ground-truth.

**Роль движка:** byedpi — **альтернативный движок** (`--engine byedpi`), не замена. Он изолирован от основной netns-машинерии, но делит DB/matrix/CLI. UDP/QUIC/voice остаются на nfqws2 (byedpi их не покрывает).

---

## 2. Архитектура

**Принцип: полная изоляция исполнения, общий каркас данных.**

```
src/blockchecks/engine/
├── byedpi_translator.py        ← ЧИСТЫЙ перевод nfqws2→ciadpi argv (нет IO/netns)
├── byedpi_matrix_generator.py  ← пул стратегий byedpi (native + translated)
├── byedpi_manager.py           ← [план] ByedpiManager: процесс ciadpi/стратегия
├── matrix_generator.py         ← REGISTRY["byedpi"] = ByedpiMatrixGenerator
├── async_runner.py             ← [план] ветка engine=="byedpi" в test_tcp
└── checkers/curl_probe.py      ← [план] CurlProbeRequest.proxy
```

**Почему отдельный модуль перевода, а не правка существующего кода:**

- `byedpi_translator` не импортирует `async_runner`, `in_ns_workers`, `nfqws_config` — тестируется изолированно, переиспользуется любым фронтендом.
- `byedpi_matrix_generator` — **отдельный source**, а не новая семья в `StandardGenerator`: у byedpi свои native one-liners (`-o`, `-q`, `-n`, `-M`), которых нет в nfqws2. Полный пул покрывает **только** переводимый срез стратегий.
- MatrixGenerator.REGISTRY уже поддерживает `--generate byedpi` — CLI не меняется.

**Исполнение одной стратегии (target):**

```
bs scan --engine byedpi --generate byedpi
  → ByedpiMatrixGenerator.generate() → StrategyItem(strategy="ciadpi argv")
  → ByedpiManager.from_argv(argv).start() → ciadpi -p PORT -i 127.0.0.1 ...
  → curl_cffi.Session(proxies={"https":"socks5h://127.0.0.1:PORT"})
  → result → store.log_byedpi(...)
  → ByedpiManager.stop()
```

---

## 3. Upstream: жизненный цикл ciadpi

Изучено по коду (`main.c`, `proxy.c`, `params.h`).

### 3.1 Стратегии НЕ меняются на лету

- Параметры парсятся **один раз** при старте (`parse_args` в `main.c`).
- Сигналы: `SIGINT`/`SIGTERM` → закрытие listener; `SIGHUP` → **только дамп кеша** (`dump_all_cache`), не релоад стратегий.
- `--auto=torst,ssl_err,redirect` переключает *группы опций* по триггерам внутри одного процесса — но это перебор групп, заданных при старте, а не смена стратегии на лету.

**Вывод:** перевод всегда даёт свежий argv для нового процесса. Process-per-strategy — единственный детерминированный режим для тестирования.

### 3.2 Мульти-инстансность: несколько прокси на разных портах/PID

- `-p <port>` — порт прослушивания (по умолчанию 1080).
- `-i <ip>` — адрес прослушивания (default `0.0.0.0`).
- `-D/--daemon` — демонизация (Linux/BSD); `-w/--pidfile <file>` — PID-файл.
- Модель: **один процесс, event-loop на mpool** (`proxy.c`: accept loop, НЕ fork/pthread на соединение). Нет глобального состояния между инстансами.
- Ограничение на один инстанс нет: N стратегий = N процессов ciadpi на N портах, каждый свой PID.

**Вывод:** параллельный пул ciadpi на `127.0.0.1:PORT_0..PORT_{N-1}` работает без изменений в byedpi; PID-файлы опциональны.

### 3.3 pos_t — ключевая семантика

Формат: `offset[:repeats:skip][+flag1[flag2]]`

| Часть | Значение |
|---|---|
| `offset` | байт или `-N` (от конца пакета) |
| `:repeats:skip` | N позиций (не rawsend!) |
| `+s` / `+h` | внутри SNI / Host |
| `+n` / `+e` / `+m` / `+r` | нулевое / конец / середина / случайно |

**Критично:** nfqws2 `repeats=N` = N rawsend одного пакета. byedpi `offset:repeats:skip` = N позиций **split**. Это разные вещи — в переводчике `repeats` даёт PARTIAL-note, не транслируется.

### 3.4 `-l` fake-data

`-l <file>` или `-l :HEX/escaped` (`ftob`: `:str` → строка, иначе файл). В `main.c` `-l` принимается **один раз** (`if (dp->fake_data.data) continue;`).

**Вывод:** dual-fake ALT2 (stun+max_ru, 2 rawsend в nfqws2) **невозможен в одном ciadpi** — требуется 2 процесса или будущая цепочка. Из пула убран.

---

## 4. Модули

### 4.1 `byedpi_translator.py` — ✅ реализовано

Изолированный модуль (`engine/byedpi_translator.py`, ~330 строк). Чистая функция `translate(strategy) -> Translation | None`.

- `Translation`: `argv: list[str]`, `quality` (`full`/`partial`), `notes: list[str]`.
- `translate()` → `None` (SKIP) при: нет семейства, unmapped fooling (`badsum`, `badsid`, `seqovl`, `ipfrag`, `tcpseg`, `padencap`, `wssize`, `circular`, `dup`, `quic`, …), пустая строка.
- Droppable foolings (`tcp_ack`, `tcp_ts_up`) → переводятся, PARTIAL + note.
- `tcp_ts` → `--ttl 8` (note: другой механизм), `tcp_md5` → `--md5sig`.
- Blob через существующий `resolve_blob_path()` (engine/blob_aliases.py).
- Семьи: fake, hostfakesplit, fakedsplit, fakeddisorder, multisplit/multidisorder, tlsrec, oob, syndata.
- **Порядок семей фиксирован по длине** (fakedsplit/fakeddisorder/hostfakesplit начинаются с "fake") — не зависит от PYTHONHASHSEED.
- Тесты: `tests/unit/test_byedpi_translator.py` (17 кейсов).

### 4.2 `byedpi_matrix_generator.py` — ✅ реализовано

Отдельный source (`engine/byedpi_matrix_generator.py`, ~140 строк), зарегистрирован в `MatrixGenerator.REGISTRY["byedpi"]`.

- **native** (18 one-liners): OOB/disoob (`-o`, `-q`), fake-sni (`-n {sni}`), split/disorder ladders, TLS rec split, md5sig, mod-http (`-M`, HTTP-only), fake-tls-mod (`-Qr`).
- **translated** (15 seeds): nfqws2-строки через `translate()`; label `byedpi:<strategy>`.
- Dedup по argv; `max_count` уважается; HTTP-мод фильтрует `-M`-строки.
- Тесты: `tests/unit/test_byedpi_matrix_generator.py` (8 кейсов).

Итого полный пул: **31 стратегия** (tls12) / HTTP-подмножество.

### 4.3 `ByedpiManager` — план (~120 строк)

```python
@dataclass
class ByedpiManager:
    port: int
    bin_path: str
    argv: list[str]            # из translator (или native line через shlex)
    _proc: subprocess.Popen | None = None

    def start(self) -> str:    # ciadpi -p PORT -i 127.0.0.1 [-K tls] <argv>, _wait_port
    def stop(self) -> None:    # SIGTERM → wait(1) → SIGKILL
    @staticmethod
    def find_free_port() -> int
```

Оркестрация: пул `Semaphore` (как у nfqws2, но без netns) + портовая аллокация.

### 4.4 `curl_probe.py` — план (+10 строк)

```python
@dataclass
class CurlProbeRequest:
    # ...
    proxy: str | None = None   # socks5://127.0.0.1:PORT
```

В `run_curl_probe()`: если `req.proxy` — `Session(proxies={"https": proxy, "http": proxy})`. Не конфликтовать с существующим `SOCKS5_PROXY` (googlevideo-path).

### 4.5 store — план (+35 строк)

- `schema.py`: таблица `byedpi_results` (strategy_id, domain, status, http_code, latency_ms, proxy_port, byedpi_flags, nfqws2_original, error, timestamp).
- `sqlite_store.py`: `log_byedpi()`.
- `store/__init__.py` Protocol: добавить метод.
- Тест `test_sqlite_store.py`.

### 4.6 CLI — план (+15 строк)

```
--engine {nfqws2,byedpi}   default: nfqws2
--byedpi-bin PATH           default: resolve_byedpi_bin()
```

В `async_runner.AsyncTestRunner` — ветка `engine=="byedpi"`: ByedpiManager + run_curl_probe(proxy=...), без netns/semaphore-слоя.

### 4.7 `system_deps.py` — план

`resolve_byedpi_bin()` по порядку: `BLOCKCHECKS_BYEDPI` env → `DATA_DIR/bin/ciadpi` → PATH → `~/.local/bin/ciadpi`. Скачивание — по паттерну `ensure_zapret2_vendor` (GitHub release + sha256), см. §6.

---

## 5. Маппинг стратегий

| nfqws2 | byedpi argv | quality |
|---|---|---|
| `fake:blob=X:repeats=N:tcp_ts=-1000` | `-f -1 -l @blob --ttl 8` | PARTIAL (repeats dropped) |
| `fake:blob=X:repeats=N:tcp_md5` | `-f -1 -l @blob --md5sig` | PARTIAL (repeats dropped) |
| `hostfakesplit:nofake2:tcp_ts=-1000` | `--split 1+sm --ttl 8` | PARTIAL |
| `hostfakesplit:disorder_after:nofake2:tcp_ack=-66000:tcp_ts_up` | `--split 1+sm --disorder 1+sm --ttl 8` | PARTIAL (ack/ts_up dropped) |
| `fakedsplit:pos=N:pattern=X` | `--fake N --disorder N [-l @blob]` | FULL |
| `fakedsplit:pos=midsld:pattern=X` | `--fake 0+sm --disorder 0+sm [-l @blob]` | FULL |
| `fakeddisorder:pos=N:pattern=X` | `--disorder N --fake N [-l @blob]` | FULL |
| `multisplit:pos=A,B` | `--split A --split B` | PARTIAL |
| `tlsrec:pos=N+s` | `-r N+s` | FULL |
| `oob:urp=b` / `s` / `m` | `-o 0` / `0+sm` / `0+m` | FULL |
| `syndata:tls_mod=rnd` | `-f -1 -Q rand` | PARTIAL |
| QUIC/UDP/voice | — | SKIP |
| `badsum`, `seqovl`, `ipfrag`, `padencap`, `circular`, … | — | SKIP |

**Оценка покрытия nfqws2 → byedpi (по families):** ~30–35% переводимо (PARTIAL), ~20% strict FULL. Dual-fake (2 rawsend) — вне одного процесса.

---

## 6. XDG / DAO / бинарники

Бинарники живут в **XDG DATA**, не в `~/.local/bin`:

| Путь | Назначение |
|---|---|
| `$XDG_DATA_HOME/blockcheckS/bin/nfqws2` | symlink на zapret2 nfqws2 (существует) |
| `$XDG_DATA_HOME/blockcheckS/bin/ciadpi` | **новый** symlink на скачанный byedpi |
| `$XDG_DATA_HOME/blockcheckS/byedpi/ciadpi` | каталог vendor (по аналогии `zapret2/`) |

- Паттерн скачивания копируется у `ensure_zapret2_vendor`: GitHub release API → asset → sha256 → распаковка → `DATA_DIR/bin/ciadpi` + chmod 0755.
- `BLOCKCHECKS_BYEDPI` env — переопределение пути.
- DAO: `byedpi_results` — отдельная таблица в том же `state.db` (XdgState); `log_byedpi()` через существующий `RunStateStore` Protocol.

---

## 7. Roadmap

### Phase 1 — Translator (✅ 2026-08-11)
- [x] `engine/byedpi_translator.py` (перевод 9 семей, SKIP-логика, notes).
- [x] `tests/unit/test_byedpi_translator.py` (17 кейсов).
- [x] ruff/unit чистые.

### Phase 1b — Matrix generator (✅ 2026-08-11)
- [x] `engine/byedpi_matrix_generator.py` (native + translated, ~28 стратегий).
- [x] `MatrixGenerator.REGISTRY["byedpi"]`.
- [x] `tests/unit/test_byedpi_matrix_generator.py` (8 кейсов).

### Phase 2 — ByedpiManager (1–2 часа)
- [ ] `engine/byedpi_manager.py` (start/stop/find_free_port).
- [ ] Ручной smoke: `bs scan --engine byedpi -d youtube.com --user-matrix …`.

### Phase 3 — curl proxy (30 мин)
- [ ] `curl_probe.CurlProbeRequest.proxy`.
- [ ] curl через socks5h на локальный ciadpi.

### Phase 4 — store (1 час)
- [ ] `byedpi_results` таблица + `log_byedpi` + Protocol.

### Phase 5 — CLI + runner (1 час)
- [ ] `--engine`, `--byedpi-bin`.
- [ ] `async_runner` byedpi-ветка.

### Phase 6 — system deps (1 час)
- [ ] `resolve_byedpi_bin()` + скачивание в `DATA_DIR/bin/ciadpi`.

### Phase 7 — Bench регресс
- [ ] `dev/byedpi_bench.py` переключить на `byedpi_manager` + translator.
- [ ] Сверка PASS nfqws2 vs byedpi на общем наборе.

### Phase 8 — ByeByeDPI catalog (future, см. §9)

---

## 8. Ограничения byedpi

| Что не работает | Причина |
|---|---|
| `badsum`, `badseq`, `badsid` | byedpi не трогает TCP checksum/sequence |
| `tcp_ack=-66000:tcp_ts_up` | нет эквивалента (дропается, PARTIAL) |
| `seqovl`, `padencap`, `tcpseg`, `ipfrag` | нет sequence overlap / padding / segmentation |
| `ip_autottl` | только фиксированный `-t` |
| UDP voice `fake:blob=discord_udp` | `-a N` ≠ nfqws2 UDP voice |
| QUIC `fake:blob=quic_initial` | QUIC не трогается |
| multiline dual-fake | один `-l` на процесс |
| `circular:fails=` | нет; аналог `-A` auto-chains |
| `repeats=N` (nfqws2 rawsend) | нет эквивалента |
| disorder на Windows | нужен `--split 1+s --disorder 3+s` |

Непереводимые стратегии: `translate()` → `None` → статус `SKIP`.

---

## 9. ByeByeDPI catalog (future)

- Vendor `presets/byedpi/proxytest_strategies.list` (60 curated one-liners, все `-a1`).
- `CiadpiLineParser`: short (`-f-1`) + long (`--fake -1`), `{sni}` placeholder.
- Matrix source `byedpi` уже подключён — catalog дополнит native-пул.
- Domain bundles из `proxytest_*.sites` (youtube 13, googlevideo 19, discord 21, …).

---

## 10. Критерии приёмки

1. `tests/unit/test_byedpi_translator.py` + `test_byedpi_matrix_generator.py` зелёные; ruff чист.
2. `bs scan --engine byedpi -d <domain> --generate byedpi` без root: PASS-вердикты совпадают с nfqws2 на общем пуле, test/sec выше.
3. `gate_all` (unit + quality + ruff) проходит; integration не затронут (default engine = nfqws2).
4. `byedpi_results` пишутся в state.db; `--engine nfqws2` — поведение не изменилось.
