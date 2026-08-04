# Custom Lua для nfqws2 × blockcheckS

> **Статус:** design doc (не реализовано)  
> **Upstream:** [zapret2/nfqws2](https://github.com/bol-van/zapret2) — `zapret-lib.lua`, `zapret-antidpi.lua`, `zapret-auto.lua`  
> **Связанные:** [architecture.md](architecture.md), [byedpi_engine.md](byedpi_engine.md), [todo.md](todo.md) T3-4

Документ описывает, как **кастомные Lua-скрипты** могут усилить blockcheckS: что уже есть в nfqws2, что из идей реализуемо без fork C, и как это стыкуется с Python-раннером.

---

## 1. Как Lua живёт в blockcheckS сегодня

### 1.1 Стек при старте nfqws2

blockcheckS собирает flat `.conf` и запускает daemon в netns:

```text
--lua-init=@/opt/zapret2/lua/zapret-lib.lua
--lua-init=@/opt/zapret2/lua/zapret-antidpi.lua
--lua-init=@/opt/zapret2/lua/zapret-auto.lua
--blob=stun:@.../blobs/stun.bin
--filter-tcp=443
--filter-l7=tls
--payload=tls_client_hello
--lua-desync=fake:blob=stun:repeats=6:tcp_ts=-1000
--lua-desync=fake:blob=max_ru:repeats=6:tcp_ts=-1000   # multiline chain
```

Код: `nfqws2.py`, `async_runner.py`, `config.py` (`LUA_INIT_SCRIPTS`).

### 1.2 Модель выполнения (важно для дизайна)

| Концепт | Смысл |
|---------|--------|
| **Profile** | Блок фильтров + список `--lua-desync` |
| **Instance** | Один вызов Lua-функции из `--lua-desync=` |
| **Chain** | Несколько `--lua-desync` **в одном профиле** — последовательная обработка **одного dissect** |
| **Orchestrator** | `circular`, `condition`, `repeater` — перехватывает execution plan |
| **conntrack** | `desync.track` + `desync.track.lua_state` — состояние на flow |
| **WRITABLE** | `--writable=dir` → env `WRITABLE`, Lua `io.open()` для IPC с Python |
| **Timer** | `timer_set(name, func, period_ms, oneshot, data)` — между пакетами |

**Не путать:** chain внутри одного nfqws2 ≠ два процесса nfqws2 в NFQUEUE pipeline (см. обсуждение в [byedpi_engine.md](byedpi_engine.md)).

### 1.3 Ограничения blockcheckS firewall

`firewall.py` ставит **только OUTPUT NFQUEUE** (TCP/UDP outbound). Для детекторов на **incoming RST / HTTP 302 / ServerHello** нужны правила на входящий трафик (как в keenetic scaffold: `--in-range=-s5556` в `conf_builder.py`). Без этого Lua видит в основном **outbound retrans** — частичный детект.

### 1.4 Предлагаемая раскладка файлов (future)

```text
lua/blockchecks/
  init.lua              # --lua-init после zapret-auto
  fake_mutator.lua      # payload-randomizer
  dpi_assert.lua        # anti-tamper
  scan_bridge.lua       # file/timer IPC + scan_pick orchestrator
  smart_fallback.lua    # fast fail signals
presets/lua/            # опциональные one-liner стратегии
```

Регистрация: расширить `get_lua_init_scripts()` или env `BLOCKCHECKS_LUA_EXTRA=@lua/blockchecks/init.lua`.

---

## 2. Карта идей: feasibility

| # | Идея | Реализуемость | Зависимости |
|---|------|---------------|-------------|
| 1 | Genetic fake mutator | **P1** — mostly Lua | `tls_mod`, `brandom`, blobs |
| 2 | Anti-tamper validator | **P1** — нужен inbound NFQUEUE | INPUT rules, `VERDICT_DROP` |
| 3 | Lua-signal-bridge (socket) | **P2** — нет socket API в Lua | fork nfqws2 **или** file/timer |
| 4 | Smart-fallback → Python | **P1** — file + timer | inbound partial, curl early abort |
| 5 | `/dev/shm` hot-swap strategy | **P1** — file poll | orchestrator `scan_pick` |
| — | `scan_pick` (детерминизм) | **P1** | WRITABLE, batch conf |
| — | `dupfake` atomic hook | **P1** | custom desync function |
| — | `circular` для matrix | **❌** | production failover only |

**P0** = уже в upstream (`tls_mod=rnd`, `standard_failure_detector`). **P1** = кастом Lua без fork C. **P2** = патч nfqws2 (T3-4).

---

## 3. Идея 1 — Genetic LUA-мутатор фейков (payload-randomizer)

### Проблема

Статичные блобы (`quic_initial`, TLS ClientHello) попадают в сигнатурные базы DPI.

### Что уже есть в upstream

`fake()` в `zapret-antidpi.lua` поддерживает:

```text
fake:blob=google:repeats=6:tcp_ts=-1000:tls_mod=rnd,rndsni,dupsid
```

C-функция `tls_mod(blob, modlist, payload)` ([manual.en.md](https://github.com/bol-van/zapret2)):

| Mod | Действие |
|-----|----------|
| `rnd` | random Session ID / random fields |
| `rndsni` | случайный SNI (subdomain или `[a-z][a-z0-9]*`) |
| `dupsid` | Session ID из реального ClientHello |
| `sni=domain` | фиксированный SNI |
| `padencap` | payload в padding extension |

Для QUIC: `fake` + blob `quic_initial_*` + при необходимости кастомный `fool` / post-process.

### Решение blockcheckS

**Уровень A (без кастомного Lua):** расширить генераторы — ось `tls_mod` (`rnd`, `rndsni`, `dupsid`) на `fake` / `multi_fake` families.

**Уровень B (кастомный `fake_mutate`):**

```lua
-- lua/blockchecks/fake_mutator.lua
function fake_mutate(ctx, desync)
  direction_cutoff_opposite(ctx, desync)
  if not (desync.dis.tcp or desync.dis.udp) then return end
  if not payload_check(desync) or not direction_check(desync) then return end
  if not replay_first(desync) then return end

  local base = blob(desync, desync.arg.blob)
  local mods = desync.arg.tls_mod or "rnd,rndsni"
  local payload = desync.reasm_data or desync.dis.payload
  local fake_payload = tls_mod_shim(desync, base, mods, payload)

  -- QUIC: мутировать Connection ID / padding в известных offset (из arg map)
  if desync.l7payload == "quic_initial" and desync.arg.quic_rand_cid then
    fake_payload = quic_mutate_cid(fake_payload, desync.arg.quic_rand_cid)
  end

  -- Seed per-flow для воспроизводимости в DB (опционально)
  if desync.track and desync.track.lua_state then
    desync.track.lua_state.mut_seed = desync.track.lua_state.mut_seed or math.random(1, 0x7FFFFFFF)
  end

  rawsend_payload_segmented(desync, fake_payload)
end
```

**Уровень C (генетический перебор):** orchestrator + `WRITABLE/mutator_gen.json` — Python пишет поколение (набор mods/offset masks), Lua читает при каждом fake; fitness = PASS rate из DB. Это **исследовательский** режим, не default scan.

### Интеграция

- Matrix source `mutator` — комбинации `tls_mod` + optional custom offsets
- Логировать `mut_seed` / hex prefix fake в `--debug` для корреляции с `state.db`
- **Не** ломать resume fingerprint без явного `--mutator` flag

### Риски

- Слишком агрессивный `rndsni` может сломать TLS fingerprint parity с curl_cffi (JA4) — тестировать на Fryazino
- QUIC структура жёстче TLS — мутировать только documented safe offsets

---

## 4. Идея 2 — LUA-валидатор фейков (anti-tamper-assert)

### Проблема

DPI может отвечать фальшивыми RST / HTTP 302, путая логику probe (curl видит fail/success не от реального сервера).

### Что уже есть

`standard_failure_detector` в `zapret-auto.lua`:

- incoming RST в `inseq` range
- HTTP 302/307 redirect на «чужой» SLD
- outbound retrans threshold

`drop()` в antidpi — `VERDICT_DROP` на dissect.

### Решение blockcheckS

**Отдельный instance на inbound** (после добавления INPUT NFQUEUE):

```text
--in-range=-s5556
--lua-desync=dpi_assert:iff=cond_incoming
```

```lua
function dpi_assert(ctx, desync)
  if not desync.dis.tcp or desync.outgoing then return end
  local verdict = VERDICT_PASS

  if bitand(desync.dis.tcp.th_flags, TH_RST) ~= 0 then
    local ttl = desync.dis.ip and desync.dis.ip.ip_ttl
  if ttl and ttl > 64 then  -- эвристика: RST не от ближного hop
      mark_tamper(desync, "rst_ttl=" .. ttl)
      verdict = VERDICT_DROP
    end
  end

  if desync.l7payload == "http_reply" then
    local hdis = http_dissect_reply(desync.dis.payload)
    if hdis and (hdis.code == 302 or hdis.code == 307) then
      if is_dpi_redirect(desync.track.hostname, hdis.headers[...].value) then
        mark_tamper(desync, "dpi_redirect")
        verdict = VERDICT_DROP
      end
    end
  end

  return verdict
end

function mark_tamper(desync, reason)
  write_ipc(desync, { event = "TAMPER", reason = reason, host = desync.track.hostname })
end
```

`write_ipc` → append JSON line to `$WRITABLE/events.ndjson`.

### Python side

- `async_runner`: после curl читать `events.ndjson` → статус `TAMPER` / `PARTIAL_BLOCK`
- Parity с ByeByeDPI truncated-body probe ([byedpi_engine.md](byedpi_engine.md) §8.5)

### Firewall patch (required)

Добавить в `firewall.py` (или netns bootstrap):

```text
iptables -A INPUT -p tcp --sport 443 -j NFQUEUE --queue-num 200 --queue-bypass
```

Или nftables postnat/pre как в [manual.en.md](https://github.com/bol-van/zapret2) § Traffic interception.

### Риски

- DROP inbound RST может замеднить legitimate close — только early ClientHello phase (`in-range`)
- curl_cffi может уже получить RST до Lua — валидатор полезен для **логирования и early abort**, не 100% защита

---

## 5. Идея 3 — Динамический активатор по команде из Python (lua-signal-bridge)

### Проблема

Restart nfqws2 per strategy ≈ 0.5–3s settle (netns); для production Discord/YouTube — микрофризы.

### Реалистичные каналы IPC

| Канал | В nfqws2 Lua | Вердикт |
|-------|--------------|---------|
| UNIX/UDP socket listen | **Нет** API в zapret-lib | Нужен **fork C** (T3-4) |
| `WRITABLE` file | `io.open`, `writable_file_name()` | **✅ P1** |
| `/dev/shm/bs-{ns}.cmd` | то же | **✅ P1**, lowest latency |
| `timer_set` 50–100ms poll | `timer_set` | **✅ P1** |
| SIGHUP | C-side | только hostlists/ipsets today |
| `autostate` / `_G` | Lua global | **✅** внутри одного процесса |

**Рекомендация:** file + timer bridge, не socket (до fork nfqws2).

### Архитектура `scan_bridge`

```text
Python (async_runner)
  write /dev/shm/bs-p-0/strategy.cmd  →  "fake:blob=stun:repeats=6:tcp_ts=-1000"
  write /dev/shm/bs-p-0/strategy.id   →  "42"
  curl ...
  read  /dev/shm/bs-p-0/events.ndjson

nfqws2 (один daemon)
  timer 50ms: read strategy.cmd → parse → _G.bs_active_strategy
  orchestrator scan_pick: execute only matching strategy=N instances
```

**lua-init one-shot:**

```lua
timer_set("bs_poll", poll_strategy_file, 50, false, { path = "/dev/shm/bs-p-0/strategy.cmd" })
```

**Orchestrator `scan_pick`:**

```lua
function scan_pick(ctx, desync)
  orchestrate(ctx, desync)
  local id = tonumber(_G.bs_active_id) or 1
  local verdict = VERDICT_PASS
  while true do
    local inst = plan_instance_pop(desync)
    if not inst then break end
    if tonumber(inst.arg.strategy) == id then
      verdict = plan_instance_execute(desync, verdict, inst)
    end
  end
  return verdict
end
```

Conf содержит **все** стратегии batch (например 200) с `strategy=1..200` — размер conf лимитирует batch.

### UDP switch

`set_udp_strategy:fake:blob=discord_udp:repeats=6` — парсер cmd в Lua → обновить `_G.bs_udp_lines` → orchestrator для UDP profile (`--new=voice`). Полная смена без restart **внутри одного nfqws2** возможна только если UDP instances уже в plan или парсятся из cmd (динамический plan = custom orchestrator + `load()` desync args — **сложно**, нужен safe parser).

**Практичнее:** hot-swap только **TCP tls_client_hello** для matrix; UDP pair matrix оставить coexist q201 restart или pre-built UDP profiles.

### Production vs matrix

| Режим | bridge |
|-------|--------|
| `bs scan` matrix | file poll + `scan_pick`, batch ≤500 |
| Keenetic / long-lived | fork T3-4 unix socket |
| Discord desktop | не blockcheckS path |

---

## 6. Идея 4 — Реактивный failover по метрикам DPI (smart-fallback)

### Проблема

При silent drop Python ждёт curl timeout (3–4s); мёртвые стратегии тормозят matrix.

### Что уже есть

- `standard_failure_detector` — retrans на outbound (работает **без inbound**)
- `send` + `timer_set` delayed send в antidpi
- `automate_failure_check` — счётчик fails для `circular`

### Решение: fast-fail IPC (не production circular)

```lua
function smart_fallback(ctx, desync)
  -- lightweight instance, early in chain or on inbound
  if desync.dis.tcp and desync.outgoing and desync.l7payload == "tls_client_hello" then
    if is_retransmission(desync) and (desync.track.lua_state.retrans or 0) + 1 >= 2 then
      write_ipc(desync, { event = "STRATEGY_FAIL", reason = "retrans", ms = elapsed_ms(desync) })
      -- optional: disconnect flow early via rawsend RST to self
    end
  end
end
```

**Inbound path (если INPUT NFQUEUE):**

```lua
if not desync.outgoing and bitand(desync.dis.tcp.th_flags, TH_RST) ~= 0 then
  write_ipc(desync, { event = "STRATEGY_FAIL", reason = "rst_in", ms = 100 })
end
```

### Python: early abort curl

1. Перед curl: `events.ndjson` truncate / offset
2. `asyncio` task: poll `events.ndjson` каждые 20ms
3. На `STRATEGY_FAIL` → kill curl subprocess / cancel worker
4. DB: `FAIL_FAST` + `fail_reason=retrans` + `latency_ms≈100`

Ожидаемый выигрыш: **3–40×** на dead strategies (зависит от threshold retrans vs silent hang).

### Отличие от `circular`

| | `circular` | `smart-fallback` |
|---|------------|------------------|
| Цель | rotate strategy on host | signal Python to abort probe |
| State | `autostate` per host | per-probe IPC |
| DB row | ambiguous | deterministic `strategy_id` from Python |
| blockcheckS matrix | ❌ | ✅ |

### Риски

- Ложный FAIL на медленных серверах — tune `retrans` threshold, `maxseq`
- Race: curl уже завершился PASS — игнорировать stale events (probe generation counter в cmd file)

---

## 7. Идея 5 — Hot-swap через `/dev/shm` и `_G` (file poll)

### 7.1 Проблема: где именно упирается restart

Перебор стратегий в blockcheckS сегодня = **«новый nfqws2 процесс на каждую стратегию (или на каждый fan-out batch)»**. Hot-swap цель — оставить **один daemon per netns worker** и менять только **активную стратегию** между curl-пробами.

#### Текущий hot path (`_run_tcp_check`)

```text
async_runner.test_tcp()
  pool.acquire(ns)
  _run_tcp_check(ns, strategy, domain, ...)
    mkstemp → write .conf (inline или copy)
    start_daemon(ns, tmp_conf)     ← pkill -9 nfqws2 + Popen @conf + settle
    iptables -A OUTPUT NFQUEUE q200
    invoke_curl_probe_worker(...)
    unlink tmp_conf
  pool.release(ns) → _cleanup_ns: pkill nfqws2 + iptables -F OUTPUT
```

Код: `async_runner.py` (`_run_tcp_check`), `nfqws2.py` (`start_daemon`), `netns_pool.py` (`_cleanup_ns`).

#### Бюджет времени на один TLS-probe (FAIL, wssize retry)

Из [todo.md](todo.md) perf audit (2026-08-04):

| Фаза | Время | Накопительно |
|------|-------|--------------|
| `pkill` + `start_daemon` + settle (`pgrep` poll) | **0.15–0.25s** | 0.25s |
| `iptables -A NFQUEUE` | 0.05–0.10s | 0.35s |
| Python subprocess curl worker | 1–3s | ~2.35s |
| curl timeout (blocked) | 5s | ~7.35s |
| wssize retry (ещё один full cycle) | +7–8s | ~15s |
| DB + `pkill` + `iptables -F` on release | 0.2–0.4s | ~15.25s |

Settle defaults (`config.py`): `NFQWS2_SETTLE_MAX=0.5`, `POLL=0.05`, `MIN=0` — даже при min=0 остаётся **pkill + fork + lua-init ×3 + pgrep loop**.

**Важно:** settle — не главный тормоз на full scan (curl timeout и subprocess доминируют), но на **PASS-тестах** (~100–500ms curl) restart **0.2–0.35s** = **40–70% overhead**. На batch 379k стратегий × 1 domain это **~21–44 часов** только на daemon churn (грубо: 0.25s × 379k ≈ 26h serial; с parallel 4 ≈ 6.5h wall).

#### Что restart делает в nfqws2 (и что **не** обновляется без него)

| При restart | Без restart (сегодня) |
|-------------|------------------------|
| Новый PID, NFQUEUE bind | — |
| `--lua-init` ×3 (parse globals) | SIGHUP → только hostlists/ipsets |
| Parse всех `--lua-desync` → execution plan | План **фиксирован** при старте профиля |
| `--blob` load в Lua vars | Blobs в памяти процесса |
| conntrack / `autostate` сброс | Per-host state сохраняется |
| iptables churn (`-F OUTPUT` на release) | Можно держать одно правило |

**Вывод:** «Просто писать в `_G`» недостаточно — C-side уже собрал **execution plan** из argv. Нужен **orchestrator** (`scan_pick`) или вызов `fake()`/`multisplit()` с динамическими args из файла.

---

### 7.2 Три режима hot-swap (выбор по масштабу)

| Режим | Механизм | Max strategies | Детерминизм DB | Сложность |
|-------|----------|----------------|----------------|-----------|
| **B — `scan_pick` batch** | conf с `strategy=1..N`; file = только `id` + `gen` | 200–2000 | ✅ | **P1, рекомендуемый** |
| **A — dynamic parse** | file = lua-desync line; orchestrator парсит → `plan_instance_execute` | любая строка | ✅ | P1–P2 (safe parser) |
| **C — mutator only** | file = `tls_mod` axis; fake blob один | ∞ комбинаций mods | ✅ | P1 (идея 1) |
| **D — fork T3-4** | unix socket → C reload plan | 379k+ | ✅ | weeks |

**Не путать режим B с `circular`:** B выбирает стратегию **из Python по id**; circular rotate по **failure_detector per host**.

---

### 7.3 Файловый протокол IPC (`/dev/shm`)

Использовать **tmpfs** (`/dev/shm`) — без disk flush, latency ~μs для small files.

```text
/dev/shm/blockchecks/{netns}/
  strategy.id          # текущий int (scan_pick index)
  strategy.gen         # monotonic probe generation (fence stale events)
  strategy.cmd         # optional: full lua-desync line (режим A)
  strategy.ready       # Python writes after id/gen/cmd (atomic rename)
  events.ndjson        # Lua → Python (STRATEGY_FAIL, TAMPER, APPLIED)
  nfqws2.pid           # optional: Python verifies daemon alive
```

#### Atomic write (Python)

```python
def publish_strategy(ipc_dir: Path, id: int, gen: int, cmd: str | None = None):
    tmp = ipc_dir / ".staging"
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "strategy.id").write_text(f"{id}\n")
    (tmp / "strategy.gen").write_text(f"{gen}\n")
    if cmd:
        (tmp / "strategy.cmd").write_text(cmd + "\n")
    # rename atomic on same filesystem
    for name in ("strategy.id", "strategy.gen", "strategy.cmd"):
        src = tmp / name
        if src.exists():
            src.rename(ipc_dir / name)
    (ipc_dir / "strategy.ready").write_text(str(gen))
```

#### Fencing (`gen`)

- Python: `gen += 1` перед каждой пробой; curl worker читает `gen` в результат
- Lua: в `events.ndjson` всегда `"gen": N`; Python игнорирует events с `gen < current`
- Устраняет race smart-fallback (§6) после завершения curl

#### nfqws2 side

```text
--writable=/dev/shm/blockchecks/bs-p-0
--lua-init=@lua/blockchecks/init.lua
```

`init.lua` регистрирует timer и/или hook на ClientHello.

---

### 7.4 Когда читать file: timer vs ClientHello vs гибрид

| Стратегия poll | Latency swap | CPU idle | Риск stale id | Рекомендация |
|----------------|--------------|----------|---------------|--------------|
| **Timer 50–100ms** | до 100ms | постоянный wake | низкий | fallback, UDP profile |
| **On ClientHello** (`replay_first`) | **~0** | нулевой | средний (нужен `gen`) | **TCP matrix default** |
| **Гибрид** | 0 на TLS; timer для UDP | низкий | низкий | pair matrix |

```lua
-- lua/blockchecks/scan_bridge.lua (концепт)

local function read_strategy_ipc()
  local base = os.getenv("WRITABLE") or ""
  local f = io.open(base .. "/strategy.id", "r")
  if not f then return nil end
  local id = tonumber(f:read("*l"))
  local gen = tonumber(f:read("*l"))
  f:close()
  return id, gen
end

function bs_poll_strategy(ctx, desync)
  if desync.l7payload ~= "tls_client_hello" or not replay_first(desync) then return end
  local id, gen = read_strategy_ipc()
  if id then
    _G.bs_active_id = id
    _G.bs_active_gen = gen
  end
end

function scan_pick(ctx, desync)
  orchestrate(ctx, desync)
  local id = tonumber(_G.bs_active_id) or 1
  local verdict = VERDICT_PASS
  while true do
    local inst = plan_instance_pop(desync)
    if not inst then break end
    if tonumber(inst.arg.strategy) == id then
      verdict = plan_instance_execute(desync, verdict, inst)
    end
  end
  write_ipc({ event = "APPLIED", id = id, gen = _G.bs_active_gen })
  return verdict
end
```

**Порядок в conf:**

```text
--lua-desync=bs_poll_strategy
--lua-desync=scan_pick
--lua-desync=fake:blob=stun:...:strategy=1
--lua-desync=fake:blob=max_ru:...:strategy=2
...
```

---

### 7.5 `_G`, execution plan и conntrack — глубже

#### Что можно менять в runtime

| Storage | Scope | Hot-swap use |
|---------|-------|--------------|
| `_G.bs_active_id` | process | индекс для `scan_pick` |
| `_G.bs_strategy_table` | process | lazy parse cmd → args (режим A) |
| `desync.track.lua_state` | per TCP flow | retrans, tamper; **очищается новым conn** |
| `autostate[hostkey]` | per host NLD | **не использовать** для matrix |
| `desync.plan` | per packet (orchestrator) | pop/execute; rebuild только в orchestrator |

#### Новое соединение curl = чистый flow

Каждый curl создаёт **новый TCP connection** → новый conntrack → `lua_state` пустой. Это **плюс** для matrix: нет carry-over retrans от прошлой стратегии. **Минус:** нельзя тестировать «вторая стратегия на том же socket» без keep-alive (curl обычно новый conn).

#### Isolation между стратегиями на одном daemon

| Риск | Митигация |
|------|-----------|
| Старый `autostate` от circular-тестов | не грузить `circular` в bridge conf |
| ipcache по IP | `--ipcache-lifetime=0` (уже в inline conf) |
| nfqws2 internal caches | новый conn per probe |
| Wrong strategy if poll late | `gen` fence + read on ClientHello only |

---

### 7.6 Построение batch conf и лимиты памяти

#### Режим B: размер batch

Оценка строки conf:

```text
--lua-desync=fake:blob=stun:repeats=6:tcp_ts=-1000:strategy=42
≈ 60–120 bytes + multiline × lines
```

| Batch N | conf size (оценка) | nfqws2 parse | Рекомендация |
|---------|-------------------|--------------|--------------|
| 100 | ~15 KB | мгновенно | smoke |
| 500 | ~75 KB | <100ms | **default bridge batch** |
| 2000 | ~300 KB | ~0.5s startup | max practical |
| 379960 | ~45 MB | **OOM / slow** | ❌ split batches |

**Full matrix 379k:** не один daemon — **rolling batches**: Python держит window `[k..k+499]`, при исчерпании batch → restart с следующим window (редкий restart каждые 500 стратегий, не каждую).

#### Генерация batch conf

```python
def build_bridge_conf(strategies: list[str], ipc_dir: str) -> str:
    lines = base_nfqws_lines() + [
        f"--writable={ipc_dir}",
        "--lua-init=@lua/blockchecks/init.lua",
        "--lua-desync=bs_poll_strategy",
        "--lua-desync=scan_pick",
    ]
    for i, strat in enumerate(strategies, start=1):
        for part in strat.strip().split("\n"):
            if part.strip():
                lines.append(f"--lua-desync={part}:strategy={i}")
    return "\n".join(lines)
```

#### Режим A: без N строк в conf

Один `dynamic_apply` orchestrator + `strategy.cmd` file:

- Parser whitelist: families `fake|multisplit|hostfakesplit|...` + known foolings
- **Запрещён** `load()` на произвольной строке (RCE)
- Conf минимальный (~2 KB), но parser = maintenance burden

---

### 7.7 Worker lifecycle: persistent nfqws2 per netns

Целевая архитектура для `--lua-bridge`:

```text
NetNsPool worker bs-p-0 (persistent across many strategies)
  ON worker boot (once):
    mkdir /dev/shm/blockchecks/bs-p-0
    build_bridge_conf(batch_or_empty)
    start_daemon(ns, bridge.conf, kill_existing=True)
    iptables -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 200 --queue-bypass
    (optional) iptables INPUT for inbound detectors

  FOR each strategy item in rolling batch:
    publish_strategy(ipc_dir, id=local_idx, gen=global_gen, cmd=...)
    curl probe (same ns, same nfqws2)
    drain events.ndjson
    log DB

  ON batch exhausted:
    restart daemon with next bridge.conf window OR reload batch file (режим A)

  ON pool.release (worker end):
    pkill nfqws2; iptables -F OUTPUT  # как сегодня
```

**Отличие от сегодня:** `pkill` + `start_daemon` **раз в 500** стратегий, не **раз в 1**.

#### Fan-out (`--fan-out`)

Один nfqws2 + один `strategy.id` + **parallel curl N domains** — все домены получают **одну и ту же** стратегию (корректно для matrix: strategy×domain ячейка). Swap стратегии **между** fan-out волнами, не внутри одной волны.

#### Pair matrix (TCP + UDP)

- TCP: hot-swap через shm (режим B)
- UDP: **отдельный** nfqws2 q201 — либо coexist без pkill (как сегодня), либо отдельный `strategy.id.udp` file + UDP orchestrator (сложнее; Phase 2)

---

### 7.8 Ожидаемый выигрыш (модель)

Переменные (на PASS-heavy short scan):

| | Per-test restart | Hot-swap batch=500 |
|--|------------------|---------------------|
| nfqws2 churn | 0.20s | 0.20s / 500 ≈ **0.0004s** |
| iptables `-A` | 0.08s | 0.08s / 500 ≈ **0.00016s** |
| lua-init parse | каждый тест | раз / 500 |

На **FAIL @ 5s timeout** выигрыш **~1–3%** (curl доминирует). На **PASS @ 150ms** выигрыш **~50–80%** per test. На mixed full scan (большинство FAIL): **~5–15%** total wall + synergия с P0-2 inline curl и `--no-wssize`.

**Синергия с T3-7 pipelining:** hot-swap убирает settle между S и S+1 на **одном worker**; pipelining overlap settle **между workers** — ортогональные оптимизации.

| Оптимизация | Убирает |
|-------------|---------|
| Hot-swap (§7) | pkill/start/settle/iptables per strategy |
| T3-7 pipelining | idle wait между strategy waves |
| T3-4 fork reload | restart entirely |
| P0-2 inline curl | subprocess spawn |
| §6 smart-fallback | curl timeout on dead |

---

### 7.9 Реализация: фазы и CLI

| Phase | Deliverable |
|-------|-------------|
| **7.1** | `lua/blockchecks/init.lua`, `scan_bridge.lua`, `write_ipc()` |
| **7.2** | `Nfqws2Ipc` Python module + `/dev/shm` layout |
| **7.3** | `build_bridge_conf()` + rolling batch iterator |
| **7.4** | `AsyncTestRunner` branch: `--lua-bridge` + `--bridge-batch 500` |
| **7.5** | Persistent iptables on worker acquire (не `-A` per test) |
| **7.6** | Metrics: `settle_ms=0`, `bridge_batch`, `applied_gen` в DB |
| **7.7** | Integration test: 500 strategies, compare results vs classic restart |

```bash
# future CLI
sudo bs scan -d discord.com --generate standard --max 500 \
  --lua-bridge --bridge-batch 500 --parallel 4
```

Env overrides:

```bash
export BLOCKCHECKS_SHM_BASE=/dev/shm/blockchecks
export BLOCKCHECKS_BRIDGE_BATCH=500
```

---

### 7.10 Failure modes и отладка

| Симптом | Причина | Fix |
|---------|---------|-----|
| Wrong strategy applied | poll after ClientHello sent | read only on `replay_first` |
| Stale `STRATEGY_FAIL` | event от прошлого curl | `gen` fence |
| nfqws2 OOM | batch too large | cap 500–2000 |
| Empty `strategy.id` | race before rename | write `strategy.ready` last |
| PASS rate drift vs classic | `scan_pick` bug / wrong id | A/B mode `--lua-bridge-compare` |
| Daemon zombie | crash without pool cleanup | `nfqws2.pid` watch + restart |

Debug: `--debug=@logs/...` + `events.ndjson` tail; `APPLIED` event на каждый ClientHello.

---

### 7.11 Связь с идеей «шина памяти»

Идея «читать conf из `/dev/shm` каждые 100ms и обновлять `_G`» **верна для метаданных** (id, gen, tls_mod axis), но **не заменяет** execution plan для 379k уникальных multiline стратегий:

- **Шина памяти** → **O(1) swap индекса** в preloaded batch (режим B)
- **Полный lua-desync string в shm** → режим A (parser) или rolling batch reload
- **100ms timer** → backup; **ClientHello hook** — primary для TCP

Теоретический ceiling после hot-swap на PASS tests: **min(curl latency, TLS handshake)** ≈ 50–200ms/strategy; на FAIL — всё ещё **curl timeout** unless §6 smart-fallback.

---


## 8. Дополнительные паттерны (из архитектуры blockcheckS)

### 8.1 `scan_pick` — детерминированный batch scan

Альтернатива `circular` для тестов:

```text
--lua-desync=scan_pick
--lua-desync=fake:...:strategy=1
--lua-desync=fake:...:strategy=2
...
```

Python: `id=7` → curl → точно знаем strategy 7. Todo **M10** circular *scan* → реализовать как `scan_pick`, не `circular`.

### 8.2 `dupfake` — atomic multi-blob

Keenetic custom Lua (`dupfake:blob=stun+max_ru:...`) — один hook, один atomic send pattern. blockcheckS fallback: multiline `fake\nfake`. Кастом:

```lua
function dupfake(ctx, desync)
  -- blob=stun+max_ru → два rawsend с repeats из arg
end
```

Preset: `presets/strategies/gp-custom-dupfake.tls` (comments only today).

### 8.3 `condition` / progressive scan (H2)

```text
--lua-desync=condition:iff=cond_tcp_has_ts
--lua-desync=oob:urp=s:strategy=2
```

Сокращает matrix без full Cartesian product — ось в `standard.py` (`oob --in-range`).

### 8.4 Debug / regression

- `argdebug`, `pktdebug`, `zapret-pcap.lua`
- `scripts/strategy_debug_probe.py`
- `--debug=@logs/nfqws2_q200_*.log`

---

## 9. Интеграция в blockcheckS (чеклист)

### 9.1 nfqws2.conf generation

```python
# future: conf_builder / async_runner
lines.append("--writable=/dev/shm/blockchecks/{ns}")
lines.append("--lua-init=@lua/blockchecks/init.lua")
lines.append("--lua-desync=scan_pick")
# ... strategy=1..N groups
```

### 9.2 Python IPC helpers

```python
class Nfqws2Ipc:
    def __init__(self, ns_name: str):
        self.base = Path(f"/dev/shm/blockchecks/{ns_name}")
    def set_strategy(self, id: int, lua_line: str, gen: int):
        (self.base / "strategy.id").write_text(f"{id}\n{gen}\n")
        (self.base / "strategy.cmd").write_text(lua_line)
    def drain_events(self) -> list[dict]:
        ...
```

### 9.3 async_runner branch

- `--persistent-nfqws2` / `--lua-bridge` flag
- Skip `pkill nfqws2` between strategies in same netns worker
- On worker release: still `pkill` + shm cleanup

### 9.4 DB schema extensions

| Column | Source |
|--------|--------|
| `fail_fast` | `STRATEGY_FAIL` event |
| `tamper_reason` | `TAMPER` event |
| `mut_seed` | lua_state log |
| `probe_gen` | `strategy.gen` mismatch detection |

### 9.5 Тесты

- Unit: mock `WRITABLE` dir, parse `events.ndjson`
- Integration: netns + inbound rule + synthetic RST → `TAMPER`
- **Не** ломать default path без `--lua-bridge`

---

## 10. Roadmap (приоритет)

| Phase | Deliverable | Effort |
|-------|-------------|--------|
| **L0** | Док + ось `tls_mod` в generators | done / small |
| **L1** | `firewall.prepare_tcp_inbound()` + keenetic in-range | 0.5d |
| **L2** | `lua/blockchecks/init.lua` + `write_ipc` + `dpi_assert` | 1d |
| **L3** | §7 hot-swap: `scan_bridge.lua`, `Nfqws2Ipc`, rolling batch conf, `--lua-bridge` | 2–3d |
| **L4** | `smart_fallback` + curl early kill | 1d |
| **L5** | `fake_mutate` + matrix source `mutator` | 1–2d |
| **L6** | `dupfake.lua` + preset wiring | 0.5d |
| **L7** | nfqws2 fork: unix socket API (T3-4) | weeks |

---

## 11. Анти-паттерны

1. **`circular` для full matrix** — nondeterministic DB, per-host state pollution.
2. **Два nfqws2 в chain** на одном TCP 443 — NFQUEUE + FWMARK loop prevention.
3. **`load()` на произвольной strategy string** из file — RCE risk; whitelist parser.
4. **Socket IPC без fork** — Lua не умеет listen; не пытаться через `os.execute`.
5. **Inbound assert без INPUT rule** — детекторы молчат.
6. **379k strategies в одном conf** — RAM / parse time; batch ≤500–2000.

---

## 12. Ссылки

| Ресурс | Путь |
|--------|------|
| nfqws2 manual (EN) | `/opt/zapret2/docs/manual.en.md` |
| Orchestrators | `zapret-auto.lua` — `circular`, `repeater`, `condition`, `stopif` |
| Desync functions | `zapret-antidpi.lua` — `fake`, `multisplit`, … |
| blockcheckS nfqws2 lifecycle | `src/blockchecks/engine/nfqws2.py` |
| Keenetic circular scaffold | `src/blockchecks/engine/conf_builder.py` |
| Hot-reload todo | `docs/todo.md` T3-4 |
| ByeByeDPI probe parity | `docs/byedpi_engine.md` §8.5 |

---

## 13. Краткий ответ на «можем ли кастомный fast circular»

**Да, но не через `circular`.** Нужен **`scan_pick` + file/timer bridge**: один nfqws2, Python пишет `strategy.id` в `/dev/shm`, Lua на ClientHello применяет нужную группу, `smart_fallback` шлёт `STRATEGY_FAIL` для early abort. Это даёт скорость близкую к «без restart», с **детерминизмом** blockcheckS matrix.

`circular` оставить для **keenetic export** и production failover ([conf_builder.py](https://github.com/zhoel-sherk/blockcheckS/blob/alpha/src/blockchecks/engine/conf_builder.py) scaffold).

---

## 14. Новые идеи (вне документа)

### 14.1 `parallel_fake` — мульти-фейк в одном проходе

Вместо N отдельных стратегий `fake:blob=stun`, `fake:blob=max_ru`, `fake:blob=google` — один atomic send с **несколькими фейками** подряд. DPI видит каскад фейков → не может вычленить реальный ClientHello.

```lua
function parallel_fake(ctx, desync)
  for _, blob_name in ipairs(desync.arg.blobs or {"stun"}) do
    local base = blob(desync, blob_name)
    rawsend_payload_segmented(desync, base)
    desync.wsleep_us = 200  -- 200µs между фейками
  end
end
```

Вызов: `--lua-desync=parallel_fake:blobs=stun,max_ru,google:tcp_ts=-1000`

**Эффект:** 3 стратегии тестируются за 1 проход вместо 3. 3× ускорение на fake-семействе.

### 14.2 `blob_fusion` — случайная инжекция байт в блоб

Добавляет 1-3 случайных байта в фиксированные offset блоба перед отправкой. Ломает сигнатурное совпадение DPI без полной рандомизации TLS-полей.

```lua
function blob_fusion(ctx, desync)
  local base = blob(desync, desync.arg.blob)
  local seed = desync.track.lua_state.flow_seed or math.random(1, 0x7FFFFFFF)
  math.randomseed(seed)
  for _ = 1, (desync.arg.fuse or 3) do
    local pos = math.random(5, #base - 5)
    base = base:sub(1, pos) .. string.char(math.random(32, 126)) .. base:sub(pos + 1)
  end
  rawsend_payload_segmented(desync, base)
end
```

Вызов: `--lua-desync=blob_fusion:blob=stun:fuse=3:tcp_ts=-1000`

### 14.3 `tcp_rtt_calibrate` — адаптивный тайминг фейка

Измеряет RTT между SYN и SYN/ACK → вычисляет оптимальную задержку для fake-пакета. Если RTT=20ms, fake должен уйти через 10ms после real, а не через фиксированный `wsleep`.

```lua
function tcp_rtt_calibrate(ctx, desync)
  if desync.dis.tcp and desync.dis.tcp.th_flags == TH_SYN then
    desync.track.lua_state.syn_ts = get_us()
  elseif desync.dis.tcp and bitand(desync.dis.tcp.th_flags, TH_SYN + TH_ACK) == TH_SYN + TH_ACK then
    local rtt = get_us() - (desync.track.lua_state.syn_ts or get_us())
    desync.track.lua_state.rtt_us = rtt
  end
end
```

### 14.4 `quic_cid_rotate` — ротация QUIC Connection ID

DPI трекает QUIC по Connection ID. Если менять CID между Initial и Handshake — DPI теряет flow. QUIC позволяет серверу сменить CID в ответе, но клиентский CID фиксирован. Инжекция фейкового Initial с другим CID сбивает tracking.

```lua
function quic_cid_rotate(ctx, desync)
  if desync.l7payload ~= "quic_initial" then return end
  local payload = desync.dis.payload
  -- QUIC Initial: offset 6 (flags + version + DCIL/SCIL + DCID + SCID + token)
  -- Меняем 1 байт Source Connection ID
  local scid_start = 6 + 5 + payload:byte(6)  -- after DCID
  local fake = payload:sub(1, scid_start) .. string.char(math.random(0, 255)) .. payload:sub(scid_start + 2)
  rawsend(desync, fake)
end
```

### 14.5 `ttl_binary_scan` — бинарный поиск TTL

Вместо `--ttl 8` — Lua тестирует TTL=1,2,4,8,16,32,64 за 7 проходов (log₂ 128) и находит минимальный TTL, при котором fake доходит до DPI но не до сервера.

```lua
function ttl_scan(ctx, desync)
  local lo, hi = 1, 64
  local state = desync.track.lua_state.ttl_scan or { phase = "probe", lo = 1, hi = 64, probe = 4 }
  -- binary search логика: отправить fake с probe TTL → ждать verdict от Python → сузить диапазон
end
```

Требует feedback от Python (через `/dev/shm` IPC): достиг ли fake сервера? (TCP RST от сервера = TTL достал, timeout = TTL мал).

### 14.6 `proto_hop` — перескок между TCP/QUIC на лету

Для доменов где TCP blocked а QUIC open (или наоборот) — одна стратегия пробует TCP, при fail → QUIC probe без перезапуска nfqws2. Lua на ClientHello без ответа → `timer_set` → QUIC Initial probe.

```lua
function proto_hop(ctx, desync)
  if desync.l7payload == "tls_client_hello" and replay_first(desync) then
    desync.track.lua_state.tcp_sent_ts = get_us()
  end
  -- timer: через 2s если нет ServerHello → QUIC probe
end
```

---

## 15. Заключение и метрики

### Таблица: идеи по категориям

| # | Идея | Тип | Оценка (1–5) | Эффект | Трудозатраты |
|---|------|-----|-------------|--------|-------------|
| **§3** | `fake_mutator` — генетическая мутация фейков | **Quality** | ⭐⭐⭐⭐ | Обход сигнатур DPI через рандомизацию blob | 1–2d |
| **§4** | `dpi_assert` — валидатор фейков (anti-tamper) | **Quality** | ⭐⭐⭐ | Детект фальшивых RST/HTTP 302 от DPI | 1d |
| **§5** | `lua-signal-bridge` — сокет/IPC мост | **Speed** | ⭐⭐⭐⭐⭐ | Устранение pkill+settle per strategy | 2–3d |
| **§6** | `smart-fallback` — fast-fail по retrans | **Speed** | ⭐⭐⭐⭐⭐ | Early abort curl при dead-стратегии (3–40×) | 1d |
| **§7** | `scan_pick` hot-swap — file poll + orchestrator | **Speed** | ⭐⭐⭐⭐⭐ | Без restart между стратегиями (50–80% на PASS) | 2–3d |
| **§7.8** | `dupfake` — atomic multi-blob | **Quality** | ⭐⭐⭐ | Два фейка в одном atomic send | 0.5d |
| **§8.3** | `condition` — progressive scan | **Speed** | ⭐⭐⭐ | Пропуск целых Cartesian-осей | 1d |
| **14.1** | `parallel_fake` — мульти-фейк в одном проходе | **Speed** | ⭐⭐⭐⭐ | 3 стратегии за 1 проход (3× на fake) | 0.5d |
| **14.2** | `blob_fusion` — случайная инжекция байт | **Quality** | ⭐⭐⭐ | Ломает сигнатуры без полной рандомизации | 0.5d |
| **14.3** | `tcp_rtt_calibrate` — адаптивный тайминг | **Quality** | ⭐⭐ | Оптимальная задержка fake относительно real | 0.5d |
| **14.4** | `quic_cid_rotate` — ротация QUIC CID | **Quality** | ⭐⭐ | Сбивает QUIC connection tracking | 0.5d |
| **14.5** | `ttl_binary_scan` — бинарный поиск TTL | **Quality** | ⭐⭐⭐ | Авто-подбор TTL вместо хардкода ttl=8 | 1d |
| **14.6** | `proto_hop` — перескок TCP↔QUIC | **Speed** | ⭐⭐ | Тест TCP+QUIC без перезапуска nfqws2 | 1d |

### Приоритетный роадмап (по убыванию ROI)

```
1. §7  scan_pick hot-swap     | Speed  ⭐⭐⭐⭐⭐ | 2-3d | Максимальный эффект, batch 500
2. §6  smart-fallback         | Speed  ⭐⭐⭐⭐⭐ | 1d   | 3-40× на dead-стратегиях
3. §5  lua-signal-bridge      | Speed  ⭐⭐⭐⭐⭐ | 2-3d | Инфраструктура для §7 и §6
4. §3  fake_mutator           | Quality ⭐⭐⭐⭐ | 1-2d | Обход сигнатур, synergy с §14.2
5. 14.1 parallel_fake         | Speed  ⭐⭐⭐⭐  | 0.5d | 3× на fake-семействе, low effort
6. §4  dpi_assert             | Quality ⭐⭐⭐  | 1d   | Точность результатов
7. 14.5 ttl_binary_scan       | Quality ⭐⭐⭐  | 1d   | Авто-TTL вместо хардкода
8. §8.3 condition             | Speed  ⭐⭐⭐   | 1d   | Меньше стратегий без потери покрытия
9. §7.8 dupfake               | Quality ⭐⭐⭐  | 0.5d | Better mimicry
10. 14.2 blob_fusion          | Quality ⭐⭐⭐  | 0.5d | Сигнатурный evasion
11. 14.3 tcp_rtt_calibrate    | Quality ⭐⭐   | 0.5d | Тайминг-оптимизация
12. 14.4 quic_cid_rotate      | Quality ⭐⭐   | 0.5d | QUIC evasion
13. 14.6 proto_hop            | Speed  ⭐⭐    | 1d   | TCP↔QUIC без restart
```

### Кумулятивный эффект (модель)

В комбинации: `scan_pick` + `smart-fallback` + `parallel_fake` + `--no-wssize` (P0-1) + inline curl (P0-2):

```
Текущий full-скан:                                         0.26 тест/сек
  + scan_pick hot-swap (§7):                               0.35  (+35% PASS-heavy)
  + smart-fallback (§6, early abort dead):                 0.50  (+43% от dead skip)
  + parallel_fake (14.1, 3× fewer fake probes):            0.65  (+30%)
  + inline curl (P0-2, no subprocess):                     0.85  (+30%)
  + --no-wssize (P0-1, no double retry):                   1.45  (+70%)
  ─────────────────────────────────────────────────────────
  Итого:                                                   1.45 тест/сек (5.6× от baseline)
```

**Теоретический потолок на PASS-тестах:** `min(curl RTT, TLS handshake)` ≈ 50–200ms → **5–20 стратегий/сек** на одном worker. С 4 workers → **20–80 стратегий/сек** (vs текущие 0.26). При 379k full-матрице: от 80 минут до 5 часов (vs текущие 16 дней).
