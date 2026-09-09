# Host-mode (fwmark) — архитектура

> **Статус:** **v1 + v2 РЕАЛИЗОВАНЫ** (2026-09-09: 39b2617+1ce1eeb v1; d5da9d5
> бинар 1.0.5.1 + PROBE_MARK; 82857ca v2a кампания; ce90c3b v2b адаптивный пул +
> detach правил; UDP/QUIC host — v2 UDP волна). `--probe-isol=host` работает на
> oneshot, composite, scan/pair/full; UDP voice (bypass=False) и QUIC
> (bypass=True) идут через UDP-слоты 221+2i. Канон разделов *зачем/как/чего не
> делать* остаётся; расхождения править здесь.
> Бинар: nfqws2 1.0.5.1 (lua_compat 6), `--fwmark` + `--filter-mark`
> (PROBE_MARK=0x20000000, nft `meta mark set` — пара, не по отдельности). Принято на живой линии: чемпион через host-слот
> (nft skuid bcprobe + fwmark, queue 220) PASS 75–135ms HTTP 200; teardown и
> рестарт после kill -9 — по приёмке §19 (AUDIT §16). Важно: /etc/environment
> прокси нейтрализуется `apply_no_env_proxy` на всех probe-сессиях; живой bind
> детектится через `/proc/net/netfilter/nfnetlink_queue` (stdout-маркер
> флашится только на выходе демона).
>
> **Рантайм:** host-mode **не** требует nfqws2 ≥ 1.0.5. Изоляцию очереди
> делает nft (`skuid` / cgroup / mark), не `--filter-mark`. v1.0.5 полезен
> сам по себе (pad TCP options, `luaexec`→verdict) и даёт `--filter-mark`
> как **второй замок**; без него host-mode включать можно.
>
> **Связанные:** [architecture.md](architecture.md) (data-flow),
> [todo.md](todo.md) (бэклог Host-mode), [custom_lua.md](custom_lua.md)
> (`scan_pick`, shm), [guide.md](guide.md) (операторские флаги — появятся после
> кода), AGENTS.md §8 / §11 (pkill, IPC, «NAT не блокер»).

---

## Оглавление

1. [Зачем это и чем это не является](#1-зачем-это-и-чем-это-не-является)
2. [Две оси: изоляция ≠ смена стратегии](#2-две-оси-изоляция--смена-стратегии)
3. [Как сейчас устроена изоляция (as-built)](#3-как-сейчас-устроена-изоляция-as-built)
4. [Почему netns остаётся дефолтом](#4-почему-netns-остаётся-дефолтом)
5. [Целевой datapath: nft режет очередь, `--fwmark` антипетля](#5-целевой-datapath-nft-режет-очередь-fwmark-антипетля)
6. [Марки и номера очередей](#6-марки-и-номера-очередей)
7. [nft-таблица: контракт создания и teardown](#7-nft-таблица-контракт-создания-и-teardown)
8. [Кто ставит mark: skuid/cgroup, не SOCKOPT curl_cffi](#8-кто-ставит-mark-skuidcgroup-не-sockopt-curl_cffi)
9. [lua_bridge на хосте: ограничение параллелизма](#9-lua_bridge-на-хосте-ограничение-параллелизма)
10. [Фазы внедрения (v1 / v2)](#10-фазы-внедрения-v1--v2)
11. [Карта модулей (для агентов)](#11-карта-модулей-для-агентов)
12. [CLI, env, resolver](#12-cli-env-resolver)
13. [Fair exclusion: `run.lock` и чужой nfqws2](#13-fair-exclusion-runlock-и-чужой-nfqws2)
14. [Входящий RST и conntrack](#14-входящий-rst-и-conntrack)
15. [UDP / Discord Voice](#15-udp--discord-voice)
16. [Чем это не blockcheck2.sh](#16-чем-это-не-blockcheck2sh)
17. [Keenetic / `bc-nfconf`](#17-keenetic--bc-nfconf)
18. [Инварианты безопасности](#18-инварианты-безопасности)
19. [Приёмка и сверка host vs netns](#19-приёмка-и-сверка-host-vs-netns)
20. [Явные non-goals](#20-явные-non-goals)
21. [Порядок работ, когда перейдём в код](#21-порядок-работ-когда-перейдём-в-код)
22. [Глоссарий](#22-глоссарий)

---

## 1. Зачем это и чем это не является

**Зачем.** Убрать veth+NAT из пути пробы, чтобы пакеты шли тем же маршрутом,
что обычный сокет на этой машине (тот же WAN, тот же TTL до ТСПУ). Историческое
«таймаут из‑за NAT» снято (AGENTS.md §11); host-mode нужен не как лечение
фейкового timeout, а как:

- дешёвый datapath на слабом CPU (Pi / старый Xeon — нет netns на воркер);
- **полный подбор** (`bs full` / `scan` / `pair` / week_cov), если коробка
  **выделена** под тестер (оператор купил Raspberry Pi только для этого —
  его выбор, не «нельзя»);
- честная сверка вердикта с host-стеком;
- безопасная замена нынешнего `bs tcp` без `--ns`, который ставит
  **HostFirewall на весь tcp/443** без mark.

**Где netns всё ещё разумный дефолт.** Смешанный хост: opencode, mihomo,
браузер, SSH рядом с прогоном (наш Xeon). Там `--probe-isol=netns`, чтобы
не дурить чужой трафик даже при ошибке mark. Это **профиль машины**, не
запрет команд.

**Чем это не является.**

| Это не… | Почему |
|---|---|
| Обязательный дефолт вместо netns | На смешанном хосте netns безопаснее; isol=host — явный флаг / env |
| Паритет с `blockcheck2.sh` | У BC2 очередь по **dst IP**; у нас — только сокет пробы |
| Lua Mode A | Разбор `strategy.cmd` в Lua — отдельный эпик в [todo.md](todo.md) / [custom_lua.md](custom_lua.md) |
| Экспорт `--filter-mark` на Keenetic | Другой hop, другой смысл fwmark (PBR роутера) |
| Второй HTTP-клиент | Проба остаётся curl_cffi + JA4 + DoH pin |

nfqws2 v1.0.5 (`--filter-mark`, pad TCP options, `luaexec`→verdict) — **рантайм**.
Host-mode — **транспорт пробы**. Их не надо смешивать в один PR. v1 host-mode
**не** требует `--filter-mark` в бинаре: очередь режет nft.

---

## 2. Две оси: изоляция ≠ смена стратегии

```
                 изоляция пакетов
            netns (сейчас) │ host+mark (цель)
                          │
смена стратегии           │
lua_bridge / scan_pick ───┼── тот же IPC, тот же APPLIED
one-shot start_daemon   ──┼── bs tcp / composite (уже host без mark)
```

Сегодня `--probe-backend` в `engine/config.py` (`resolve_probe_backend`)
означает **lua_bridge vs classic** (classic на кампании deprecated → map).
**Нельзя** занять это имя значением `host`.

Новый флаг (имя в коде, не путать с backend):

```text
--probe-isol=netns|host     дефолт netns
BLOCKCHECKS_PROBE_ISOL=netns|host
```

Кампания TCP по-прежнему lua_bridge. One-shot (`bs tcp` без `--ns`) уже хост,
но firewall широкий — host-mode v1 **сужает** его mark’ом, а не «добавляет AQ
на текущий HostFirewall».

---

## 3. Как сейчас устроена изоляция (as-built)

Агенту: не выдумывать второй пул, пока не прочитаны эти символы.

### 3.1 Кампания (scan / pair / full)

```
pair_phases / main_phases
  → AsyncTestRunner + NetNsPool          service/netns_pool.py
  → BridgeSession.boot()                 service/lua_session.py
       LuaBridge.setup()                 /dev/shm/blockchecks/<ns>/
       write_bridge_conf()               service/lua_conf.py
       start_daemon(ns, conf)            service/nfqws2_launcher.py
       _bridge_iptables_add(ns, dport)   service/lua_netns.py
  → invoke_curl_probe_worker(ns, …)      service/probe.py
       sudo ip netns exec <ns> python -m … --mode curl
```

Пул: имена `bs-p-<pid>-<i>` (`NETNS_BASE`, `config.py`). На хосте для каждого
ns: veth + `FORWARD ACCEPT` + `MASQUERADE` — это **`NetNsPool`**, не класс
`HostFirewall`.

NFQUEUE внутри ns: `NsFirewall` (`service/ns_firewall.py`) —
`ip netns exec <ns> iptables -A OUTPUT … -j NFQUEUE --queue-num 200|201`.
Teardown только парным `-D` по `_RuleSpec`. **Никогда** `iptables -F OUTPUT`.

### 3.2 One-shot `bs tcp` без `--ns`

`TestRunner` (`service/test_runner.py`): хост + `Nfqws2Manager(ns_name=None)`
**foreground** `sudo -n nfqws2` + `HostFirewall.prepare_tcp(port=443, qnum=200)`
— очередь **всех** исходящих TCP/443 (опционально `attach(dst_ip=…)` уже есть).
Curl: `python -m blockchecks.service.in_ns_workers --mode curl` **без**
`ip netns exec`. Это **не** persistent `_WORKERS` (`invoke_curl_probe_worker`).
`bridge_applied` остаётся `None` → `campaign_pass()` = только HTTP
(`engine/results.py`).

`Nfqws2Launcher.daemon()` **требует** `ns_name` (`ValueError` если `None`,
`nfqws2_launcher.py`). Долгоживущий host lua_bridge **не** стартует через
нынешний `start_daemon()` — v1 обязан ослабить это или дать `daemon_host()`.

Это ближайший родственник blockcheck2 и **опасный** прецедент: host-mode
должен **сузить** HostFirewall mark’ом, а не размножить AQ на широкий OUTPUT.

### 3.3 Очереди

| Константа | Env | Дефолт | Смысл |
|---|---|---|---|
| `NFQUEUE_TCP` | `BLOCKCHECKS_QNUM_TCP` | 200 | TLS/HTTP в ns и в `build_filter_lines` |
| `NFQUEUE_UDP` | `BLOCKCHECKS_QNUM_UDP` | 201 | QUIC / voice |

На хосте Xeon часто уже живёт nfqws2 на 200. Host-mode **не** занимает 200/201.

### 3.4 lua_bridge IPC

`LuaBridge(ns_name)` → `BridgePaths(SHM_BASE / ns_name)`:

```text
/dev/shm/blockchecks/<ns>/
  strategy.id | strategy.gen | strategy.cmd | strategy.ready
  events.ndjson | heartbeat
  lua/   (staged scan_bridge.lua — overflow-uid не читает repo)
```

`scan_pick` (`lua/blockchecks/scan_bridge.lua`): глобальные `_G.bs_active_id` /
`_G.bs_active_gen`. Один процесс nfqws2 = **одна** активная стратегия.
Кампания публикует id через `LuaBridge.publish()` (`lua_bridge_ipc.py`: gen →
cmd → id → ready, `os.replace`); проба — `run_tcp_check_bridge()` в
`batch_bridge_probe.py`, drain `events.ndjson` с `expect_id`.
`BridgeEvent.is_applied()` требует `APPLIED` и `matched != 0`.

Campaign PASS = HTTP OK **и** APPLIED (`engine/results.campaign_pass`:
`bridge_applied=True`). `False` → FAIL. `None` (oneshot / fan-out /
`_run_tcp_check`) → только HTTP. Harvest SQL: `bridge_applied IS NULL OR = 1`.
Host-mode на lua_bridge **не** ослабляет ∧ APPLIED.

`teardown_all_bridge_shm()` удаляет только префикс
`{NETNS_BASE}-{pid%10000:04d}-` и явный `ns_names`. Слоты `host-q220-<pid>`
**не** попадут под campaign cleanup — в `run_session` / `bs stop` передавать
явный список или glob `host-q*-{pid}`.

Kill демона: только `metrics.pkill_nfqws2_in_ns(ns)` (inode netns).  
**Запрет:** `ip netns exec <ns> pkill nfqws2` — нет PID namespace, умрут все
демоны на хосте.

### 3.5 Persistent curl worker

`service/probe.py`: ключ `_WORKERS[(ns_name, py, epoch)]`. Чтение stdout —
`os.read` + remainder, не `TextIOWrapper.read(1)`. На destroy ns —
`release_curl_probe_worker(ns)` из `NetNsPool._destroy_one`.

`_worker_cmd()` **всегда** `sudo ip netns exec <ns_name> … --mode curl`.
Буквальный `ns_name="host"` → попытка exec несуществующего netns. Не
использовать `"host"` как ключ.

`bump_ns_epoch()` зовётся только из `NetNsPool._create_one()`. Рестарт host
nfqws2 без bump оставляет stale worker (как после `ip netns delete` без
release). Два процесса с одним ключом — гонка JSON на одном stdin.

Host-mode: отдельная ветка `_worker_cmd` (как oneshot TestRunner — без
netns exec) + ключ `("host-q{N}-{pid}", py, epoch)` + `bump_ns_epoch` на каждый
recycle демона/таблицы + `release_curl_probe_worker` на teardown.

Пул **release** (не destroy) оставляет NFQUEUE в ns для reuse
(`lua_session.shutdown` не detach). Host-слот так не переиспользовать без
явного контракта: на хосте правила общие с браузером.

---

## 4. Почему netns остаётся дефолтом

Дефолт `--probe-isol=netns` — для **смешанного** хоста, не потому что
`bs full` «нельзя» на mark.

- На Xeon рядом живут opencode, mihomo, браузер, SSH: ошибка firewall без
  mark порежет Wi‑Fi. Netns это переживает.
- DoH и пин IP уже с хоста; внутри ns проба идёт с veth — предсказуемый
  лабораторный путь для сверки.
- Параллелизм сегодня: N ns × N nfqws2 × N `bs_active_id`. На host это v2
  (K qnum), не «кампания запрещена».
- IPC и overflow-uid отлажены в ns; host-слоты должны повторить тот же
  контракт, не ослабить APPLIED.

**Выделенная коробка** (Raspberry Pi / VPS / mini-PC, на ней только
blockcheckS): оператор ставит `BLOCKCHECKS_PROBE_ISOL=host` и гоняет
`bs full` / week_cov целиком. Mark-схема B как раз для этого: чужого
браузера нет, экономия RAM/CPU на netns — главная победа (см. todo.md,
оптимизация Pi2).

Host-mode — **opt-in изоляция на все команды**, которые умеют lua_bridge /
oneshot. Не урезать CLI до `bs tcp`. Порядок внедрения (§10): сначала
доказать транспорт (v1), потом тот же isol на пуле слотов для кампании (v2).

---

## 5. Целевой datapath: nft режет очередь, `--fwmark` антипетля

В [todo.md](todo.md) две схемы:

| | A (как blockcheck2) | **B (цель)** |
|---|---|---|
| Кто в NFQUEUE | весь трафик на IP цели | только проба (`skuid` / cgroup / mark) |
| Чужой браузер на youtube.com | попадает под desync | нет |
| `--filter-mark` 1.0.5 | не нужен | **опциональный** второй замок внутри nfqws2 |
| Риск | сломать Wi‑Fi хоста | ошибка match (слишком широкий skuid) |

**Кто изолирует хост.** Правило nft **до** NFQUEUE. Пакеты без match в очередь
220 физически не попадут. `--filter-mark` внутри nfqws2 **не** замена nft и
**не** блокер v1: если в очереди уже только проба, профильный фильтр ничего
не добавляет к изоляции. Имеет смысл как defence-in-depth, если match nft
когда-нибудь расширят (баг cgroup, лишний dport).

**Зачем два бита всё равно.** `--fwmark` / `DESYNC_MARK` — не фильтр пробы.
nfqws2 вешает его на **свои** rawsend (фейки). Без `mark & DESYNC == 0` в nft
фейки возвращаются в ту же очередь → петля. Это ортогонально `--filter-mark`.

```
                 ┌─ DoH (другой uid / без match) ─ pin CURLOPT_RESOLVE
curl worker      ┤  uid=bcprobe | cgroup slice
  (без SO_MARK)  └─ TCP/443
                      │
                      ▼
         nft inet blockchecks_host  (OUTPUT)
           meta skuid bcprobe   (или meta cgroup …)
           meta mark & DESYNC == 0
           tcp dport 443
           meta mark set PROBE     # опционально, для --filter-mark
           queue num $HOST_QNUM bypass
                      │
                      ▼
         nfqws2 --qnum=$HOST_QNUM
           --fwmark=$DESYNC_MARK          # антипетля rawsend — обязательно
           [--filter-mark=$PROBE/$PROBE]  # только если nft ставит PROBE
           --lua-desync=scan_pick …
```

Схема A (`-d $ip` без mark/skuid) в продукт **не идёт**.

---

## 6. Марки и номера очередей

Два бита, не один. Путать их — классика петли NFQUEUE.

| Имя | Предлагаемое значение | Кто ставит | Зачем |
|---|---|---|---|
| `DESYNC_MARK` | `0x40000000` | nfqws2 `--fwmark` (дефолт апстрима) | пакеты, которые демон сам rawsend, не возвращаются в очередь |
| `PROBE_MARK` | `0x20000000` | **nft** `meta mark set` на matched skb (не curl) | опционально; нужен только вместе с `--filter-mark` |

Проверка перед стартом: `PROBE_MARK & DESYNC_MARK == 0`. Не пересекать с
локальным PBR на Xeon (сейчас Xeon в exclude Keenetic; marks хоста — локальные).

**Очереди host-mode** — отдельный диапазон, не 200/201:

| Env | Значение | Роль |
|---|---|---|
| `BLOCKCHECKS_HOST_QNUM_TCP` | 220 | TLS/HTTP host-mode (слот 0) |
| `BLOCKCHECKS_HOST_QNUM_UDP` | 221 | QUIC/voice host-mode (слот 0) |
| слот *i* | 220+2*i (TCP), 221+2*i (UDP) | пул без netns, `HostSlotPool` |
| `BLOCKCHECKS_HOST_SLOTS` | auto\|N | размер пула: auto = min(cpu−1, 60% MemAvailable / 220 MiB), cap 16 |

Перед bind: если qnum уже слушает чужой nfqws2 — **отказ**, не «следующий
свободный» втихую (запрет silent fallback). Можно *явно* `--host-qnum=` после
лога «занято».

`build_filter_lines()` сегодня хардкодит `NFQUEUE_TCP`. Host-профиль должен
принимать qnum аргументом, не подменять глобальные 200/201 для netns-кампаний.
`--filter-mark` в conf — только если nft реально ставит `PROBE_MARK`.

---

## 7. nft-таблица: контракт создания и teardown

Предпочтительно **одна** таблица `inet blockchecks_host`, удаление целиком.

```text
nft add table inet blockchecks_host
# OUTPUT: marked probes → NFQUEUE
# PREDEFRAG/output: DESYNC_MARK → notrack (как в manual zapret2)
# PREROUTING/INPUT: ct mark restore → queue inbound RST/SYN-ACK (см. §14)
nft delete table inet blockchecks_host    # единственный teardown
```

Правила:

- Снимать **только** свою таблицу / свои tracked `-D`. Никогда `-F OUTPUT`,
  никогда `nft flush ruleset`.
- `--queue-bypass`: если демон мёртв, пакеты идут мимо очереди → ложный PASS.
  Как в ns: сначала heartbeat/bind settle, потом attach firewall (см.
  `BridgeSession.boot`: daemon, затем `_bridge_iptables_add`).
- iptables-legacy fallback только если nft недоступен; тот же `_IptablesTracker`
  + match `mark`. Расширить `_RuleSpec` полем `mark` / `mark_mask`, не копипастить
  трекер.

Существующий `HostFirewall.prepare_tcp` без mark после v1 считать **устаревшим**
для операторского `bs tcp`; оставлять только за `--probe-isol=netns` не нужно —
oneshot host должен идти в marked путь.

---

## 8. Кто ставит mark: skuid/cgroup, не SOCKOPT curl_cffi

Стек пробы **не меняется**: тот же `curl_probe.py` (JA4, RESOLVE, ECH).
Меняется **кто запускает** worker и **какое nft-правило** его ловит.

**Почему не `CurlOpt.SOCKOPTFUNCTION`.** В curl_cffi **0.16.1** константа
`SOCKOPTFUNCTION = 20148` есть в enum, но `Curl.setopt()` её **не
реализует**: обрабатываются WRITE/HEADER/READ/DEBUG/SEEK. Остальное
`void*` → `NotImplementedError: Option unsupported`. Python-callable в
libcurl `curl_sockopt_callback` из коробки не пробросить. Не проектировать
v1 вокруг этого и не ждать патча curl_cffi.

**Канон v1 — метка снаружи сокета**

1. **Предпочтительно:** выделенный uid воркера (например `bcprobe`), nft
   `meta skuid bcprobe`. DoH / оркестратор остаются под обычным uid —
   в очередь не попадут. **Не** `nobody` и **не** overflow-uid `2147483647`
   (это nfqws2 после setuid).
2. **Альтернатива на systemd:** `systemd-run --scope --slice=blockchecks-probe`
   + nft `meta cgroup`. Удобно на Pi без отдельного uid.
3. **Не** `LD_PRELOAD` на `socket()` в v1 (хрупко, ломает impersonate-loader).
4. **Не** httpx / голый `socket` вместо curl_cffi.

nft может сразу `queue`, без `SO_MARK` на fd. `PROBE_MARK` — если хотим
`--filter-mark`: `meta mark set PROBE` на том же правиле. `--fwmark`
антипетли на nfqws2 **обязателен** независимо от uid.

На выделенном Pi, где весь uid оператора = только `bs`, допустим match по
этому uid (все его :443 — пробы). На смешанном Xeon — только uid/cgroup
воркера, не `zhoel`.

Worker cache: ключ `("host-q{N}-{pid}", py, epoch)`, не `"host"`.
`release_curl_probe_worker` на teardown. `bump_ns_epoch` при recycle.

HTTP/3 curl_cffi по-прежнему не даёт реальных UDP:443. QUIC — `quic_raw`.

---

## 9. lua_bridge на хосте: ограничение параллелизма

Это главное архитектурное отличие от пула ns.

`scan_pick` читает `strategy.id` в **процесс-глобальные** `_G.bs_active_id`.
Два curl с разными id на одном nfqws2 → гонка APPLIED / ложный PASS without
APPLIED (уже лечили с другой стороны: host-wide pkill).

Следствие:

| Конфигурация | Допустимо |
|---|---|
| 1 nfqws2, 1 curl, смена id между пробами | v1 |
| 1 nfqws2, N curl, **одна** стратегия | бессмысленно для AQ |
| 1 nfqws2, N curl, **разные** стратегии | **запрещено** |
| K nfqws2, K qnum, K shm dir, K curl | v2 (пул без veth) |

IPC на хосте: не `ns_name=""` и не `"host"`. Слот **с PID сессии**:

```text
/dev/shm/blockchecks/host-q220-<pid>/
```

Статический `host-q220/` после `kill -9` оставляет грязные `strategy.id` /
`events.ndjson` следующему запуску. `teardown_all_bridge_shm` режет префикс
`bs-p-{pid%10000}` — host-слоты туда не входят; в `run_session` / `bs stop`
передавать явный `ns_names` **или** префикс `host-q*-{pid}`.

`LuaBridge("host-q220-12345")` кладёт файлы под `SHM_BASE / ns_name`.

**Kill nfqws2 на хосте.** `--daemon` делает double-fork, PPID=1.
`pkill_host_process_tree(launcher_pid)` **не видит** демона (дерево
оборвано). `pkill_nfqws2_in_ns` на host inode убьёт чужой nfqws2.

Канон host-mode:

1. **Предпочтительно:** foreground `subprocess.Popen` **без** `--daemon`
   (как `Nfqws2Manager` / `Nfqws2Launcher.foreground`) — PID известен,
   `terminate`/`kill` по нему. lua_bridge на хосте не обязан `daemon()`.
2. Если всё же `--daemon`: обязателен `--pidfile=` (nfqws2 умеет) + kill
   по этому PID, не process tree.

`start_daemon()` сегодня `ValueError` без `ns_name` — для host не вызывать
его «как есть», а дать foreground-host путь.

Параллелизм **доменов** при одной стратегии (`_run_tcp_check_multi` /
`--curl-parallel`) на одном демоне безопасен; параллелизм **стратегий** —
нет. Fan-out доменов lua_bridge обходит (`warn_fanout_bridge_once` в
`batch_service.py`): scan_pick — батч стратегий, не батч доменов.

Overflow-uid / chmod / setfacl на `/dev/shm/blockchecks/host-q*` — тот же
`_ipc_relax_for_nobody`. Не chmod чужие `bs-p-*` mid-run.

Heartbeat fence (`init.lua` 200ms, `wait_heartbeat_fresh`) — без изменений:
тихая смерть NFQUEUE bind (#300) на хосте та же.

---

## 10. Фазы внедрения (v1 / v2)

### v1 — транспорт, не скорость

Цель: marked oneshot + lua_bridge, concurrency **1**, сверка с netns.

- `--probe-isol=host` на `bs tcp` и опционально `bs composite` / preflight
  fooling-grid.
- Один nfqws2, qnum 220, shm `host-q220-<pid>`.
- nft table: `skuid` / cgroup (+ опционально `meta mark set PROBE`).
- `--fwmark=DESYNC` обязателен; `--filter-mark` — только если nft ставит PROBE.
- `run.lock` или эквивалентный host-isol lock.
- Сверка чемпионов discord/youtube (PASS/FAIL, не мс).

**Не входит в v1 как обязательный объём кода:** AQ-цикл и `AsyncTestRunner`
на K слотах, Mode A, Keenetic export. Команды `scan`/`full`/`pair` на host
в v1 **не запрещены продуктом** — просто ещё нет пула qnum, поэтому
concurrency=1 (медленно, но на выделенном Pi это валидный выбор оператора
для дымового `full`, не для week_cov).

### v2 — параллелизм без veth = кампания на host (**РЕАЛИЗОВАНО** 2026-09-09)

K слотов = K qnum = K nfqws2 на хосте = K `LuaBridge("host-q…")`  
(`service/host_slots.py: HostSlotPool` — тот же acquire/release контракт, что у
`NetNsPool`, но без ns). Поверх — тот же `AsyncTestRunner` / AQ. Размер пула —
**адаптивный** (`BLOCKCHECKS_HOST_SLOTS=auto|N`; auto = min(cpu−1, 60%
MemAvailable / 220 MiB на слот), cap 16) — решение оператора 2026-09-09:
«слоты не делать фиксированными». `--parallel` остаётся ручкой netns-пулов.

**Уроки живой приёмки v2 (больше не «теория»):**
- Правило слота с мёртвым демоном = `--queue-bypass` пропускает пробы RAW
  (pin-проба оставила правило 220 → все пробы уходили в мёртвую очередь →
  0/18 при живом чемпионе). Лечится `detach_host_slot_rule(qnum)` при
  каждом kill демона (§18.6 усилен).
- Recreate таблицы на каждом boot рвал соседние слоты дважды: transient
  (правило удалено → очередь пуста) и permanent (каждый attach писал только
  СВОЁ правило). Итог: attach идемпотентный + **additive** (`_ATTACH_LOCK`),
  teardown — только `nft delete table` целиком.
- Живой bind — только `/proc/net/netfilter/nfnetlink_queue` portid; stdout-
  маркер флашится на выходе демона.
- Память-монитор для слота — по PID демона (`daemon_proc.pid`), не по
  `/var/run/netns/<name>` (его нет).
- Паритет вердиктов host vs netns подтверждён: scan discord.com,
  одинаковый сет стратегий, один период ТСПУ: **5/18 = 5/18**.

UDP (§15): voice — правило **без bypass** на qnum 221+2i; QUIC — **с bypass**
(parity с NsFirewall); oneshot UDP/QUIC снимает пустую таблицу
(`teardown_host_queue_if_empty`).

---

## 11. Карта модулей (для агентов)

Куда класть код, когда дойдёт до PR. Не размазывать mark по генераторам.

| Модуль | Роль сейчас | Host-mode |
|---|---|---|
| `cli/parser.py` | `--ns`, `--qnum`, `--probe-backend` | `--probe-isol`, `--host-qnum` |
| `engine/config.py` | `NFQUEUE_*`, `resolve_probe_backend` | `PROBE_MARK`, `DESYNC_MARK`, `resolve_probe_isol`, host qnum; **не** пихать host в `resolve_probe_backend` |
| `engine/conf_builder.py` / `lua_conf.py` | `--qnum=200`, `--bind-fix4`, нет fwmark | аргумент qnum; `--fwmark`; `--filter-mark` опционально |
| `service/ns_firewall.py` | `NsFirewall`, `HostFirewall` без mark | match `skuid`/cgroup (+ mark) в `_RuleSpec`; deprecate голый `prepare_tcp` |
| **новый** `service/host_isol.py` | — | таблица nft, uid/cgroup воркера, bind qnum, teardown |
| `service/lua_session.py` | `ns_name` обязателен, iptables in-ns | слот `host-qN-<pid>` без `_check_netns_exists` |
| `service/lua_netns.py` | `_bridge_iptables_add` | не вызывать для host; отдельный attach |
| `service/lua_bridge_ipc.py` | `LuaBridge(ns_name)` | `ns_name="host-q220-<pid>"` |
| `service/metrics.py` | kill по inode ns | kill **конкретного** Popen PID / `--pidfile`, не inode host |
| `service/probe.py` | `_worker_cmd` = netns exec | ветка без netns; spawn воркера под `bcprobe` / slice |
| `checkers/curl_probe.py` | Session + RESOLVE + ECH | **без** SOCKOPT; DoH — другой uid, не воркер |
| `service/nfqws2.py` / launcher | `foreground()` умеет `ns_name=None`; **`daemon()` → ValueError без ns** | v1: **foreground** на хосте (не double-fork); settle по bind marker в `nfqws2_out_host_*.log` |
| `service/test_runner.py` | oneshot host/ns | HostFirewall по skuid/cgroup + qnum 220; не путать с persistent worker |
| `engine/results.py` `campaign_pass` | HTTP ∧ APPLIED на bridge | host lua_bridge тот же ∧; oneshot без bridge — HTTP only |
| `lua_session.teardown_all_bridge_shm` | префикс `bs-p-{pid}` | явно передавать `ns_names=["host-q220-<pid>"]` |
| `service/netns_pool.py` | veth+NAT | не трогать в v1 |
| `engine/adaptive_queue.py` | AQ | не трогать в v1 |
| `engine/generators/*` | матрица | не трогать |
| `nfconf.py` | Keenetic conf | **не** добавлять `--filter-mark` в v1 |

Тесты: unit на `_RuleSpec`+skuid/cgroup, resolver isol, «нет nft-match → отказ»;
integration — opt-in, не CI GitHub (sudo+nft). Не возвращать монолитный
`pytest tests/` в CI.

---

## 12. CLI, env, resolver

Предлагаемый контракт (ещё не в argparse):

```text
--probe-isol {netns,host}     default netns
--host-qnum INT               override TCP queue (default 220)
--host-mark 0xHEX             PROBE_MARK (default 0x20000000)

BLOCKCHECKS_PROBE_ISOL
BLOCKCHECKS_HOST_QNUM_TCP / _UDP
BLOCKCHECKS_PROBE_MARK / BLOCKCHECKS_DESYNC_MARK
```

`resolve_probe_isol(args)`:

- isol=host + нет uid/cgroup воркера и нет nft-match → ошибка (не «весь :443»);
- бинар без `--filter-mark` — **warning**, не отказ; defence-in-depth пропускаем;
- isol=host + активный `run.lock` чужой кампании → ошибка (как serve vs full);
- isol=host + qnum занят → ошибка;
- isol=netns → нынешний путь, игнорировать `--host-mark`.

`--classic` по-прежнему не включает host-mode.

Preflight: live fooling-grid сегодня дергает probe в ns/lock-skip. Host-mode
grid — только если нет lock **и** оператор явно isol=host. Иначе skip + warning
(уже есть `_maybe_skip_fooling_for_lock`).

---

## 13. Fair exclusion: `run.lock` и чужой nfqws2

`service/run_control.py`: кампания пишет `RUN_LOCK_FILE`. `bs serve` не
стартует при живом lock.

Один `run.lock` на процесс кампании — как сейчас. `bs full --probe-isol=host`
держит lock сам; второй `bs tcp` / `bs serve` не стартует. Не нужен отдельный
«запрет full + host».

Конфликты, которые **резать**:

- два прогона на одной машине (netns-кампания и host-isol, или два host);
- qnum 200/201, если на этой же коробке уже слушает production nfqws2
  (на «чистом» Pi часто нет — тогда всё равно лучше 220+, чтобы не пересечься
  с ручным `nfqws2` оператора);
- `cleanup_env.sh` **без** `--orphans-only` во время **любого** live-прогона
  (ns или host) — снесёт таблицу/демоны. На week_cov в host-mode тот же
  запрет полного cleanup, что и для ns.

---

## 14. Входящий RST и conntrack

Исходящий match (`skuid` / cgroup) на RST от ТСПУ не действует: ответ приходит
на WAN без uid воркера.

`smart_fallback` ловит inbound RST (TTL ≥ 64) → `STRATEGY_FAIL` / `rst_in`.
На хосте это **best-effort**, не паритет с netns.

**Почему одного `ct mark` мало.** DPI часто шлёт **инжект** RST: sequence
вне окна → Linux conntrack ставит `INVALID` и **не** привязывает пакет к
сессии. `ct mark` исходящего потока на такой RST **не восстанавливается**.
Правило `ct mark and PROBE queue` его не увидит.

Честный минимум, если вообще ловим inbound:

- `ct state invalid` + узкий L4 (tcp `rst` flag, sport 443) — не «весь
  sport 443» (это схема A), и всё равно ложные срабатывания возможны;
- либо смириться: v1 = только OUTPUT; PASS/FAIL по HTTP 200 vs timeout
  (Fryazino silent drop как раз timeout). Не обещать `rst_in` в приёмке v1.

Не заявлять паритет `rst_in` с netns, пока нет отдельного захвата invalid RST.

---

## 15. UDP / Discord Voice

Тот же `PROBE_MARK` на UDP-сокете STUN/voice. Отдельный qnum (`HOST_QNUM_UDP`).
Профиль nfqws2: `--filter-udp=…`; `--filter-mark` только если nft ставит PROBE.

Не смешивать TCP и UDP в одной очереди (как сейчас 200 vs 201).  
v1 можно **только TCP**; UDP — когда TCP сверка зелёная.

UDP voice attach сегодня: `_attach_udp_queue(ns_name, port, *, coexist)` в
`in_ns_workers.py` ставит `fw.attach(…, queue=NFQUEUE_UDP, bypass=False)`.
`--queue-bypass` на voice → трафик минует nfqws2 → ложный
PASS. Host-mode UDP обязан повторить `bypass=False`.

`curl_cffi` HTTP/3 сюда не прикручивать.

---

## 16. Чем это не blockcheck2.sh

| | blockcheck2.sh | blockcheckS netns | host-mode B |
|---|---|---|---|
| Очередь | `-d $ip` / nft daddr | OUTPUT в ns | skuid/cgroup (+ опц. mark) |
| Смена стратегии | часто новый процесс / eval | lua_bridge id | lua_bridge id |
| Проба | curl скрипта | curl_cffi JA4 | **тот же** curl_cffi |
| Параллелизм | обычно 1 | N ns | v1: 1; v2: K qnum |
| Результат | текст/summary | SQLite, AQ, pair, harvest | то же API |
| Чужой трафик на IP | да | нет (другой ns) | нет (нет mark) |

Host-mode **сближает datapath** с BC2 на Xeon, не продукт. Схема A была бы
«стать BC2»; мы её отвергаем.

---

## 17. Keenetic / `bc-nfconf`

`--filter-mark` на роутере — про фильтр **профиля** по fwmark LAN/PBR (Win11 vs
исключения), не про SO_MARK curl на Xeon.

v1 **не** добавляет `--filter-mark` в `nfconf.py` / Keenetic `.conf`. Иначе
операторские конфиги начнут молча PASS’ить немеченый LAN.

Отдельный эпик: «Keenetic профили по mark» — после host-mode на тестере, не
вместо.

`--bind-fix4` в netns optional (PBR); на хосте Xeon с политикой маршрутизации
может понадобиться — решать по логу `bind-fix4=0`, не копировать слепо.

---

## 18. Инварианты безопасности

Агент обязан соблюдать все пункты. Нарушение = регрессия класса «PASS without
APPLIED» или «порезали Wi‑Fi».

1. **Нет silent fallback.** Нет nft-match (skuid/cgroup) / занят qnum →
   ошибка и лог (`log.warning`/`error` с причиной), не «тогда как BC2».
   Отсутствие `--filter-mark` в бинаре — warning, не отказ.
2. **Не `iptables -F` / не flush ruleset.** Только своя nft-таблица или tracked `-D`.
3. **Не `ip netns exec … pkill nfqws2`.** На хосте — kill по PID слота, не по
   inode всего host netns.
4. **Не qnum 200/201** для host-mode, пока на машине может жить чужой nfqws2.
5. **Не дурить немеченый трафик.** Контрольный curl без mark на discord.com
   не должен менять код ответа из‑за нашего nfqws2.
6. **Settle до attach.** Heartbeat/bind, потом nft queue. Иначе `--queue-bypass`
   → ложный PASS.
7. **campaign_pass** на lua_bridge: HTTP ∧ APPLIED. Host не ослабляет это.
8. **IPC overflow-uid:** ACL + sudo chmod fallback; не world-writable без
   warning; не chmod живые `bs-p-*`.
9. **`CancelledError` / голый `except`:** как в AGENTS.md code quality.
10. **Worker stdout:** только `os.read` + remainder.
11. **DoH без mark.** На host-слоте DoH идёт от того же `bcprobe`-воркера и
    попадает под skuid-правило (дёсинкится наравне с пробой) — это ПАРИТЕТ с
    netns (там очередь ловит весь ns OUTPUT tcp/443). Не «чинить» выделением
    второго uid для DoH: пины CURLOPT_RESOLVE живут в том же воркере.
12. **Blob `4pda` → `b4pda`** в conf-builder — не отключать на host-профиле.
13. **Не `ns_name="host"`** в `probe.py` / `LuaBridge` — `_worker_cmd` делает
    `ip netns exec`. Слот только `host-qN-<pid>`.
14. **Host nfqws2 — foreground `Popen`, не `--daemon`.** Double-fork рвёт дерево;
    `pkill_host_process_tree` лаунчера демона не найдёт. `--pidfile` — запас.
15. **UDP voice: `bypass=False`.** TCP campaign `bypass=True` + живой демон;
    путать нельзя.
16. **`teardown_all_bridge_shm` не видит `host-q*`** по префиксу `bs-p-`.
    Передавать `ns_names` явно (`host-qN-<pid>`). Не статический `host-q220/`.

---

## 19. Приёмка и сверка host vs netns

Минимальный набор (Fryazino-реалии, не «любой сайт»):

1. Чемпион `fake:blob=stun:repeats=6:tcp_ts=-1000` на `discord.com` — PASS оба
   isol.
2. Нежизнеспособный `multisplit` без fooling — timeout/FAIL оба (не PASS).
3. Немеченый curl во время (1) — тот же результат, что до старта host nfqws2.
4. IPC: в `events.ndjson` слота есть APPLIED с ожидаемым id.
5. Teardown: `nft list table inet blockchecks_host` → нет таблицы; qnum свободен.
6. Повторный старт после kill-9 Python — не оставляет OUTPUT NFQUEUE (atexit
   недостаточен: нужен lock+gc или явный `bs stop` / detach в `run_control`).

Бенчмарк «на сколько быстрее без veth» — **после** паритета вердиктов, не
вместо. Метрика: wall-time `bs tcp` × N, не AQ.

Не сравнивать мс 1-в-1 (NAT vs host). Сравнивать статус и `bridge_applied`.

---

## 20. Явные non-goals

Пока нет отдельного решения оператора:

- сменить **дефолт** CLI на isol=host (на смешанном Xeon это опасно; на
  образе «Pi-only» можно зашить env в unit, не в argparse default);
- мультиплекс разных стратегий на одном `scan_pick` (Mode A++ / lua_state по
  4-tuple);
- Python `cffi` → libnetfilter_queue;
- `--filter-mark` в экспорте Keenetic;
- SSID-neg / NLM-neg (клиентский Wi‑Fi, не этот эпик);
- ранний abort curl по `STRATEGY_FAIL` (свой пункт todo lua_bridge);
- замена `blockcheck2.sh` в GP root-helper (сокет `bs serve`, другой эпик).

---

## 21. Порядок работ, когда перейдём в код

Не начинать с AQ и не начинать с nft «на весь 443».

1. Апгрейд **пары** nfqws2 + `zapret-lib.lua` на v1.0.5 (compat 6) — **ops**,
   не блокер host-mode. Smoke чемпиона в **существующем** netns (pad TCP options).
2. `host_isol.py` + nft table (`skuid` / cgroup) + teardown + тесты трекера.
3. Spawn curl-воркера под выделенный uid / systemd slice (не SOCKOPT curl_cffi).
4. `write_bridge_conf` / oneshot: `--fwmark`; `--filter-mark` если nft ставит PROBE.
5. Foreground `Popen` + kill по PID; shm `host-qN-<pid>`.
6. `--probe-isol=host` на `bs tcp`; сверка §19.
7. Документация оператора в guide.md (флаги, риски).
8. v2: пул `host-qN-<pid>` + тот же `AsyncTestRunner` / AQ — `bs scan`/`full`/`pair`
   / week_cov с `--probe-isol=host` на выделенной коробке.

Пункт 1 можно сделать **без** кода host-mode. Пункты 2–7 — один эпик v1.

---

## 22. Глоссарий

| Термин | Смысл здесь |
|---|---|
| **isol / probe-isol** | Где живут пакеты пробы: `netns` или `host` |
| **probe-backend** | Как крутится стратегия: только `lua_bridge` на кампании |
| **PROBE_MARK** | Опциональный fwmark на matched skb (nft), не SO_MARK из Python |
| **DESYNC_MARK** | `--fwmark` nfqws2, антипетля rawsend (апстрим `0x40000000`) |
| **`--filter-mark`** | Defence-in-depth внутри nfqws2 ≥ 1.0.5; **не** изоляция очереди |
| **схема A** | Очередь по dst IP, как blockcheck2 — отвергнута |
| **схема B** | Очередь только пробы (skuid/cgroup, не dst IP) — канон |
| **HostFirewall (код сейчас)** | OUTPUT NFQUEUE на хосте **без** mark; подлежит сужению |
| **HostFirewall (architecture.md §пул)** | путаница: FORWARD/MASQUERADE для veth делает `NetNsPool` |
| **слот host-qN** | Синтетическое имя вместо netns: shm + qnum + PID демона |
| **Mode A** | Lua парсит полную строку стратегии из `strategy.cmd` — не host-mode |
| **Mode B (lua)** | В conf заранее `strategy=1..N`, в файл пишется id — текущий bridge |
| **v1 / v2** | Один демон vs K демонов на хосте |

---

*Конец канона. Расхождения с кодом после реализации править здесь же, не в
чатах. Если агент предлагает очередь `-d youtube_ip` «для простоты» — это
схема A, отклонять.*
