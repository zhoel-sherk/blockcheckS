# Backlog — blockcheckS

Закрытые релизы: [changelog.md](../changelog.md). Здесь только то, чего ещё нет.

## Оглавление

1. [Открытое](#открытое) — конкретная работа в продукте (lua_bridge, host-mode, GP, отложенное).
2. [Оптимизация для слабых устройств](#оптимизация-для-слабых-устройств-pi2-старые-cpu) — память и CPU на Pi2 / старых Xeon / MIPS.
3. [Уголок идей](#уголок-идей) — исследования, не в спринте (в т.ч. [дыры preflight](#preflight-dnsl3geo-ip)).
4. [RL/ML-подбор стратегий](#rlml-подход-подбора-стратегий) — научить очередь угадывать PASS лучше эвристики.

---

## Открытое

Инженерный бэклог: пункты можно брать в работу без нового исследования. Цель — довести текущий стек (lua_bridge, `bs serve`, изоляция трафика) до конца, не изобретая второй движок. Дыры preflight (L3 по всем IP, geo-CDN) — в [уголке идей](#preflight-dnsl3geo-ip), не здесь.

### lua_bridge

Один процесс nfqws2 на батч стратегий: Python пишет id в `/dev/shm`, Lua `scan_pick` выбирает instance. Дефолт с 1.3.1 (`--classic` — старый путь «рестарт на каждую стратегию»). Документ: [custom_lua.md](custom_lua.md).

Lua `smart_fallback` уже пишет в `events.ndjson` события вроде `rst_in` / `retrans` — «DPI уже убил поток, ждать curl timeout бессмысленно». Python **ещё не** читает этот поток во время пробы: `ProbeBatchService` ждёт полный curl timeout даже когда Lua уже знает FAIL.

- [ ] **Ранний abort по IPC.** Пока идёт curl, поллить `events.ndjson` (десятки мс). При `STRATEGY_FAIL` оборвать пробу и записать `fail_phase`, не дожидаясь `--timeout`. Код: `service/batch_service.py`, `lua/blockchecks/scan_bridge.lua`. Готово, когда FAIL-тяжёлый `bs scan` заметно короче wall-time и нет ложных PASS из-за гонки.

Флаг `--lua-bridge-compare` гоняет classic **и** bridge и логирует расхождение вердиктов. Нужен для отладки и `dev/release_smoke.sh`, не для обычного `bs scan`.

- [ ] **Compare убрать с пользовательского CLI.** Оставить в smoke/CI. В `--help` не светить как основной путь. Не путать с `--classic` (это другой backend). Не строить `classic_persistent` (демон без shm) — низкий ROI. UDP voice (очередь 201) и unix-socket reload nfqws2 — не этот пункт.



### Host-mode и Lua Mode A

Сейчас каждая проба в **network namespace** (veth + iptables + свой nfqws2). Это безопасно для хоста, но дорого на слабом CPU.

Два независимых шага:

1. **Mode A** — тот же netns, но демон живёт весь прогон, а не батч. Сейчас Mode B: в conf заранее `strategy=1..N`, в файл пишется только id. Mode A: в файл пишется полная строка `fake:blob=stun:…`, Lua разбирает её на лету. См. [custom_lua.md](custom_lua.md) §7.
2. **Host-mode** — вообще без netns: трафик помечается fwmark / SO_MARK, в NFQUEUE только тестовые пакеты. Референсы: `blockcheck2.sh` (iptables mangle + fwmark) и [blockcheckw](https://github.com/rcd27/blockcheckw) (SO_MARK + nftables vmap).

- [ ] **Разбор** `strategy.cmd` **в Lua.** Whitelist параметров, без `load()`/`eval`. Результат — таблица для `plan_instance_execute`. Python уже пишет строку при `extra_lua_desync` (`lua_bridge_ipc.py`). Нужен забор поколений (gen), чтобы старая строка не применялась к новому пакету.

- [ ] **Один nfqws2 на весь прогон.** Правила iptables/nft ставятся один раз. Замерить очередь NFQUEUE на сотнях стратегий (`--queue-bypass` должен спасать). Не держать демон, если растёт RSS Lua (см. следующий пункт).

- [ ] **Lua GC.** На одном daemon тысячи plan-instance не должны течь. Иначе Mode A на 20-часовом прогоне упрётся в память раньше, чем в DPI.

- [ ] **Выбрать схему host-mode.** A: iptables mangle по dst IP + fwmark loop-protection + notrack (как blockcheck2). B: SO_MARK на сокете воркера + nftables vmap (как blockcheckw). Сравнить сложность cleanup и скорость. Флаг вроде `--probe-backend host`.

- [ ] **Не резать чужой трафик.** Если тестируемый IP сейчас использует браузер/VPN на хосте — предупредить или отказать. Снимать только свои правила (`-D` / `nft delete`), никогда `-F OUTPUT`.

- [ ] **Сверка host vs netns.** Тот же набор youtube/discord: вердикты не должны разъезжаться. Потом бенчмарк (сколько даёт отказ от netns).

- [ ] **Документация.** Mode A — в custom_lua.md. Host-mode: ограничения и риск «сломать Wi‑Fi хоста» — в [guide.md](guide.md).



### GP и `bs serve`

`bs serve` уже слушает Unix-сокет (`~/.local/state/blockcheckS/blockchecks.sock`) и опционально HTTP. Контракт: [api.md](api.md). Кампания `bs full` и сервис взаимно исключаются через `run_control` (423 busy).

[GP control plane](https://github.com/) сейчас запускает `/opt/zapret2/blockcheck2.sh` через root-helper. Идея: ходить в наш сокет, не поднимая второй тестер.

- [ ] **GP → socket.** Root-helper делает POST (action `probe` / `find_strategy` / `start-run` как договоримся), не exec `blockcheck2.sh`. Контракт GP `start-run` сохранить снаружи.

- [ ] **Объём MVP.** TCP/TLS/HTTP через уже тёплый пул. QUIC — отдельный subprocess (как сейчас). UDP voice — отдельные аргументы, не смешивать с TLS-пробой.

- [ ] **Четыре netns на всех.** Пул маленький. Если serve и кто-то ещё дерут одни namespace — явная очередь/отказ через тот же `run_control`, не молчаливая порча iptables.



### Отложено

Не делаем, пока не появится внешний запрос. Чтобы не воскрешать под старыми буквами:

- **Circular в matrix-скане.** `circular` — production-failover внутри nfqws2 («следующая стратегия после N fails»), не способ перебрать матрицу. Экспорт `--in-range`/`--out-range` для Keenetic уже есть. В тестере нужен `scan_pick`, не circular.
- **Дефолтные мультидомены на стороне GP.** Наш импорт пресетов уже умеет пачки доменов.
- **Один nfqws2 навсегда без shm.** Высокий риск утечек и чужого трафика; сначала host-mode + Mode A.
- **Встроить blockcheckw.** Чужой Rust-проект; полезны идеи SO_MARK, не вендоринг.
- **nftables vmap на хосте.** Имеет смысл только вместе с host-mode.
- **Playwright вместо yt-dlp** для свежих googlevideo URL. yt-dlp extra `youtube` достаточно.
- **Порт эвристик unblock-pro.** Внешний каталог, не наш генератор.
- **Скачивать чужие ipset-листы.** Нужно, только если крутим nfqws2 на роутере с IP-блоками. LLC Fiord режет SNI, не IP-лист.

---



## Оптимизация для слабых устройств (PI2, старые CPU)

Сделать так, чтобы `bs full` жил на Raspberry Pi 2 (1 GB RAM, ARM), старом Xeon (у нас 7.5 GB) и в перспективе отдал **готовую таблицу весов** на OpenWrt/MIPS с 64–128 MB.

Уже сделано (1.3.x): `__slots__` + lazy `blobs`/`traits` — RSS полной матрицы примерно **442 → 82 MB**. Этого мало для Pi2, если снова материализовать все стратегии × все домены сразу.

Узкое место очереди: `AdaptiveJobQueue.build()` (`engine/adaptive_queue.py`) создаёт все jobs при старте. За 20 часов скана используется ~38% — остальное висит. На ε-exploration `_rebuild_heap` пересобирает всю кучу (~0.07–0.2 s на Xeon; на Pi хуже). Последовательный lua_bridge в `main_phases.py` дублирует матрицу в `list` + `asyncio.Queue` (~25–30 MB сверху).

### Очередь и RSS

- [ ] **Чанки вместо всей матрицы.** Строить кусок (например 256 стратегий × N доменов ≈ тысячи jobs, ~1 MB), отдавать его, по исчерпании — `refill()` со свежими весами. Веса `ScanWeights` и множество `_done` **общие** на весь прогон (иначе генетический буст и дедуп fan-out сломаются). Чанк обязан брать **все домены** одной стратегии — иначе ломается googlevideo-solo и fan-out. Флаг вроде `--aq-chunk-size`; `None` = как сейчас (тесты не трогать). Бонус: куча больше не живёт со «старыми» приоритетами после `boost_pass`.

- [ ] **Sequential-bridge без полной копии.** В `main_phases.py` не складывать все jobs в список и Queue — идти индексом/генератором.

- [ ] **Сторож по RSS.** Раз в 5–10 с читать RSS своего pid (не только в lua_bridge). Если высоко — уменьшить `bridge_batch`, сделать `flush()` SQLite; если критично — одна стратегия за раз вместо батча. Сейчас порог около 512 MiB (`MEM_MONITOR_PY_MAX_MIB`).

- [ ] **Профиль «Pi2».** Один флаг включает: маленькие чанки, `--parallel 1–2`, `--bridge-batch ~50`, жёсткий RSS, выкл. wssize/ECH/длинный settle, короткие `--timeout`. Слоты в датаклассах уже обязательны — не отключать.



### CPU и subprocess

Каждая classic-проба часто делает `sudo ip netns exec … python -m …` — на Pi это секунды импорта, не сеть.

- [ ] **Curl в том же процессе.** Внутри уже настроенного netns звать `run_curl_probe` через `asyncio.to_thread`, не новый интерпретатор. Если curl_cffi уронит процесс — откатиться на subprocess. Код: `service/probe.py`, `engine/async_runner.py`. На Xeon ~1.2–1.5×; на Pi разница больше.

- [ ] **Проба без тела.** Для «прошёл TLS или нет» достаточно CONNECT + handshake + заголовков (`session.head` / `--no-body`). Тело HTML не качать. **Исключение:** googlevideo — нужен `Range` и кусок медиа, HEAD там бесполезен.

- [ ] **Settle 0.5 s на ARM.** Дефолт `NFQWS2_SETTLE_MAX = 0.5` заточен под x86. Проверить на Pi, что nfqws2 успевает встать; если нет — env override, не раздувать дефолт для всех.



### Таблица весов для роутера

Когда (если) блок RL научит коэффициенты family/blob/trait — их надо увезти без sklearn/ONNX.

- [ ] **Плоский JSON или sqlite.** Чистый Python или C на MIPS считает `score = Σ w`. 64–128 MB RAM, без pip-модели.

---



## Уголок идей

Долгосрок: прототипы, форки, другие языки. Не начинать вместо открытого, если нет явного запроса. Сюда же альтернативный движок byedpi и «DPI начал душить слишком быстрый скан».

### Структурные ускорения

- [ ] **Детектор агрессии DPI.** Если ТСПУ видит пачку проб, вчерашние PASS начинают FAIL. Скользящее окно (~50 проб): PASS-rate ниже порога → пауза (десятки секунд), при повторе — длиннее. Флаги включить/окно/пауза. На 1–4 пробы/с на Fiord, скорее всего, не стреляет — safety net для экспериментов со скоростью. Новый модуль рядом с `async_runner`.

- [ ] **Опциональный движок byedpi/ciadpi.** SOCKS5 без root и netns: один `ciadpi` на стратегию, curl через прокси, старт ~50 ms. План и маппинг флагов: [byedpi_engine.md](byedpi_engine.md). Не умеет `badsum` / `tcp_ts_up` и наш UDP/QUIC — это остаётся nfqws2. На LLC Fiord живьём не гоняли.



### Исследования

- [ ] **C-проба TLS на сырых сокетах.** TCP connect + ClientHello + есть ли ServerHello. Без HTTP, без curl_cffi. Имеет смысл только для packet-level `fake`; `split`/`hostfakesplit` нужен настоящий TCP-поток. Бинарь ~50 KB, вызов subprocess.

- [ ] **Probe-слой на Rust** (reqwest + tokio). Обход GIL; отдельный crate и CI/кросс-компиляция. Имеет смысл после C-прототипа, если он правда выигрывает.

- [ ] **eBPF/XDP вместо nfqws2.** Модификация пакетов в драйвере, line rate. По сути новый продукт на месяцы, не патч.

- [ ] **Hot-reload** `--lua-desync` **в самом nfqws2.** Сейчас SIGHUP обновляет hostlist/ipset, не план Lua. Нужен fork C и unix-socket/API. Обход уже есть: `/dev/shm` + `scan_pick` ([custom_lua.md](custom_lua.md)). Имеет смысл, когда Mode A упрётся в poll файла.

- [ ] **Kernel module** в духе youtubeUnblock. Все стратегии в модуле, переключение через `/proc`. Ядро + security review + матрица версий.

- [ ] **QUIC через системный curl.** `curl --http3-only` вместо отдельного curl_cffi-процесса. Сначала проверить, что `/usr/local/bin/curl` (BoringSSL+quiche) вообще умеет HTTP/3 в нашем окружении.

- [ ] **Конвейер стратегий.** Пока стратегия S ещё curl'ится в netns A, в netns B уже стартует S+1 (settle перекрывается). Сейчас fan-out ждёт все домены S. qnum между netns не конфликтуют. Переписывать `_run_tcp_fanout`.

- [ ] **Timeout 3 s с VPN до US.** Дефолт `--timeout` уже 3. Хватает ли ClientHello через далёкий VPN, или тихие DROP станут ложными FAIL? Замер, не смена дефолта вслепую.

### Preflight: DNS/L3/geo-IP

Чужой RFC предлагал «с нуля» DoH-hijack, MTR как в trippy и geo-CDN через ECS/RIPE. У нас это **не с нуля**. Ниже — что уже делает [`run_preflight_async`](../src/blockchecks/engine/preflight.py), чего не хватает, и что сознательно не копируем. Код не писать, пока пункт не поднимут в открытое.

**Цепочка сейчас:** nfqws2 на хосте → baseline TLS (`ripe.net`) → параллельный UDP vs DoH → UDP 16KB voice → на каждый домен: порт, prolog TLS без nfqws2, SNI↔IP cross-test, L3+stall+JA4+QUIC → диагностика (TTL hops, fooling grid). Результат — [`TriageProfile`](../src/blockchecks/engine/triage.py) и пины в `data_block` hosts / `DnsRunCache`.

**Уже закрывает «anti-hijack» из того RFC:**

- DoH JSON + wire на `curl_cffi` (не httpx), ротация [`DOH_SERVERS`](../src/blockchecks/engine/config.py)
- UDP vs DoH, bogon/sinkhole, **anycast ≠ hijack** ([`audit_domain`](../src/blockchecks/checkers/dns_secure.py))
- Pin: hosts-файл + auto-pin первой **работающей** стратегии, не «любой A-запись из DoH»

TTL у нас — не traceroute: [`probe_ttl`](../src/blockchecks/checkers/ttl_probe.py) читает TTL входящего SYN-ACK/RST, чтобы оценить `server_hops` / `dpi_hops` для `ip_autottl`. L3 — [`probe_l3`](../src/blockchecks/checkers/l3_probe.py): ICMP dest-unreach conclusive, иначе TCP connect; триаж обходит до 6 A-записей и пинит первый живой.

- [x] **L3 по всем A-записям** (cap 6). Первый PASS → pin; все мёртвые → CDN bypassable / origin `unbypassable_l3`.
- [x] **Raw ICMP в триаже.** Conclusive только dest-unreach/admin-prohibit; иначе TCP connect.
- [ ] **Параллельный TTL=1..N** (ICMP Time Exceeded), бюджет ~300–500 мс, лучше только primary-домен. Это blackhole «путь оборвался за N хопов». Не путать с hop-estimate по SYN-ACK. GUI trippy не нужен.
- [x] **DoH через `CURLOPT_RESOLVE`** на bootstrap IP (`1.1.1.1` / `8.8.8.8` / …). SNI/сертификат остаются на имени; hijack UDP не травит hostname резолвера.
- [ ] **Geo-пул только при L3/SYN drop.** ECS на Google DoH (`edns_client_subnet`) и/или несколько резолверов → SYN по кандидатам → pin лучшего RTT. Не гонять ECS на каждый скан (лишняя задержка и лишний DNS).
- [x] **Дешёвый SYN до auto-pin.** `_auto_pin_ips` отсекает SYN_DROP/ICMP `probe_l3` до netns + `fake:blob=stun`.

**Не берём:**

- Сниппет с `httpx` + `verify=False` + «нет пересечения IP ⇒ hijack» — ломает Cloudflare/Google anycast (у нас как раз `_anycast_equivalent`).
- RIPE Atlas в runtime: API-ключ, кредиты, 5–15 с на измерение.
- RIPE Stat «все префиксы AS13335» как триаж: весь Cloudflare. Имеет смысл только офлайн, не per-scan.
- Полный GUI/TUI trippy.

---



## RL/ML-подход подбора стратегий

Научиться **не перебирать** 10k стратегий, а рано ставить вперёд те, что похожи на вчерашние PASS. Эвристика уже есть: адаптивная очередь — линейная модель `семья + блоб + trait`, ε-greedy, куча = argmax, fan-out на соседние домены, preflight провайдера как холодный старт. Таксономия фейлов (`FailPhase`, `TriageProfile`) — в 1.3.x.

Ниже — заменить зашитые 1.0 / 0.5 / 0.4 на числа из `state.db` и (далеко) поиграть в эмуляторе. Обучение **только** как prior для живой сети: LLC Fiord ≠ модель в лаборатории.

### Офлайн-ранкер (холодный старт)

Выгрузка прошлых прогонов → модель «эта стратегия на таком домене скорее PASS» → топ-K кладём в очередь до первого пакета.

- [ ] **Выгрузка фич.** Из `tcp_results`: класс домена × признаки стратегии (семья, blob, fooling, repeats…) → parquet или аналог.
- [ ] **Модель вероятности PASS.** Logistic или GBDT. Не тащить sklearn в runtime-зависимости `bs` — fit офлайн.
- [ ] **Флаг ранкера.** Что-то вроде `--ranker model.json`: топ-K становится seed очереди в том же месте, где сейчас `_apply_provider_weights`.
- [ ] **Когда переучивать.** После большого скана, смены провайдера, или когда живой PASS-rate разъехался с предсказанием.



### Веса внутри очереди

- [ ] **Выучить** `w_family` **/** `w_blob` **/** `w_trait` **из БД**, не хардкод 1.0 / 0.5 / 0.4.
- [ ] **Thompson sampling или LinUCB** вместо (или поверх) ε-greedy — меньше слепого тыканья, когда данных уже много.
- [ ] **Порядок осей генератора** (какой fooling пробовать первым) зависит от класса домена, не глобальный.
- [ ] **Не ломать** `ScanWeights`**.** Таблица `scan_weights` и resume как сейчас; меняется только откуда числа.

Таблица для роутера без ML-зависимостей — в блоке PI2.

### Как понять, что лучше эвристики

- [ ] **Recall на 10 доменах.** На полном переборе знаем «лучшую» стратегию. Раннер/бандит должен находить её, перебрав заметно меньше, чем вся матрица. Без этой цифры «ML быстрее» — ощущение.
- [ ] **Нулевой PASS.** Если очередь застряла в нуле — расширить луч, взять топ-K модели или пройти семью целиком. Не заканчивать скан с пустым shortlist из-за жадности.



### Дальний R&D

Имеет смысл только с **дешёвым эмулятором** DPI. Иначе каждый эпизод — живой `curl` на Fiord.

- [ ] **Среда-бандит, не MDP.** DPI отвечает на один flow, переходов «комната → комната» нет. Gymnasium: Discrete action, эпизод = одна проба. Не путать с непрерывным SAC.

- [ ] **Эмулятор цензора.** NFQUEUE + scapy / nDPI / правила ТСПУ в лаборатории. Учить PPO (stable-baselines3) и GA/CMA-ES параллельно. Проверка — holdout на живом LLC Fiord, не на том же эмуляторе.

- [ ] **PPO vs генетика.** Geneva показал, что GA хорошо ищет новые обходы малым числом проб. PPO — если нужна политика «при таком профиле DPI делай это» и эмулятор дешёвый. SAC не подходит (действия дискретные).

- [ ] **Только prior, не истина.** В деплой уходит дерево/JSON коэффициентов в очередь. Эмулятор генерирует кандидатов. Вердикт всегда с живой сети.