# TODO / roadmap — blockcheckS

Единый живой документ: цели, статус, бэклог и сжатый research
(бывшие `research.md` + `GOALS.md`). Обновлять здесь, не плодить
корневые roadmap-файлы.

## Mission

Lightspeed DPI strategy tester для **zapret2/nfqws2**:

- \>10× быстрее наивного `blockcheck.sh` (restart-per-strategy);
- curl_cffi / BoringSSL (браузерный JA4), не голый OpenSSL curl;
- content / DPI-заглушки, netns + tracked iptables;
- TCP×UDP pairs + fingerprint resume;
- mass `bs full` (strategy × coverage) + dual nfqws2 conf export;
- unit/integration, которые ловят регрессии контрактов.

## Статус фаз (факт 2026-07)

| Phase | Тема | Статус |
|-------|------|--------|
| 1 | Single TCP (`bs tcp`, configs, content check) | ✅ |
| 2 | UDP voice STUN / dual nfqws2 | ✅ |
| 3 | Pair matrix + checkpoint/resume + discover | ✅ |
| 4 | Parallel asyncio + NetNsPool | ✅ |
| 5 | GP JSON/DB bridge | 📋 partial (`state.db`; GP import later) |
| 6 | Export keenetic + raw (`bs full` / `bc-nfconf`) | ✅ |
| 7 | QUIC/HTTP3 first-class | 🔄 generate + full stub; curl_http3 later |
| 8 | HTTP :80 families | 📋 |

## CLI сейчас

| Entry | Роль |
|-------|------|
| `bs` | tcp / udp / scan / pair / composite + early `full` |
| `bc-main` / `bs full` | mass strategy×coverage + export |
| `bc-nfconf` | export only from `state.db` |

Дефолт `bs full` = максимум (uncapped × `presets/domains/coverage.txt`).
Флаги только сужают. Ориентир GP (curl без curl_cffi): ~21k strat /
~515k success links / ~968k raw attempts — `bs full` целится в тот же
масштаб, но с curl_cffi + content + UDP/voice.

## Ближайший бэклог

1. **~80% сценариев bol-van/zapret2** в matrix + checkers.
2. **~95% flowseal-like** (перевод + пересечения zapret2 ∩ flowseal).
3. ~~nfqws2-keenetic export~~ ✅ (`conf_builder` / `bc-nfconf`).
4. **[unblock-pro](https://github.com/by-sonic/unblock-pro)** — переносимые эвристики.
5. **matrix_generator** — registries, dedup, PASS priority, стабильный fingerprint.
6. **multi-endpoint** pair matrix по всем discover EP.
7. **package-data**: явная политика `configs/` (repo root vs wheel).

### googlevideo CDN probe (2026-07-30)

Модуль есть, в stress-test **не используется**:

- `checkers/youtube_url.py` — `get_fresh_url()` via `yt-dlp` → signed
  `*.googlevideo.com/videoplayback?…`, кэш `logs/bs_gv_url_cache.json` (3h).
- `async_runner` для `googlevideo*`: ECH off + `Range: bytes=0-17407` + rate bands
  для 206 — но curl на **`https://googlevideo.com`**, не на videoplayback URL.
- `get_fresh_url()` **нигде не вызывается** из `bs tcp` / `pair` / `full`.

Факты Fryazino (без VPN):

- `yt-dlp` URL — **OK** (~15s, youtube metadata).
- curl на корень / videoplayback **без nfqws2** — timeout (DPI).
- Chunk probe **реален без VPN**, но **нужен nfqws2** + YouTube-стратегия
  (ориентир: `hostfakesplit:disorder_after:…`, dpi-tester 27–37 chunks).

GP vs blockcheckS на `googlevideo.com`: GP **12** success links (`http_req` +
hostfakesplit); blockcheckS stress **0 PASS** (TLS на корень домена).

- [ ] **Wire `get_fresh_url()`** в `async_runner` / sync runner: при
  `googlevideo*` curl на videoplayback URL, не на apex.
- [ ] Опционально: Playwright intercept как в `dpi-tester/youtube_test.py`.
- [ ] Починить hostfakesplit checker: `Session.request() unexpected keyword 'options'`.

### Domain denylist / fool filter (2026-07-31)

Stress `coverage.txt` (40 dom) × full matrix ≈ 312k jobs; часть доменов даёт
**0% PASS** или дублирует сигнал (apex TLS ≠ реальный трафик).

**Файл:** `presets/domains/denylist.txt` — FQDN + optional `# category` comment.
Загрузка в `_load_domains()` (`main.py`, `bs.py` preset path): по умолчанию
**выкидывать** совпадения, печатать summary `skipped N: googlevideo.com (videoplayback), …`.

**Флаг:** `--allow-unsafe-domains` — не фильтровать (осознанный mass-run / GP parity).

Стартовый denylist (кандидаты):

- `googlevideo.com` — needs videoplayback probe, not apex TLS
- `discord.media` — voice/media CDN, 0% на TLS apex
- static YouTube CDN: `i.ytimg.com`, `i9.ytimg.com`, `yt3/yt4.ggpht.com`,
  `yt3/yt4.googleusercontent.com`, `gstatic.com`, `gvt1.com`,
  `ytimg.l.google.com`, `ytstatic.l.google.com`, `youtube-ui.l.google.com`
- optional trim: Discord marketing mirrors (`discord.co`, `.design`, …) — оставить
  `discord.com` + `discord.gg` + `discordapp*` + `discordcdn.com`

Позже: `coverage-tcp.txt` (lean ~15 dom) как дефолт для `bs full`; полный
`coverage.txt` — только с `--allow-unsafe-domains`. Почистить `benchmark.txt`
(сейчас там `googlevideo` + `discord.media`).

- [ ] `presets/domains/denylist.txt` + loader filter
- [ ] CLI `--allow-unsafe-domains` на `bs full` / `scan` / `pair` (`--preset`)
- [ ] WARN при 0% PASS в DB после N runs (опционально)

### Speed: GP vs BS optimization (2026-07-31)

Bottleneck BS: `async_runner._nfqws2_daemon` sleep 2s + nfqws2 restart/job (~1.35 job/s
на stress 312k). GP: 100ms minsleep, multi-domain fan-out.

**Роли:** dpi-tester — provider profiling (Fryazino, custom lists, что вкл/выкл);
blockcheckS — community mass-scan; GP — production orchestrator + import shortlists.

#### Часть A — внедрять / использовать сейчас

- [ ] **A1** denylist + lean `coverage-tcp.txt` — 40→~15 dom, −62% jobs (см. denylist выше)
- [x] **A2** `scan_level=fast` — пропуск TTL/autottl expansions (уже в CLI)
- [x] **A3** `--resume` — skip записанных (strategy, domain) в DB
- [ ] **A4** GP multi-domain + `curl_parallelism` 4–10 — один nfqws2, parallel curl (не standard-discovery)
- [ ] **A5** *(dpi-tester)* `provider_summary.json` — custom lists, `TEST=custom`, сводка конфигов для GP/Keenetic; BS только shortlist import
- [x] **A6** GP `SCANLEVEL=quick|standard` — early-exit (уже в GP)
- [x] **A7** `--parallel 4` — **потолок**, не рычаг: iptables/NFQUEUE задыхается при 6–8 netns; масштабировать через B2, не ↑parallel; B7 prerequisite для >4
- [ ] **A8** короткие presets: `critical.txt`, `benchmark.txt`, `gp-verified.tls` для smoke
- [ ] **A9** timeout benchmark matrix — settle+curl на **0.5/1/1.5/2s**; preset `timeout-benchmark.tls`; families: `repeats=N`, `tcp_ts`, `disorder_after`, `ip_autottl`, `dupfake`, `discord_udp r6/r12` → таблица family→timeout → B11
- [ ] **A10** orchestrator flags: `--tls12-off`, `--tls13-off`, `--http3-off` (алиас `--no-quic`), `--http-off` — зеркало GP enable_*; фильтр фаз в `bs full`/`scan`/`pair`

#### Часть B — benchmark до production

- [ ] **B1** settle 2s → readiness poll (100–300ms), приоритет #1; согласовать с A9
- [ ] **B2** multi-domain fan-out — 1 nfqws2, `asyncio.gather` curl, `--curl-parallel N`; приоритет #2 (замена A7↑parallel)
- [ ] **B3** persistent nfqws2 per worker — высокий риск; после B7
- [ ] **B4** runtime family early-exit в `bs full` на первом PASS
- [ ] **B5** hybrid: BS shortlist export → GP multi-domain на роутере
- [ ] **B6** blockcheckw (Rust vmap) — fast scan reference, не drop-in voice/pair
- [ ] **B7** nftables vmap POC (GP/blockcheckw) — prerequisite parallel > 4
- [ ] **B8** batch DB writes (~5%)
- [ ] **B9** double Semaphore cleanup в `main.py`
- [ ] **B10** wire `get_fresh_url()` для googlevideo (см. googlevideo section)
- [ ] **B11** dynamic per-strategy settle+curl из результатов A9

**Порядок:** A1+A2+parallel4 → A5 dpi-tester → A10+A1 CLI → A9→B1→B11 → B2 → B4 → B7.

**Цель после B1+B2+A1 @ parallel=4:** ~6–12 job/s (7–14h на 312k), не через ↑parallel.

### Исследование вариативности blobs (2026-07-31)

Web/GitHub survey: Flowseal (22 `.bat`, ref-count), bol-van `files/fake` (~45),
nfqws2-keenetic discussions, GP custom lists. Источники:
[Flowseal/bin](https://github.com/Flowseal/zapret-discord-youtube/tree/main/bin),
[bol-van/fake](https://github.com/bol-van/zapret/tree/master/files/fake),
[nfqws2-keenetic #2](https://github.com/nfqws/nfqws2-keenetic/discussions/2).

**Топ по популярности (Flowseal refs):** `max_ru` TLS (64) → `google` TLS (57) →
`quic_google` (44) → `discord_udp` (43) → `stun` (25) → `game_udp` (21).
Эталон SIMPLE FAKE ALT2: dual `stun` + `max_ru` + `repeats=6:tcp_ts=-1000`.

**По сервисам:** YouTube/Discord TCP — `max_ru`/`google`+`stun`; voice UDP —
только `discord_udp` (1200B); QUIC — `quic_google`, `quic_dbank` (VK/social);
Telegram — blob вторичен (IP-block); built-in `fake_default_tls/http/quic` — GP baseline.

| Blob (alias) | Файл | Есть в `/opt/zapret2/blobs/` | Популярность | Use case | Добавить в BS? |
|---|---|:---:|:---:|---|:---:|
| `max_ru` | `tls_clienthello_max_ru.bin` | ✅ | ★★★★★ | General TLS, YouTube, Discord TCP | — |
| `google` | `tls_clienthello_www_google_com.bin` | ✅ | ★★★★★ | Google list, multisplit, Discord.media | — |
| `stun` | `stun.bin` | ✅ | ★★★★ | Dual-fake pair, UDP STUN | — |
| `discord_udp` | `discord_udp.bin` (Flowseal ACTIVE_DISCORD_UDP) | ✅ | ★★★★★ | Discord voice UDP 50000–50100 | — |
| `quic_google` | `quic_initial_www_google_com.bin` | ✅ | ★★★★ | YouTube QUIC, games UDP 443 | — |
| `quic_dbank` | `quic_initial_dbankcloud_ru.bin` | ✅ | ★★★ | VK/Instagram QUIC | — |
| `4pda` | `tls_clienthello_4pda_to.bin` | ✅ | ★★ | Alt TLS fingerprint (alt10) | — |
| `tls_default` | `tls_clienthello.bin` | ✅ | ★★★ | Keenetic generic baseline | каталог |
| `quic_default` | `quic_initial.bin` | ✅ | ★★★ | Keenetic generic QUIC | каталог |
| `fake_default_tls` | *(built-in)* | — | ★★★★ | GP/blockcheck2 без custom file | тесты есть |
| `fake_default_quic` | *(built-in)* | — | ★★★ | GP `list_quic.txt` | тесты есть |
| `fake_default_http` | *(built-in)* | — | ★★ | HTTP :80 families | тесты есть |
| `game_udp` | `ACTIVE_GAME_UDP.bin` | ❌ | ★★★ | Game filter UDP (21 Flowseal ref) | **да** |
| `stun2` | `stun2.bin` | ❌ | ★ | Alt STUN payload | опционально |
| `quic_4pda` | `quic_initial_4pda.to.bin` | ❌ | ★ | Alt QUIC fingerprint | опционально |
| `quic_tencent` | `quic_initial_tencent_com.bin` | ❌ | ★ | Gaming / Tencent QUIC | опционально |
| `quic_steam` | `quic_initial_steamcommunity_com.bin` | ❌ | ★ | Steam QUIC | опционально |
| `tls_vk` | `tls_clienthello_vk_com.bin` | в `files/fake` | ★★ | VK / RU whitelist TLS | **да** |
| `quic_vk` | `quic_initial_vk_com.bin` | в `files/fake` | ★★ | VK QUIC | **да** |
| `discord_ipdisc` | `discord-ip-discovery-with-port.bin` | в `files/fake` | ★★ | Official zapret 74B voice alt | сравнить |
| `quic_gv_kyber` | `quic_initial_*_googlevideo_com_kyber_*.bin` | в `files/fake` | ★ | YouTube CDN QUIC (не apex TLS) | после B10 |
| `wireguard_init` | `wireguard_initiation.bin` | в `files/fake` | ★ | WG / hysteria-adjacent UDP | low |
| `http_iana` | `http_iana_org.bin` | в `files/fake` | ★ | HTTP fake desync | low |
| `blob_zero` | `0x00000000` hex inline | — | ★★ | UDP fallback, multisplit | hex в matrix |

- [ ] Синхронизировать `presets/blobs/` manifest: что в wheel vs symlink на `/opt/zapret2/blobs/`
- [ ] Скопировать tier-1 gaps: `game_udp`, `tls_vk`, `quic_vk` из Flowseal/bol-van
- [ ] Matrix generator: alias map `google`→`tls_clienthello_www_google_com.bin` (уже в nfqws2 conf)
- [ ] Документировать built-in vs file blobs в `presets/README.md`

### Multi-blob chains (ТСПУ) — покрытие blockcheckS (2026-07-31)

Community: цепочки разных blobs подряд = несколько `--lua-desync=fake` (порядок важен) или
`fake`+`multisplit`/`multidisorder` с `seqovl_pattern=blob`. `repeats=N` — тот же blob N раз,
не разные blobs. Runtime BS: multi-line strategy → несколько `--lua-desync` ([`async_runner.py`](src/blockchecks/engine/async_runner.py) L234).

| Паттерн | Community ref | BS | Где / пробел |
|---|---|:---:|---|
| Dual fake `stun→max_ru` (+repeats, tcp_ts) | Flowseal ALT2 | ✅ | `StandardGenerator.multi_fake`, `--generate fake_multi`, `flowseal` |
| Dual fake пары (stun/google/max_ru/4pda) | Flowseal | ✅ | 4 ordered pairs; **нет reverse** (max_ru→stun) |
| `fake` + `multisplit` + `seqovl_pattern=blob` | ALT11, PR #10293 | ⚠️ | `configs/alt11*`; `fake_faked` только seqovl=1; **нет** fake blob ≠ seqovl blob в standard |
| Triple: fake + multisplit + hostfakesplit | ALT12 | ⚠️ | `configs/alt12*` only; **не в matrix generator** |
| `fake` + `hostfakesplit` | fake_hostfake | ✅ | `StandardGenerator.fake_hostfake` |
| `multisplit` seqovl 568–681 + blob | Flowseal FAKE TLS AUTO | ✅ | `multisplit` family, `FlowsealGenerator` |
| `fake` + `multidisorder` | sonicdpi #3, zapret default | ❌ | `configs/fake_tls_auto__fake_multidisorder.conf`; **нет generator** |
| `fakedsplit` / `fakeddisorder` | sonicdpi #4 | ❌ | `FakedTcpGenerator` = multisplit seqovl=1, **не fakedsplit** |
| `dupfake` (multi-blob один вызов) | GP/Keenetic custom Lua | ❌ | **нет** в matrix / presets |
| 3+ blobs в цепочке | редко | ❌ | только пары |
| HTTP fake + TLS fake (один профиль) | Flowseal `--fake-http`+`--fake-tls` | ❌ | **нет** generator |
| UDP dual-blob (quic_dbank на discord+stun L7) | Flowseal UDP profile | ❌ | UDP = single `discord_udp` / `quic_*` |
| `circular` rotate strategies | zapret2-auto | ⚠️ | export [`conf_builder`](src/blockchecks/engine/conf_builder.py); **не scan** |
| `tls_fake_flood` | keenetic discussion #82 | ❌ | **нет** |
| `flowseal` source в `bs full` default | — | ⚠️ | default `standard,custom,configs`; flowseal — явный `--tcp-sources` |
| Порядок blobs A→B vs B→A | эмпирика ТСПУ | ⚠️ | fixed pairs; **benchmark order matrix отсутствует** |
| Per-blob разный `repeats` | часть Flowseal bats | ❌ | multi_fake: одинаковый repeats на оба blob |

**Итог:** ядро ТСПУ-паттерна (dual fake stun+max_ru) **покрыто**. Пробелы — комбо-desync
(multidisorder/fakedsplit/dupfake), полные Flowseal triple chains, HTTP+TLS dual fake, UDP
multi-blob, order sensitivity.

- [ ] **M1** `fake_multisplit` family: `fake:blob=X` + `multisplit:seqovl=664:seqovl_pattern=Y` (X≠Y), как ALT11
- [ ] **M2** `fake_multisplit_hostfake` triple chain (ALT12 pattern) в StandardGenerator
- [ ] **M3** `multidisorder` + `fakedsplit`/`fakeddisorder` families (sonicdpi tier-1)
- [ ] **M4** `dupfake` preset / GP custom list import
- [ ] **M5** blob order matrix: reverse pairs + 3-blob permutations subset
- [ ] **M6** HTTP+TLS dual-fake generator (`fake_default_http` + TLS blob)
- [ ] **M7** UDP multi-blob (discord L7: quic_dbank на stun+discord)
- [ ] **M8** `flowseal` в default `bs full --tcp-sources` или merge combos в `standard`
- [ ] **M9** rename/fix `FakedTcpGenerator` → real `fakedsplit` или deprecate
- [ ] **M10** `circular` в optional scan mode (rotate blob combos on fail)

### ML: sklearn Random Forest ranker (Breiman / scikit-learn)

Offline ranker поверх `state.db` / GP SQLite — **не замена curl verify**, а сужение 18k → top-K.

**Постановка B (рекомендуемая):** `(domain_features + strategy_features) → P(PASS)`;
inference: rank top-20 → BS verify. Train только на BS curl_cffi labels.

**sklearn:** `RandomForestClassifier(n_estimators=200, max_features="sqrt", class_weight="balanced", oob_score=True)`.
Валидация: `GroupKFold` по domain (anti-leakage). Метрика: **Recall@K**, не accuracy.

Альтернатива на больших данных: `HistGradientBoostingClassifier` (быстрее tabular).

- [ ] **ML1** optional-dep `scikit-learn` в `[project.optional-dependencies] ml`
- [ ] **ML2** `scripts/train_strategy_ranker.py` — export `state.db` → parquet → fit → `model.pkl`
- [ ] **ML3** feature parser: domain (TLD, cdn_class) + strategy (family/blob/repeats/fooling из `strategy_safety`-подобного парсера)
- [ ] **ML4** BS integration: `--ranker model.pkl` → top-K candidates вместо full matrix
- [ ] **ML5** retrain policy: после mass scan / drift (blob burn) / provider change

**Риски:** label noise GP≠BS, нестационарность ТСПУ, cold start → fallback brute-force.

### ML: иерархическое облако параметров (progressive drill-down)

Альтернатива full matrix: **дерево осей** вместо декартова произведения. Домен проходит
уровни — на каждом добавляется один слой параметров; при PASS на уровне N можно углубляться
или остановиться (early-exit).

```text
L0: desync=fake                    → FAIL
L1: + ip_autottl=-2                → FAIL
L2: + blob=tls_clienthello_max_ru  → PASS  → stop / optional L3 (repeats, tcp_ts, …)
```

Похоже на GP `SCANLEVEL=standard` (break family), но **внутри одной ветки** — наращивание
параметров, а не перебор готовых строк из `list_https_tls12.txt`.

| | Full matrix (сейчас) | Hierarchical cloud | RF ranker |
|---|---|---|---|
| Тестов/домен | тысячи | десятки–сотни | K verify после rank |
| Ловит combo fake+blob+tcp_ts | ✅ | ⚠️ если порядок осей верный | ✅ если в train |
| Скорость | медленно | **быстро** при удачном дереве | быстрый inference |
| Риск | нет | **greedy miss** — combo без промежуточных уровней | stale model |

**ML для иерархии (не RF напрямую):**
- **Learned policy tree** — какую ось раскрывать следующей (contextual bandit / small RL)
- **Provider template** — dpi-tester отдаёт порядок осей для Fryazino: fake → blob → repeats → tcp_ts
- **Beam search** — держать top-B частичных конфигов, не одну greedy-ветку
- **Monotonic priors** — blob почти всегда после fake; autottl — optional branch

**Связь с RF:** RF ранжирует *готовые* стратегии; hierarchy *строит* стратегию по слоям.
Гибрид: hierarchy для cold start → RF для уточнения blob/fooling на известном family.

- [ ] **H1** спецификация «облака параметров»: оси (desync, blob, fooling, ttl, repeats, split…)
- [ ] **H2** `ProgressiveStrategyBuilder` — API: `add_axis()` → partial conf → test → branch
- [ ] **H3** default tree order из GP `family_rank` + Fryazino facts (fake→blob→repeats=6→tcp_ts)
- [ ] **H4** beam width B=3 — не только greedy, чтобы не пропустить fake+blob без autottl
- [ ] **H5** интеграция в `bs scan --progressive` / `scan_level=progressive`
- [ ] **H6** лог partial results в DB (`partial_results`: level, axis, status) для ML train
- [ ] **H7** learned axis order: contextual bandit или RF на «какая ось дала gain на этом domain_class»
- [ ] **H8** provider template export из dpi-tester (`provider_summary.json` → axis order)
- [ ] **H9** benchmark vs full matrix на 10 доменах: tests count, Recall(best strategy found)
- [ ] **H10** fallback: если progressive 0 PASS → expand beam / RF top-K / full family scan

- [ ] `ipfrag_udp` / `ipfrag_tcp` (`send:` dual-call)
- [ ] TTL > 255, `repeats=4` generator

### Packaging tech debt (закрыто)

- [x] scan `--auto-discover` semantics
- [x] untrack `state.db`
- [x] nfqws2 DEVNULL stderr; pair coexist; queue-bypass; THROTTLED; ECH
- [x] UserMatrix UDP skip on TCP; protocol/preset/`-M`; blob/seqovl runner
- [x] Matrix protocol-gate + `scan_level=single`

---

## Research notes (merged from research.md)

### Почему не blockcheck.sh

| Проблема | Влияние |
|----------|---------|
| restart nfqws2 на каждую стратегию | 1000+ spawn/kill |
| Curl+OpenSSL JA4 `t13d0202` | DPI режет сам OpenSSL → ложные FAIL |
| Только sequential | 2s × N стратегий |
| Нет Discord voice UDP | voice не подбирается |
| 5 firewall backends | избыток для Linux-only |

Главный выигрыш blockcheckS: **netns pool + parallel** и **браузерный TLS**.
Идеал research (reconfigure без restart) частично вытеснен моделью
«свой nfqws2 на netns» — проще изоляция, тот же порядок ускорения.

### Сравнение

| | blockcheck.sh | blockcheckw | **blockcheckS** |
|---|:---:|:---:|:---:|
| Язык | Bash | Rust | Python 3.10+ |
| UDP voice | ❌ | ❌ | ✅ STUN + IP Discovery |
| TLS FP | OpenSSL | rustls | **curl_cffi BoringSSL** |
| Parallel | ❌ | tokio | asyncio + NetNsPool |
| Flowseal blobs | ❌ | ❌ | ✅ |
| Conf export | text | JSON | keenetic + raw nfqws2 |
| GP | custom TEST | ❌ | `state.db` (+ future import) |

### Ключевые решения (актуальные)

1. Linux-only: iptables NFQUEUE (+ опционально nftables later).
2. curl_cffi — обязателен для «не врёт».
3. Dual nfqws2 (TCP q200 + UDP q201) для voice coexist.
4. SQLite checkpoints / resume; fingerprint на pair matrix.
5. Discover: DNS finland* + Maks list + dual STUN probe; concurrency=4.
6. Export: coverage_score → `:strategy=1..N` в dual conf.

### Устаревший layout из research (не использовать)

Ранний набросок (`engine.py`, `fw.py`, `strategies/standard/`) **не актуален**.
Канон: `src/blockchecks/` — см. [package.md](package.md).

---

## Docs map

| Файл | Роль |
|------|------|
| [guide.md](guide.md) | Установка и CLI |
| [package.md](package.md) | Структура пакета / аудит |
| [todo.md](todo.md) | Этот roadmap |
| `presets/README.md` | Domains / strategies / `bs full` |
| Root `README.md` | Quick start |
| Root `research.md`, `GOALS.md` | stubs → сюда |
