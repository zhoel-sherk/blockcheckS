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

- [ ] `ipfrag_udp` / `ipfrag_tcp` (`send:` dual-call)
- [ ] `multidisorder`
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
