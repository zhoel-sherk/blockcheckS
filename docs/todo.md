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

---

## Статус фаз (факт 2026-08)

| Phase | Тема | Статус | Приоритет | Ключевой бэклог |
|-------|------|--------|-----------|----------------|
| **1** | Single TCP (`bs tcp`, configs, content check) | ✅ | — | — |
| **2** | UDP voice STUN / dual nfqws2 | ✅ | P2 | multi-endpoint pair (все discover EP) |
| **3** | Pair matrix + checkpoint/resume + discover | ✅ | P2 | `--full-voice` gateway WS probe |
| **4** | Parallel asyncio + NetNsPool | ✅ | P1 | B1 settle poll, B2 fan-out, B7 vmap |
| **5** | GP / dpi-tester bridge | 📋 partial | P1 | A5 provider_summary, B5 hybrid, GP import |
| **6** | Export keenetic + raw (`bs full` / `bc-nfconf`) | ✅ | P2 | BC2-7 COMMON intersection ✅ |
| **7** | QUIC / HTTP3 first-class | 🔄 partial | P1 | BC2-10 ✅; `ipfrag_udp`/`ipfrag_tcp` |
| **8** | HTTP :80 families | 🔄 partial | P2 | BC2-9 ✅; M6 HTTP+TLS dual-fake |
| **9** | Secure DNS + blockcheck2 preflight | ✅ | **P0** | SD ✅; BC2-1..8,11,12 ✅ |
| **10** | Matrix coverage & blobs | 🔄 | P1 | M1–M10, ~80% zapret2 / ~95% flowseal |
| **11** | Speed / throughput | 🔄 | P1 | A1–A10, B1–B11 |
| **12** | Smart scan (ML / hierarchy / AQ) | 📋 | P3 | ML1–5, H1–10, AQ1–8 |
| **13** | Developer onboarding (docs, hygiene, modularity) | ✅ | P1 | ONB-1..ONB-13 |

**Легенда приоритетов:** P0 = без этого mass-scan ненадёжен; P1 = production
parity / скорость; P2 = полнота протоколов и export; P3 = оптимизация после
базового покрытия.

**Порядок внедрения (сквозной):** Phase 9 (SD) → Phase 11 A1 → Phase 11
B1→B11 → Phase 11 B2 → Phase 10 M* → Phase 7/8 → Phase 12.
**Phase 13** (onboarding) — параллельно Phase 9, не блокирует SD.

### Дубликаты (одна задача — несколько ID)

| Задача | Канонический ID | Также упоминается как |
|--------|-----------------|------------------------|
| DoH pre-resolve на все домены | **SD1–SD3** | BC2 C1, BC2 C2 |
| Denylist + lean coverage | **A1** | Domain denylist section |
| Wire googlevideo videoplayback | **GV-1** | B10 |
| Multi-domain curl fan-out | **B2** | A4 (GP mirror), AQ5 |
| HTTP :80 фаза | **BC2-9** | Phase 8 |
| QUIC HTTP/3 curl | **BC2-10** | Phase 7 |
| Family early-exit | **B4** | BC2-6, A6 (GP), AQ (online) |
| Orchestrator protocol flags | **A10** | BC2-9/10 enable_* mirror |
| Provider profiling | **A5** | H8, dpi-tester (не BS runtime) |
| Blob manifest sync | **BLOB-1** | `presets/blobs/` wheel vs symlink |
| configs/ wheel policy | **ONB-7** | editable install; ≠ BLOB-1 |

---

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

---

## Ближайший бэклог (сводка по важности)

### P0 — честность тестов (Phase 9)

1. ~~**Secure DNS** — DoH pre-resolve на **все** домены (SD1–SD8).~~ ✅
2. ~~**Preflight** — IP-block cross-test, unblocked baseline (BC2-1..BC2-3).~~ ✅ BC2-1..3,5,11

### P1 — скорость и покрытие (Phase 4, 10, 11)

3. **~80% сценариев bol-van/zapret2** в matrix + checkers (Phase 10).
4. **~95% flowseal-like** (перевод + пересечения zapret2 ∩ flowseal).
5. **matrix_generator** — registries, dedup, PASS priority, стабильный fingerprint.
6. **Speed** — A1 denylist, B1 settle poll, B2 multi-domain fan-out.
7. **googlevideo** — videoplayback probe (GV-1), не apex TLS.
8. **[unblock-pro](https://github.com/by-sonic/unblock-pro)** — переносимые эвристики.

### P2 — протоколы и интеграция (Phase 5–8)

9. ~~nfqws2-keenetic export~~ ✅ (`conf_builder` / `bc-nfconf`).
10. **multi-endpoint** pair matrix по всем discover EP (Phase 2).
11. **QUIC/HTTP3** + **HTTP :80** first-class (BC2-9, BC2-10).
12. **GP hybrid** — BS shortlist → GP multi-domain (B5).

### P3 — smart scan (Phase 12)

13. **ML ranker** (ML1–5), **hierarchical cloud** (H1–10), **adaptive queue** (AQ1–8).

### Инфраструктура

14. ~~**configs/** package policy (editable install) → **ONB-7** (≠ BLOB-1 blobs).~~ ✅

---

# Phase 9 — Secure DNS + blockcheck2 preflight (P0)

> Критично для **любого** провайдера: hijack-картина разная; DoH — на все домены.

### Secure DNS: DoH/DoT (SD)

**Проблема:** `NetNsPool` пишет `nameserver 8.8.8.8` в
`/etc/netns/{name}/resolv.conf`; `async_runner` вызывает
`curl_cffi.get("https://" + domain)` — DNS внутри netns идёт **UDP к
публичному DNS**, без DoH. На Fryazino провайдер **перехватывает UDP-запросы
к 8.8.8.8/1.1.1.1** (transparent DNS proxy), отдавая подменённые A-записи.
`blockcheck2.sh` это знает: `check_dns_` → `DNS_IS_SPOOFED` → auto `SECURE_DNS=1`
→ `doh_find_working` → `mdig_resolve` + `curl_with_subst_ip`. **SD1–SD8 ✅**
(2026-08-01): `dns_secure.py`, DoH pre-resolve + `CURLOPT_RESOLVE`, startup
audit, CLI flags, `state.db` metrics. Проверено на Fryazino: `cloudflare-ech.com`
/ `signal.org` sinkhole `8.47.x` → abort; `--allow-dns-hijack` → curl на DoH IP.

**Живой замер (2026-08-01, Xeon / Fryazino, dpi-tester `dns_checker.py`):**

| Домен (coverage) | UDP @8.8.8.8 | DoH | Вердикт |
|------------------|--------------|-----|---------|
| discord.com | 162.159.x (CF) | 162.159.x | ✅ OK |
| speedtest.net | 151.101.x | 151.101.x | ✅ OK |
| rutracker.org | 104.21.x / 172.67.x | совпадает | ✅ OK |
| youtube.com | 142.251.x | 64.233.x | ⚠️ другой Google anycast |
| googlevideo.com | 142.251.x | 173.194.x | ⚠️ другой Google anycast |
| google.com | 142.251.x | 192.178.x | ⚠️ другой Google anycast |
| cloudflare-ech.com | **8.47.69.6** (sinkhole) | 104.18.x | ❌ **явный hijack** |

Дополнительно: `signal.org` — UDP sinkhole `8.47.x`, DoH `104.18.x` (не в
coverage, но тот же паттерн).

**Насколько влияет (любой провайдер):**

| Сценарий | Эффект |
|----------|--------|
| UDP=DoH (честный резолв) | Тест валиден — curl идёт на реальный CDN |
| Разные IP, оба CDN (Google anycast) | Стратегия может работать/не работать на другом POP — непредсказуемо |
| Sinkhole IP (`8.47.x` и аналоги) | **Критический** — curl на заглушку → ложные FAIL |
| Сравнение с GP/blockcheck2 | Они при hijack → DoH; BS без DoH → **несопоставимы** |
| Voice discover (`getaddrinfo` на host) | host resolver ≠ netns 8.8.8.8 — отдельный риск |

**Эталон (blockcheck2):** `DOH_SERVERS` (CF, Google, Quad9, AdGuard, Yandex) →
auto-pick → `mdig` + `curl --connect-to ::host:ip:` (SNI сохраняется).
Переменные: `SECURE_DNS=0|1`, `DOH_SERVER`, `CURL_MAX_TIME_DOH`.

**dpi-tester:** `src/dns_checker.py` — UDP vs DoH cross-check; режим `--dns-check`
в `start.sh`. Роль: **provider profiling** (A5), не runtime BS.

**Целевой дизайн:**

```text
bs full startup
  → dns_audit(all_domains_in_run)   # UDP vs DoH per domain
  → doh = pick_working(DOH_SERVERS) # default on (--secure-dns)
  → per job (every domain):
       ip = doh_resolve(domain)
       curl: CURLOPT_RESOLVE host:443:ip  (SNI = hostname)
```

- [x] **SD1** `checkers/dns_secure.py` — порт `dpi-tester/dns_checker.py`
- [x] **SD2** `doh_resolve(domain) -> list[ip]` — curl_cffi DoH JSON + binary wire fallback
- [x] **SD3** `async_runner` / `test_runner`: pre-resolve + `CURLOPT_RESOLVE`; SNI = hostname
- [x] **SD4** startup audit в `bs full` / `bs scan`: таблица tampered; abort без `--allow-dns-hijack`
- [x] **SD5** CLI: `--secure-dns` (default on), `--doh-server URL`, `--skip-dns-audit`
- [x] **SD6** кэш DoH на batch run (`DNSCACHE_*` как blockcheck2)
- [x] **SD7** netns: pre-resolve достаточно (DoH stub в netns — optional/heavy)
- [x] **SD8** метрики в `state.db`: `dns_verdict`, `resolved_ip`, `doh_server`

### blockcheck2 parity (BC2)

Аудит `/opt/zapret2/blockcheck2.sh` + `blockcheck2.d/` vs blockcheckS
(2026-08-01). **Где BS сильнее:** curl_cffi/JA4, netns pool, content/throttle,
voice UDP, async parallel, resume/state.db, MatrixGenerator, keenetic export.

#### CRITICAL

| # | BC2 feature | BS сейчас | Задача |
|---|-------------|-----------|--------|
| C1 | DoH pre-resolve на все домены | ✅ DoH + audit | ~~SD1–SD3~~ |
| C2 | DNS spoof detection | ✅ startup audit | ~~SD1, SD4~~ |
| C3 | IP-block cross-test | ✅ `ip_block.py` | ~~BC2-1~~ |
| C4 | UNBLOCKED_DOM baseline | ✅ startup preflight | ~~BC2-2~~ |

#### HIGH

| # | BC2 feature | Задача |
|---|-------------|--------|
| H1 | Port block pre-check (`nc -z`) | **BC2-3** |
| H2 | REPEATS (N curl на стратегию) | **BC2-4** |
| H3 | Prolog без bypass | **BC2-5** |
| H4 | SCANLEVEL + need_* chain | **BC2-6** (= B4 частично) |
| H5 | COMMON intersection | **BC2-7** |
| H6 | wssize fallback TLS1.2 | **BC2-8** |
| H7 | HTTP :80 фаза | **BC2-9** → Phase 8 |
| H8 | QUIC/HTTP3 curl | **BC2-10** → Phase 7 |
| H9 | zapret already running warn | **BC2-11** |
| H10 | HTTP redirect detection | **BC2-12** |

#### MEDIUM / LOW

- **BC2-M1** `PKTWS_EXTRA_PRE/POST` — глобальные доп.параметры
- **BC2-M2** IPv6 dual-stack (`IPVS=4|6|46`)
- **BC2-M3** VM/NAT warning (`check_virt`)
- **BC2-M4** `SIMULATE=1` для отладки без curl
- **BC2-M5** Standard families: oob, syndata, http-basic — gaps в generator
- **BC2-L1** Кроссплатформенность (FreeBSD/Win) — не цель BS

#### Main flow BC2 (эталон)

```text
check_system → check_already → check_prerequisites
  → check_dns (spoof? → SECURE_DNS=1 → doh_find_working)
  → for each domain:
      port block nc → prolog (no bypass) → IP-block cross-test
      → pktws + test_runner(standard|custom)
  → SUMMARY + COMMON intersection
```

- [x] **BC2-1** `checkers/ip_block.py`: cross-test blocked ↔ `UNBLOCKED_DOM` IP
- [x] **BC2-2** preflight baseline: auto unblocked check (`--unblocked-dom`)
- [x] **BC2-3** port block probe на все resolved IP
- [x] **BC2-4** `--repeats N` + `--parallel-repeats`
- [x] **BC2-5** prolog curl без nfqws2; skip domain если уже OK (`--force` override)
- [x] **BC2-6** полная цепочка `need_*` между standard families
- [x] **BC2-7** `bs full` export: COMMON strategies (intersection all domains)
- [x] **BC2-8** wssize retry в tls12 checker
- [x] **BC2-9** HTTP :80 standard generator + фаза в `bs full`
- [x] **BC2-10** QUIC: curl HTTP/3 + `--quic-timeout` *(Phase 7)*
- [x] **BC2-11** detect running nfqws2 на host, warn/abort
- [x] **BC2-12** redirect-to-blockpage detector (curl code 254 pattern)

---

# Phase 7 — QUIC / HTTP3 (P1)

Сейчас: генерация `standard_quic` в matrix; в `bs full` — **UDP probe на :443**,
не HTTP/3 curl; export подставляет дефолт `fake:blob=quic_initial:repeats=11` при 0 PASS.

- [x] **BC2-10** curl HTTP/3 + `--quic-timeout` (канон; ≠ `--udp-timeout`)
- [ ] `ipfrag_udp` / `ipfrag_tcp` (`send:` dual-call) — generator gap
- [ ] **M7** UDP multi-blob (discord L7: quic_dbank на stun+discord) *(Phase 10)*

---

# Phase 8 — HTTP :80 families (P2)

Сейчас: `CustomListGenerator` читает `list_http.txt`; только в `bs tcp --protocol http`;
нет standard HTTP family; `bs full` — только tls12/tls13.

- [x] **BC2-9** HTTP :80 standard generator + фаза в `bs full`
- [ ] **M6** HTTP+TLS dual-fake generator (`fake_default_http` + TLS blob) *(Phase 10)*
- [ ] **A10** `--http-off` — зеркало GP `ENABLE_HTTP` *(Phase 11)* ✅

---

# Phase 10 — Matrix coverage & blobs (P1)

### googlevideo CDN probe (2026-07-30) — Phase 7/10

Модуль есть, в stress-test **не используется**:

- `checkers/youtube_url.py` — `get_fresh_url()` via `yt-dlp` → signed
  `*.googlevideo.com/videoplayback?…`, кэш `logs/bs_gv_url_cache.json` (3h).
- `async_runner` для `googlevideo*`: ECH off + `Range: bytes=0-17407` + rate bands
  для 206; curl на **videoplayback URL** (`get_fresh_url()`), не на apex.
- `get_fresh_url()` вызывается из `_run_tcp_check` и `_run_tcp_check_multi` (GV-1).

Факты Fryazino (без VPN):

- [x] `yt-dlp` URL — **OK** (~15s, youtube metadata) *(проверено)*
- [x] curl на корень / videoplayback **без nfqws2** — timeout (DPI) *(проверено)*
- [x] Chunk probe **реален без VPN**, но **нужен nfqws2** + YouTube-стратегия
  (ориентир: `hostfakesplit:disorder_after:…`, dpi-tester 27–37 chunks) *(проверено)*

GP vs blockcheckS на `googlevideo.com`: GP **12** success links (`http_req` +
hostfakesplit); blockcheckS stress **0 PASS** (TLS на корень домена).

**Задачи:**

- [x] **GV-1** Wire `get_fresh_url()` в `async_runner` / sync runner: при
  `googlevideo*` curl на videoplayback URL, не на apex *(= B10)*
- [ ] **GV-2** Опционально: Playwright intercept как в `dpi-tester/youtube_test.py`
- [x] **GV-3** Починить hostfakesplit checker: `Session.request() unexpected keyword 'options'`
  — вынесено в `checkers/curl_probe.py` + `_curl_probe_worker`; ECH только через `setopt`
- [x] **GV-4** После GV-1: убрать `googlevideo.com` из denylist / вернуть в lean coverage
- [ ] **GV-5** `quic_gv_kyber` blob тесты — после videoplayback probe (см. blob table)

### Domain denylist / fool filter (2026-07-31) — Phase 11 A1

Stress `coverage.txt` (40 dom) × full matrix ≈ 312k jobs; часть доменов даёт
**0% PASS** или дублирует сигнал (apex TLS ≠ реальный трафик).

**Решение (2026-08):** static YouTube CDN **исключать** из дефолтного mass-scan — дублируют
SNI-сигнал `youtube.com`; apex TLS на `i.ytimg.com` / `gstatic.com` не отражает реальный
трафик. Оставить в lean coverage: `youtube.com`, `youtu.be`, `googleapis.com`,
`youtubei.googleapis.com`. Полный список — `coverage.txt` + `--allow-unsafe-domains`.

**Флаг:** `--allow-unsafe-domains` — не фильтровать (осознанный mass-run / GP parity).

Стартовый denylist (кандидаты):

- `googlevideo.com` — videoplayback probe (GV-1), в lean coverage (GV-4) ✅
- `discord.media` — voice/media CDN, 0% на TLS apex
- static YouTube CDN: `i.ytimg.com`, `i9.ytimg.com`, `yt3/yt4.ggpht.com`,
  `yt3/yt4.googleusercontent.com`, `gstatic.com`, `gvt1.com`,
  `ytimg.l.google.com`, `ytstatic.l.google.com`, `youtube-ui.l.google.com`
- optional trim: Discord marketing mirrors (`discord.co`, `.design`, …) — оставить
  `discord.com` + `discord.gg` + `discordapp*` + `discordcdn.com`

Позже: `coverage-tcp.txt` (lean ~15 dom) как дефолт для `bs full`; полный
`coverage.txt` — только с `--allow-unsafe-domains`. Почистить `benchmark.txt`
(сейчас там `googlevideo` + `discord.media`).

- [x] **A1a** `presets/domains/denylist.txt` + loader filter *(= A1)*
- [x] **A1b** CLI `--allow-unsafe-domains` на `bs full` / `scan` / `pair`
- [x] **A1c** `coverage-tcp.txt` lean preset (~15 dom)
- [x] **A1d** WARN при 0% PASS в DB после N runs (опционально)

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
| `quic_gv_kyber` | `quic_initial_*_googlevideo_com_kyber_*.bin` | в `files/fake` | ★ | YouTube CDN QUIC (не apex TLS) | после GV-1 |
| `wireguard_init` | `wireguard_initiation.bin` | в `files/fake` | ★ | WG / hysteria-adjacent UDP | low |
| `http_iana` | `http_iana_org.bin` | в `files/fake` | ★ | HTTP fake desync | low |
| `blob_zero` | `0x00000000` hex inline | — | ★★ | UDP fallback, multisplit | hex в matrix |

- [ ] **BLOB-1** Синхронизировать `presets/blobs/` manifest: wheel vs symlink `/opt/zapret2/blobs/`
- [ ] **BLOB-2** Скопировать tier-1 gaps: `game_udp`, `tls_vk`, `quic_vk` из Flowseal/bol-van
- [ ] **BLOB-3** Matrix generator: alias map `google`→`tls_clienthello_www_google_com.bin`
- [ ] **BLOB-4** Документировать built-in vs file blobs в `presets/README.md`

### Multi-blob chains (ТСПУ) — покрытие blockcheckS (2026-07-31)

Community: цепочки разных blobs подряд = несколько `--lua-desync=fake` (порядок важен) или
`fake`+`multisplit`/`multidisorder` с `seqovl_pattern=blob`. `repeats=N` — тот же blob N раз,
не разные blobs. Runtime BS: multi-line strategy → несколько `--lua-desync` ([`async_runner.py`](src/blockchecks/engine/async_runner.py) L234).

| Паттерн | Community ref | BS | Где / пробел |
|---|---|:---:|---|
| Dual fake `stun→max_ru` (+repeats, tcp_ts) | Flowseal ALT2 | ✅ | `StandardGenerator.multi_fake`, `--generate fake_multi`, `flowseal` |
| Dual fake пары (stun/google/max_ru/4pda) | Flowseal | ✅ | 4 ordered pairs; **нет reverse** (max_ru→stun) |
| `fake` + `multisplit` + `seqovl_pattern=blob` | ALT11, PR #10293 | ⚠️ | `configs/alt11*`; `fake_faked` только seqovl=1; **нет** fake blob ≠ seqovl blob |
| Triple: fake + multisplit + hostfakesplit | ALT12 | ⚠️ | `configs/alt12*` only; **не в matrix generator** |
| `fake` + `hostfakesplit` | fake_hostfake | ✅ | `StandardGenerator.fake_hostfake` |
| `multisplit` seqovl 568–681 + blob | Flowseal FAKE TLS AUTO | ✅ | `multisplit` family, `FlowsealGenerator` |
| `fake` + `multidisorder` | sonicdpi #3, zapret default | ❌ | `configs/fake_tls_auto__fake_multidisorder.conf`; **нет generator** |
| `fakedsplit` / `fakeddisorder` | sonicdpi #4 | ❌ | `FakedTcpGenerator` = multisplit seqovl=1, **не fakedsplit** |
| `dupfake` (multi-blob один вызов) | GP/Keenetic custom Lua | ❌ | **нет** в matrix / presets |
| 3+ blobs в цепочке | редко | ❌ | только пары |
| HTTP fake + TLS fake (один профиль) | Flowseal `--fake-http`+`--fake-tls` | ❌ | **нет** generator → M6 |
| UDP dual-blob (quic_dbank на discord+stun L7) | Flowseal UDP profile | ❌ | UDP = single blob → M7 |
| `circular` rotate strategies | zapret2-auto | ⚠️ | export [`conf_builder`](src/blockchecks/engine/conf_builder.py); **не scan** |
| `tls_fake_flood` | keenetic discussion #82 | ❌ | **нет** |
| `flowseal` source в `bs full` default | — | ⚠️ | default `standard,custom,configs`; flowseal — явный `--tcp-sources` |
| Порядок blobs A→B vs B→A | эмпирика ТСПУ | ⚠️ | fixed pairs; **benchmark order matrix отсутствует** |
| Per-blob разный `repeats` | часть Flowseal bats | ❌ | multi_fake: одинаковый repeats на оба blob |

**Итог:** ядро ТСПУ (dual fake stun+max_ru) **покрыто**. Пробелы — комбо-desync,
multidisorder/fakedsplit/dupfake, triple chains, HTTP+TLS dual fake, UDP multi-blob.

- [ ] **M1** `fake_multisplit` family: `fake:blob=X` + `multisplit:seqovl=664:seqovl_pattern=Y` (X≠Y)
- [ ] **M2** `fake_multisplit_hostfake` triple chain (ALT12) в StandardGenerator
- [ ] **M3** `multidisorder` + `fakedsplit`/`fakeddisorder` families (sonicdpi tier-1)
- [ ] **M4** `dupfake` preset / GP custom list import
- [ ] **M5** blob order matrix: reverse pairs + 3-blob permutations subset
- [ ] **M6** HTTP+TLS dual-fake generator → Phase 8
- [ ] **M7** UDP multi-blob (discord L7: quic_dbank на stun+discord) → Phase 7
- [ ] **M8** `flowseal` в default `bs full --tcp-sources` или merge combos в `standard`
- [ ] **M9** rename/fix `FakedTcpGenerator` → real `fakedsplit` или deprecate
- [ ] **M10** `circular` в optional scan mode (rotate blob combos on fail)
- [ ] TTL > 255, `repeats=4` generator — matrix gap

---

# Phase 11 — Speed / throughput (P1)

Bottleneck BS: `async_runner._nfqws2_daemon` sleep 2s + nfqws2 restart/job (~1.35 job/s
на stress 312k). GP: 100ms minsleep, multi-domain fan-out.

**Роли:** dpi-tester — provider profiling (Fryazino, custom lists); blockcheckS —
community mass-scan; GP — production orchestrator + import shortlists.

### Часть A — внедрять / использовать сейчас

- [x] **A1** denylist + lean `coverage-tcp.txt` — 40→~15 dom, −62% jobs → A1a–A1d
- [x] **A2** `scan_level=fast` — пропуск TTL/autottl expansions
- [x] **A3** `--resume` — skip записанных (strategy, domain) в DB
- [ ] **A4** GP multi-domain + `curl_parallelism` 4–10 — один nfqws2, parallel curl *(GP-side; BS = B2)*
- [ ] **A5** *(dpi-tester)* `provider_summary.json` — custom lists, `TEST=custom`; BS shortlist import
- [x] **A6** GP `SCANLEVEL=quick|standard` — early-exit (уже в GP; BS = B4, BC2-6)
- [x] **A7** `--parallel 4` — **потолок**; масштабировать через B2, не ↑parallel; B7 для >4
- [x] **A8** короткие presets: `critical.txt`, `benchmark.txt`, `gp-verified.tls` для smoke
- [x] **A9** timeout benchmark matrix — settle+curl на **0.5/1/1.5/2s**; preset `timeout-benchmark.tls`
- [x] **A10** orchestrator flags: `--tls12-off`, `--tls13-off`, `--http3-off`, `--http-off`

### Часть B — benchmark до production

- [x] **B1** settle 2s → readiness poll (100–300ms); согласовать с A9
- [x] **B2** multi-domain fan-out — 1 nfqws2, `asyncio.gather` curl, `--curl-parallel N`
- [ ] **B3** persistent nfqws2 per worker — высокий риск; после B7
- [x] **B4** runtime family early-exit в `bs full` на первом PASS *(= BC2-6)*
- [ ] **B5** hybrid: BS shortlist export → GP multi-domain на роутере
- [ ] **B6** blockcheckw (Rust vmap) — fast scan reference, не drop-in voice/pair
- [ ] **B7** nftables vmap POC — prerequisite parallel > 4
- [ ] **B8** batch DB writes (~5%)
- [x] **B9** double Semaphore cleanup в `main.py`
- [x] **B10** wire `get_fresh_url()` для googlevideo → **GV-1**
- [x] **B11** dynamic per-strategy settle+curl из результатов A9

**Порядок:** A1+A2+parallel4 → A5 dpi-tester → A10+A1 CLI → A9→B1→B11 → B2 → B4 → B7.

**B2 риски (2026-08):**
- **Opt-in:** `--curl-parallel 1` по умолчанию; fan-out только при `N>1` и без family gates.
- **NFQUEUE:** N параллельных curl через один nfqws2 — нагрузка на очередь; cap `MAX_CURL_PARALLEL=8`.
- **Смешанные домены:** `googlevideo*` → solo batch (videoplayback curl profile); несовместимые curl-профили не смешиваются.
- **Family gates (BC2-6):** fan-out отключён — need_* цепочка per-domain.
- **wssize retry:** для FAIL в batch — solo `_run_tcp_check` с `wssize` (дороже, но редко).
- **Pool:** `--parallel` = concurrent strategies; `--curl-parallel` = domains per strategy session.

**B2 smoke (2026-08-02, Xeon, benchmark 6 dom × 24 strat, `--no-family-gates`):**

| Mode | curl-parallel | Wall time | Throughput |
|------|---------------|-----------|------------|
| serial | 1 | 134s | 1.60 job/s |
| fan-out | 4 | 106s | 2.37 job/s |

Скрипт: `scripts/b2_smoke_benchmark.sh` (требует `--no-family-gates`, иначе fan-out отключается).

**Цель после B1+B2+A1 @ parallel=4:** ~6–12 job/s (7–14h на 312k).

---

# Phase 12 — Smart scan: ML / hierarchy / AQ (P3)

### ML: sklearn Random Forest ranker (Breiman / scikit-learn)

Offline ranker поверх `state.db` / GP SQLite — **не замена curl verify**, а сужение 18k → top-K.

**Постановка B (рекомендуемая):** `(domain_features + strategy_features) → P(PASS)`;
inference: rank top-20 → BS verify. Train только на BS curl_cffi labels.

**sklearn:** `RandomForestClassifier(n_estimators=200, max_features="sqrt", class_weight="balanced", oob_score=True)`.
Валидация: `GroupKFold` по domain. Метрика: **Recall@K**.

- [ ] **ML1** optional-dep `scikit-learn` в `[project.optional-dependencies] ml`
- [ ] **ML2** `scripts/train_strategy_ranker.py` — export `state.db` → parquet → fit → `model.pkl`
- [ ] **ML3** feature parser: domain (TLD, cdn_class) + strategy (family/blob/repeats/fooling)
- [ ] **ML4** BS integration: `--ranker model.pkl` → top-K candidates
- [ ] **ML5** retrain policy: после mass scan / drift / provider change

**Риски:** label noise GP≠BS, нестационарность ТСПУ, cold start → fallback brute-force.

### ML: иерархическое облако параметров (progressive drill-down)

Альтернатива full matrix: **дерево осей** вместо декартова произведения.

```text
L0: desync=fake                    → FAIL
L1: + ip_autottl=-2                → FAIL
L2: + blob=tls_clienthello_max_ru  → PASS  → stop / optional L3
```

| | Full matrix | Hierarchical | RF ranker | Adaptive queue |
|---|---|---|---|---|
| Тестов/домен | тысячи | десятки–сотни | K verify | перестановка очереди |
| Combo fake+blob+tcp_ts | ✅ | ⚠️ greedy miss | ✅ если в train | ✅ fan-out |
| Скорость | медленно | быстро | быстрый inference | **с первого PASS** |

**Связь:** RF ранжирует готовые стратегии; hierarchy строит по слоям; AQ — online.
Гибрид: provider template (A5) → AQ + B2 → RF → hierarchy (H*).

- [ ] **H1** спецификация «облака параметров»: оси (desync, blob, fooling, ttl, repeats, split…)
- [ ] **H2** `ProgressiveStrategyBuilder` — API: `add_axis()` → partial conf → test → branch
- [ ] **H3** default tree order из GP `family_rank` + Fryazino facts
- [ ] **H4** beam width B=3 — не только greedy
- [ ] **H5** интеграция в `bs scan --progressive` / `scan_level=progressive`
- [ ] **H6** лог partial results в DB (`partial_results`) для ML train
- [ ] **H7** learned axis order: contextual bandit / RF на domain_class
- [ ] **H8** provider template export из dpi-tester → A5
- [ ] **H9** benchmark vs full matrix на 10 доменах: Recall(best strategy found)
- [ ] **H10** fallback: progressive 0 PASS → expand beam / RF top-K / full family scan

### Adaptive queue: cross-domain fan-out + online family boost (AQ)

Online scheduler во время `bs full` / `bs scan` — priority queue с обучением на лету.

```text
PASS discord.com + fake+multisplit(seqovl=664)
  → enqueue (same strategy × discord.gg, discordapp.com, …)
  → w_family[fake+multisplit] += 1
```

**Гипотеза:** ~90% рабочих стратегий в первой половине jobs при shuffle + family weights.
Проверить SQL по `state.db`.

- [ ] **AQ1** `AdaptiveJobQueue`: priority heap + ε-random
- [ ] **AQ2** fan-out on PASS: `(strategy, domain)` → sibling domains
- [ ] **AQ3** domain clusters: `discord*`, `google*`, `youtube*`, `general`
- [ ] **AQ4** family/blob weight table + persist в `state.db` (`scan_weights`)
- [ ] **AQ5** интеграция с B2: одна стратегия → `asyncio.gather` curl
- [ ] **AQ6** CLI `bs full --adaptive` / `--fan-out`
- [ ] **AQ7** метрики: `time_to_first_pass`, `pass_found_before_50pct_jobs`
- [ ] **AQ8** SQL benchmark на stress: validate «90% в первой половине»

---

# Phase 13 — Developer onboarding (ONB)

Параллельно Phase 9; не заменяет SD/GV. См. [CONTRIBUTING.md](../CONTRIBUTING.md),
[architecture.md](architecture.md).

- [x] **ONB-1** CONTRIBUTING.md
- [x] **ONB-2** docs/architecture.md (main + discover-dns/auto-discover + googlevideo)
- [x] **ONB-3** docs/database.md
- [x] **ONB-4** docs/glossary.md + docs/cookbook/
- [x] **ONB-5** README, guide, package.md, docs map; fix BLOB-1≠configs
- [x] **ONB-6** settings.example.env; убрать machine paths
- [x] **ONB-7** configs/ package-data политика (editable install)
- [x] **ONB-8** убрать sys.path.insert
- [x] **ONB-9** engine/checkers `__init__` re-exports
- [x] **ONB-10** split `cli/` из bs.py
- [x] **ONB-11** split `engine/generators/`
- [x] **ONB-12** test_package_structure + smoke
- [x] **ONB-13** GitHub Actions CI + PR template

---

# Phase 2–6 — доп. бэклог (P2)

### Phase 2 — Voice

- [ ] **V2-1** multi-endpoint pair matrix по всем discover EP (сейчас только `eps[0]`)
- [ ] **V2-2** `--full-voice` gateway WS probe (сейчас discovery+STUN only)

### Phase 5 — GP bridge

- [ ] **A5** dpi-tester `provider_summary.json` → GP/Keenetic; BS shortlist import
- [ ] **B5** hybrid: BS shortlist export → GP multi-domain discovery
- [ ] **P5-1** GP JSON import в `state.db` (partial сейчас)

### Phase 6 — Export

- [x] **BC2-7** COMMON strategies intersection в export

---

# Закрыто (Packaging tech debt)

- [x] scan `--auto-discover` semantics
- [x] untrack `state.db`
- [x] nfqws2 DEVNULL stderr; pair coexist; queue-bypass; THROTTLED; ECH
- [x] UserMatrix UDP skip on TCP; protocol/preset/`-M`; blob/seqovl runner
- [x] Matrix protocol-gate + `scan_level=single`
- [x] nfqws2-keenetic export (`conf_builder` / `bc-nfconf`)

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
| Secure DNS / DoH | ✅ auto | — | 📋 Phase 9 (SD) |
| IP-block preflight | ✅ | — | 📋 Phase 9 (BC2) |

### Ключевые решения (актуальные)

1. Linux-only: iptables NFQUEUE (+ опционально nftables later).
2. curl_cffi — обязателен для «не врёт».
3. Dual nfqws2 (TCP q200 + UDP q201) для voice coexist.
4. SQLite checkpoints / resume; fingerprint на pair matrix.
5. Discover: DNS finland* + Maks list + dual STUN probe; concurrency=4.
6. Export: coverage_score → `:strategy=1..N` в dual conf.
7. Secure DNS: DoH pre-resolve на **все** домены + CURLOPT_RESOLVE (как blockcheck2); Phase 9.
8. Preflight pipeline: DNS audit → IP-block → port block → strategy matrix (BC2 flow).

### Устаревший layout из research (не использовать)

Ранний набросок (`engine.py`, `fw.py`, `strategies/standard/`) **не актуален**.
Канон: `src/blockchecks/` — см. [package.md](package.md).

---

## Docs map

| Файл | Роль |
|------|------|
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Setup, PR checks, where to change what |
| [guide.md](guide.md) | Установка и CLI |
| [architecture.md](architecture.md) | Data flow, voice/googlevideo diagrams |
| [database.md](database.md) | state.db schema + SQL examples |
| [glossary.md](glossary.md) | Термины |
| [cookbook/](cookbook/) | How-to: checker, generator, CLI flag |
| [package.md](package.md) | Структура пакета / аудит |
| [todo.md](todo.md) | Roadmap (Phases 1–13) |
| `presets/README.md` | Domains / strategies / `bs full` |
| Root `README.md` | Quick start |
| Root `research.md`, `GOALS.md` | stubs → todo.md |
