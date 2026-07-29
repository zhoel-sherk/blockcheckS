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

### Low-priority (alpha)

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
