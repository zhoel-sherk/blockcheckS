# blockcheckS Changelog

## 1.0.0 — 2026-08-02

### Added
- **AQ + time limit:** `--adaptive`, `--fan-out`, `--max-timeh` / `--max-timem`, graceful export on stop
- **BC2/GP curl repeats parity:** `--repeats` (1–10), `--parallel-repeats`, `--repeats-mode fast|stable`
- **B2 multi-domain fan-out:** `--curl-parallel` with googlevideo solo batches
- **Secure DNS + preflight:** DoH pre-resolve, DNS audit, IP-block cross-test (Phase 9)
- **Export:** keenetic + raw nfconf via `bs full` / `bc-nfconf`
- **Matrix M5–M7:** reverse/triple fake pairs, `http_tls_dual`, `udp_multiblob`
- **Docs:** `docs/cookbook/gp-bridge.md`, repeats glossary, `scripts/release_smoke.sh`
- **CI:** optional `workflow_dispatch` integration job placeholder

### Changed
- Version `0.3.0` → `1.0.0`
- `bs scan` supports adaptive queue + time limit + optional `--out-dir` export
- `bs tcp` supports `--repeats`, `--parallel-repeats`, `--repeats-mode`, `--max-timem`

### Quality
- 237 unit tests passing

## 2026-07-29 — Hygiene: ruff + docs merge + package audit

### Added
- `ruff` in `[dev]` + `[tool.ruff]` (E/W/F/I/UP/B/SIM)
- `docs/package.md` — full package layout audit
- `docs/todo.md` absorbs research + GOALS (phases, backlog, research notes)

### Changed
- Root `research.md` / `GOALS.md` → stubs pointing at `docs/todo.md`
- `StrategyItem` single definition (`matrix_generator`; re-export from `async_runner`)
- Removed stale root `checkers/` + `engine/` `__pycache__` leftovers

### Quality
- `ruff check src tests` clean; `ruff format` applied; unit suite 104 passed

## 2026-07-27 — Phase 3: Pair Matrix Testing

### Added
- `bs.py pair` command — TCP×UDP matrix with colorama output
- `engine/pair_manager.py` — DualNfqws2Manager (TCP q200 + UDP q201)
- `engine/pair_runner.py` — PairTestRunner with checkpoint/resume
- `engine/db_logger.py` — aiosqlite state DB
- `checkers/voice_discovery.py` — auto-discovery via sing-box
- `GOALS.md` — project goals + architecture
- `changelog.md` — this file

### Changed
- `initial_plan.md` → `GOALS.md` (refactored)

### Fixed
- All config comments stripped (nfqws2 parser bug with `()` in `#` lines)

## 2026-07-26 — Phase 1 MVP + UDP Infrastructure

### Added
- `bs.py tcp` — single strategy TCP testing via curl_cffi
- `bs.py udp` — STUN probe for voice UDP
- `checkers/tcp_tls.py` — content validation + DPI fake detection
- `checkers/udp_voice.py` — lightweight UDP checker
- `engine/nfqws2.py` — single nfqws2 manager
- `engine/firewall.py` — iptables OUTPUT NFQUEUE
- `engine/strategy_loader.py` — load from strings/files/dirs
- `engine/test_runner.py` — sequential strategy testing
- `configs/` — 22 Flowseal→nfqws2 .conf files
- `research.md` — blockcheck.sh + blockcheckw analysis

### Confirmed
- 7/22 TCP strategies working on Fryazino.net
- Dual nfqws2 voice: 35ms avg latency, 0 spike
- Discord IP Discovery: SSRC(4)+zeros(66)=70B

## 2026-07-27 — Audit fixes (P0-P2)

### Fixed (Critical)
- **Paths**: hardcoded `/home/zhoel/...` replaced with config module + env vars
- **Cleanup**: documented destructive `pkill -9` / `iptables -F` behavior (netns isolation mitigates)

### Fixed (High)
- **Content validation**: MIN_CONTENT_LENGTH 2000→300, exclude 101/204/301/302 statuses
- **STUN probe**: RFC 5389 magic cookie 0x2112A442 (was 16-byte invalid format)
- **Voice discovery**: session_id race (wait for BOTH VOICE_STATE_UPDATE + VOICE_SERVER_UPDATE)
- **Voice discovery**: OP9 retry limit (max 2 retries, was infinite loop)
- **bs.py**: --generate arg lost on pair command (now forwarded to tcp_sources)
- **bs.py**: cmd_pair now returns exit 1 when 0 TCP strategies pass

### Fixed (Medium)
- **netns_pool**: FORWARD iptables rules for veth pairs
- **netns_pool**: thread-safe create_all/destroy_all via threading.Lock
- **netns_pool**: cached interface name (fixes destroy_one stale MASQUERADE)
- **pair_runner**: total_time_sec baseline (now perf_counter() - t0)
- **pair_runner**: resume tuple unpack (4-element checkpoint)
- **db_logger**: checkpoint now queries note column (strategy names)
- **async_runner**: deterministic blob file ordering (sorted os.listdir)
- **matrix_generator**: SCANLEVEL fast now starts with tcp_ts=-1000 fooling

### Added
- `engine/config.py` — shared paths/constants/env vars
- `GOALS.md` refactored from initial_plan.md

### Known (documented, not fixed)
- `nfqws2.py` + `firewall.py` destructive cleanup (by design in netns context)
- `pair_manager.py`: pgrep cannot distinguish TCP/UDP instances
- `db_logger.py`: gateway_ok always False (placeholder for future gateway WS test)

---

## deepseekv4pro_audit — 2026-08-02

Четырёхсторонний аудит (engine, checkers, CLI/presets, DB/docs) с последующей починкой.

### Fixed (CRITICAL)

| # | Файл | Правка |
|---|------|--------|
| C1 | `tcp_tls.py` | `is_suspicious_redirect()` substring match → suffix match (`loc_host.endswith("." + dom)`) |
| C2 | `curl_probe.py` | Хардкод `min(timeout, 1.5)` → `req.timeout` (кап убран) |
| C3 | `http3.py` | `supports_http3()` probe на `cloudflare.com` вместо `127.0.0.1:65535`, честная классификация ошибок |
| C4 | `ip_block.py` | CDN-детект (Cloudflare IP-диапазоны) + warning при IP-block вердикте |
| C5 | `tcp_tls.py` | `read_start` таймер теперь после Session.create (не включает connect/TLS время) |
| E1 | `async_runner.py` | `repr(None)` → `"None"` literal в QUIC check_code |
| E2 | `async_runner.py` | Уже было починено через `wait_nfqws2_ready()` (B1 settle) |
| D1 | `db_logger.py` | `busy_timeout=5000` прагма после каждого `aiosqlite.connect()` (~21 соединение) |
| P1 | `MANIFEST.in` | Добавлены `presets/strategies/*.tls`, `presets/domains/*.txt`, `presets/voice/`, `presets/blobs/` |

### Fixed (HIGH)

| # | Файл | Правка |
|---|------|--------|
| H1 | `matrix_generator.py` | Дефолтные TCP sources: `["custom","configs","standard"]` |
| H5 | `voice_dns.py` | `asyncio.Semaphore(32)` лимит на конкурентный DNS |
| H7 | 3 файла | DPI_FAKE_PATTERNS — один источник (`tcp_tls.py`), импорт в `curl_probe.py` + `composite_runner.py` |
| H9 | `fryazino-tls12.tls` | Убраны 2 дубликата стратегий |
| H10 | `discord.txt`, `coverage.txt` | Заголовки приведены к реальному количеству доменов |
| H11 | `README.md` | Версия `0.3.0` → `1.0.0` |

### Documented (1.1.0 backlog)

- H2: `run_finalize.py` — `count_tcp_passes` открывает свежий коннект к БД
- H3: `adaptive_queue.py` — sequential await'ы в `filter_resume`
- H4: `preflight.py` — prolog-проверка только TLS (не контент)
- H6: `dns_secure.py` — `DnsRunCache` не ротирует DoH-сервер
- H8: `voice_discovery.py` — глобальный `_singbox_proc` не concurrent-safe
- E3: два competing nfqws2 lifecycle-подхода (daemon vs foreground)

### Cleaned up (MEDIUM)

- `.gitignore`: удалены дубликаты, добавлены `dist/`, `build/`, `*.so`, `.DS_Store`
- `composite_runner.py` unused `parallel` param (документирован)
- `db_logger.py` `scan_weights` migration gap (документирован)
