# blockcheckS Changelog

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
