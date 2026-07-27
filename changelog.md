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
