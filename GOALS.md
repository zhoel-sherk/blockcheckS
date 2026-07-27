# blockcheckS — Goals & Architecture

## Mission
> Lightspeed DPI strategy tester. >10x faster than blockcheck.sh.
> >=95% strategy reliability on zapret2/nfqws2.
> Matrix-paired TCP+UDP testing with resume capability.

## Architecture
```
bs.py                    CLI entry point
engine/
  nfqws2.py              single nfqws2 manager (start/stop/reconfigure)
  firewall.py            iptables OUTPUT NFQUEUE rules
  strategy_loader.py     load from strings/files/custom dirs
  test_runner.py         TCP + UDP single-strategy testing
  pair_manager.py        DualNfqws2Manager (TCP q200 + UDP q201)
  pair_runner.py         PairTestRunner — TCP×UDP matrix + resume
  db_logger.py           aiosqlite state DB + checkpoints
checkers/
  tcp_tls.py             curl_cffi TLS check (content validation, JA4)
  udp_voice.py           STUN binding probe for voice UDP
  voice_discovery.py     auto-discover endpoint via sing-box + gateway
configs/                 20 Flowseal→nfqws2 .conf files
state.db                 SQLite: strategies, results, pairs, checkpoints
```

## Phases

### ✅ Phase 1 — Single Strategy TCP
- `bs.py tcp` — test one TCP strategy via curl_cffi
- 22 config files (20 TCP + 2 UDP)
- Content validation + DPI fake detection
- 7/22 TCP strategies working on Fryazino.net

### ✅ Phase 2 — UDP Voice Infrastructure  
- `bs.py udp` — STUN probe for voice UDP
- `checkers/udp_voice.py` — lightweight UDP checker
- Dual nfqws2 confirmed: 35ms avg latency, 0 spike

### 🔄 Phase 3 — Pair Matrix Testing (NOW)
- `bs.py pair` — TCP×UDP matrix with checkpoint/resume
- DualNfqws2Manager: keep TCP alive, rotate UDP
- State DB: aiosqlite + checkpoints every pair
- Auto-discovery: sing-box → gateway → voice endpoint
- --full-voice: WebSocket handshake (token required)
- Console matrix + JSON export

### 📋 Phase 4 — Parallel Testing
- asyncio pool: N nfqws2 instances in parallel
- Each pair gets its own netns + queue number
- 10x speedup for large strategy matrices

### 📋 Phase 5 — GP Integration
- Auto-generate strategies from parameter grid
- Export to GP control plane database
- Voice metrics (latency, jitter, spike) in GP format

### 📋 Phase 6 — Export
- Working strategies → nfqws2 .conf files
- GP database import/export
- Report generation (HTML/Markdown)

## Key Design Decisions

1. **Two separate nfqws2 processes** for voice — TCP q200 + UDP q201. Single `--new` profiles don't work for Discord.
2. **TCP kept alive** during UDP matrix scan — UDP instance restarts per strategy.
3. **SQLite checkpoints** after every (tcp_idx, udp_idx) pair — crash-safe.
4. **Sing-box auto-managed** — started inside netns for discovery, stopped after.
5. **Token optional** — without token, `--full-voice` SKIPs with message. UDP probe on static IPs.
6. **Colorama** output — green PASS, red FAIL, grey SKIP.
