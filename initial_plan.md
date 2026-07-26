# blockcheckS — Development Plan

## Phase 1: MVP (today)

**Goal:** `sudo python3 bs.py tcp -d discord.com -s "hostfakesplit:tcp_md5:tcp_ts_up"` → result in <3 seconds.

### Modules

| Module | Purpose | Status |
|--------|---------|:---:|
| `engine/nfqws2.py` | Nfqws2Manager: start/stop nfqws2 daemon | ✅ |
| `engine/firewall.py` | iptables OUTPUT NFQUEUE rules | ✅ |
| `engine/strategy_loader.py` | Load strategies from text files | ✅ |
| `engine/test_runner.py` | Sequential strategy testing | ✅ |
| `checkers/tcp_tls.py` | curl_cffi Chrome impersonation checker | ✅ |
| `bs.py` | CLI entry point | ✅ |

### Architecture

```
bs.py (CLI)
  ├── Firewall.prepare()         # iptables -A OUTPUT -j NFQUEUE
  ├── StrategyLoader.load()      # parse strategy string or file
  ├── for each strategy:
  │     ├── Nfqws2Manager.start(strategy)
  │     ├── TlsChecker.check(domain)   # curl_cffi async
  │     ├── Nfqws2Manager.stop()
  │     └── collect result
  └── Firewall.cleanup()
```

### Key design decisions

1. **nfqws2 restart per strategy** (MVP) — reuse added in Phase 2
2. **iptables** (not nftables) — simpler for MVP, nftables vmap in Phase 2
3. **Sequential** (not parallel) — async added in Phase 2
4. **No UDP yet** — Phase 3
5. **Independent from dpi-tester** — no imports from dpi-tester/src
