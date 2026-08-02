# Glossary

| Term | Definition |
|------|------------|
| **strategy** | One nfqws2 lua-desync line or `.conf` file tested against a domain |
| **family** | Generator group (e.g. `fake`, `hostfakesplit`, `multi_fake`) |
| **generator** | `StrategyGenerator` subclass producing `StrategyItem` list |
| **scan_level** | `single` / `fast` / `full` — controls matrix size and early-exit |
| **netns** | Network namespace (`bs-p-N`) for isolated nfqws2 + curl |
| **NFQUEUE** | iptables target sending packets to nfqws2 (q200 TCP, q201 UDP) |
| **pair matrix** | Cartesian product TCP strategy × UDP strategy |
| **discover-dns** | Voice EP discovery without VPN (DNS + STUN + bootstrap) |
| **auto-discover** | Voice EP via sing-box + Discord gateway (needs token) |
| **udp_bootstrap** | Temporary host nfqws2 for discover-dns UDP probes |
| **content_valid** | Body passed DPI stub / min-size checks |
| **keenetic export** | `output/nfqws2_*.conf` circular profile format |
| **coverage_score** | Domains a strategy passes in `bs full` |
| **apex_probe** | TLS curl to domain root (misleading for googlevideo) |
| **videoplayback_probe** | curl to signed `googlevideo.com/videoplayback?…` URL (GV-1) |
| **PASS / FAIL / THROTTLED** | TCP result statuses in `state.db` |
| **fingerprint** | Hash of strategy matrix for `--resume` safety |
| **curl repeats** | `--repeats N` — N curl attempts per strategy×domain (BC2 `REPEATS`, GP 1..10) |
| **parallel repeats** | `--parallel-repeats` — concurrent curl attempts (BC2 `PARALLEL`, GP `repeat_parallel`) |
| **repeats mode** | `fast` = stop on first PASS; `stable` = run all N like blockcheck2 |
| **curl fan-out** | `--curl-parallel` — multi-domain per nfqws2 (GP `curl_parallelism`, **not** repeats) |
| **strategy repeats** | `:repeats=N` in lua-desync line — nfqws2 fake packet count (matrix only) |
