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
| **XDG** | XDG Base Directory spec — `~/.config`, `~/.local/state`, `~/.local/share`, `~/.cache` |
| **ONB-7** | Packaging: wheel self-sufficient since 1.2.1a (`configs/`/`presets/`/`blobs` in data-files); editable install still recommended for development |
| **T1 / T2** | Blob tiers: T1 = shipped, T2 = external (Flowseal/bol-van) |
| **fan-out** | Multi-domain curl probe per single nfqws2 session (B2) |
| **composite** | One `.conf` handling TCP+UDP with `--new=voice` profiles |
| **settle profile** | Per-strategy calibrated timing (min settle + curl timeout) |
| **adaptive queue** | Priority-based strategy ordering: epsilon-greedy + fan-out on PASS |
| **system deps** | Auto-fetch nfqws2 + Lua + blobs on first live run (Phase 1.0.1) |
| **preflight** | Startup checks: baseline, DNS audit, fooling grid, hops, ECH/HTTP, nfqws2 |
| **triage.toml** | ISP prior in XDG `data_block/providers/<slug>/` (hops, viable foolings/blobs, `[dead]`) |
| **send:repeats=6** | Dead on L4-checksum-normalizing DPI (SSL 35); not in the 5-cell fooling grid |
| **DoH** | DNS-over-HTTPS pre-resolution via Cloudflare/Google/Quad9 |
| **GV-1** | Googlevideo videoplayback probe (signed CDN URL, not apex) |
| **BC2** | blockcheck2.sh parity — foolings list, repeats logic, family ordering |
| **shortlist** | JSON export of best strategies per domain for GP control-plane |
| **JA4** | Browser TLS fingerprint via curl_cffi; default pin `chrome124` (`BLOCKCHECKS_IMPERSONATE`, guide) |
| **FailPhase** | Enum (32 tokens) классификации фазы сбоя пробы (DNS/L3/SNI/stall/QoS/QUIC/http) — единый источник для bandit/S0 и генераторов |
| **TriageProfile** | Детерминированный профиль вмешательства DPI из preflight: dns/sinkhole, unbypassable L3, stream-stall 7-42KB, QoS throttle, QUIC drop, TLS-fingerprint block, post-quantum |
| **L3/L4 probe** | `checkers/l3_probe.py` — SYN-проба + ICMP Type 3 → L4_SYN_DROP / L4_RST_AT_SYN / ICMP_BLOCK |
| **QUIC-drop probe** | `checkers/quic_raw.py` — raw QUIC Initial over UDP :443 → PASS / QUIC_DROP / UDP_BLOCKED |
| **stream triage** | `run_stream_triage_probe` — streaming Range-запрос с per-window замером (7/16/42/64KB stall, QoS plateau) |
| **TLS fingerprint** | `run_tls_profile_probe` — контрастные профили chrome/firefox/safari/bare → fingerprint-block + ClientHello размер |
| **rst_in** | DPI-инжектированный RST (scan_bridge Lua) — `bridge_rst_in` + TTL → `fail_phase=TLS_RST_AT_SNI` |
| **bs serve** | Резидентный on-the-fly probe server (Unix socket + HTTP bridge); Fair Exclusion через run_control |
| **HTTP bridge** | HTTP-слой поверх socket core в `bs serve` (порт 8089). Обеспечивает REST API и SSE. Задокументирован в `docs/api.md` |
| **SSE (Server-Sent Events)** | Протокол для стриминга realtime-уведомлений (`/api/events`) о прогрессе проверок |
| **Hybrid envelope** | Единый формат JSON-ответов (`{"status":"ok", "ok":true, "data":...}`) для HTTP, Socket и MCP слоёв |
| **bridge_applied** | Lua bridge event: nfqws2 действительно выполнил стратегию; `campaign_pass` требует HTTP OK **и** `bridge_applied=True` |
| **campaign_pass** | Строгое определение PASS для кампаний: HTTP OK ∧ `bridge_applied=True`; без APPLIED строка пишется как FAIL |
| **domain quarantine** | Исключение домена из очереди mid-run при 0 PASS за `--quarantine-min` попыток; сид из БД только при `--resume` |
| **harvest-batch** | Read-only экспорт топ-стратегий PASS+APPLIED в `batch.txt` + `manifest.json` для внешних валидаторов |
| **live events** | NDJSON-журнал проб (`events_live.jsonl`) + `current_probe.json` для наблюдения за кампанией без рестарта |
| **MCP** | Model Context Protocol сервер (`bs-mcp`): 22 инструмента для LLM-клиентов (Cursor/Claude/opencode) |
| **stop_campaign** | MCP-инструмент: `bs stop` по `run.lock`; если кампании нет — останавливает демон `bs serve` |
| **run_id / resume fingerprint** | `runs.id` + fingerprint матрицы; resume skip keys scoped только на этот `run_id`; без `--resume` — новый run_id |
| **UNIQUE(strategy, domain, protocol)** | Уникальность в `data_block` таблице `pass_strategies`; legacy двух-колоночный unique мигрируется автоматически |
