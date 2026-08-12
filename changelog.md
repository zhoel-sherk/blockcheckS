# blockcheckS Changelog

## 1.2.1a — unreleased

### Fix: domain isolation for sequential bridge scan (false-positive risk)

`_run_tcp_sequential_bridge` (used by `bs full` without `--adaptive/--fan-out`)
probed **one domain across all 4 netns simultaneously** — the same all-youtube
false-positive pattern we fixed for AQ earlier. Rewritten to parallel workers
with an `active_domains` set: each netns batch is filled strategy-major
(s1×all domains, then s2×…), so parallel netns always probe **distinct
domains**. Gated by `[run] domain_isolate` / `BLOCKCHECKS_AQ_DOMAIN_ISOLATE`
(default on); prints a WARNING when disabled.

Also enables real parallelism for the sequential bridge path (previously 1
netns at a time round-robin).

E2E verified: benchmark.txt 6 domains → 24 probes each (was: 1 domain only).
Unit tests: +2 (isolation overlap check + isolation-off warning). 1030 pass.

Long-term run series A→F now uses this isolation (A uses `--adaptive`).


### Strategy audit: Geneva + nfqws2 + Flowseal coverage (day-5 follow-up 2)

**Research completed** (see AGENTS.md): Geneva CCS'19 strategies.md (24
strategies), nfqws2/zapret2 lua desync catalog (25 functions), blockcheck2
standard (13 scripts), Flowseal zapret-discord-youtube (21 .bat, 186 profiles,
downloaded from Win11 SMB).

**New TCP strategy families (standard.py):**
- `rst_fake` — Geneva 10-15: ACK→RST/RA duplicate on empty ACK
  (`--payload=empty --out-range=s1<d1\nrst[:rstack][:badsum|:ip_ttl|:tcp_md5]`)
  + exotic flag fakes (Geneva 16-18 ≈ FRAPUEN/FREACN/FRAPUN via
  `send:tcp_flags_set=...`). 12 items.
- `synack` — Geneva 23: SYN→SYN+ACK split handshake
  (`synack`, `synack_split:mode=syn|synack|acksyn`). 6 items.
- `wssize` — blockcheck2 companion `wssize:wsize=1:scale=6` (+multisplit combo).
- `geneva_fool` — escape-hatch for non-expressible Geneva tampers via custom
  `fool=` Lua hooks (`lua/blockchecks/geneva.lua`): bs_dataofs, bs_iplen,
  bs_corrupt_load, bs_corrupt_wscale, bs_corrupt_uto. Requires
  `BLOCKCHECKS_LUA_EXTRA=/…/blockcheckS/lua/blockchecks/geneva.lua` (colon-joined
full paths). 18 items.

**Flowseal gap-fix (flowseal.py):**
- badseq-increment 2/1000/10000000 → `tcp_seq=N` (ALT4/ALT8/FTA_ALT2)
- `tls_mod=none` (ALT8/ALT10)
- hostfakesplit-mod `altorder=1` (ALT3)
- `syndata\nmultidisorder` link (ALT5)
- `fake\nmultisplit` without split params + badseq (ALT4)
- split-pos `2,sniext+1` (ALT7)
- pool: 6338 → 6493 tls12 items

**Numeric axes synced with def.inc + Flowseal:**
- `FAST_FOOLINGS_TCP` += tcp_seq=-3000, tcp_seq=1000000, tcp_flags_unset=ACK,
  tcp_flags_set=SYN (Geneva seq/flag fools promoted from full-only to fast)
- `ALL_REPEATS`/`FAST_REPEATS` += 14 (Flowseal ALT5 UDP-game)
- `ALL_BLOBS_TCP` reordered: 0x00000000 null blob first (capped scans reach it)
- `StandardGenerator` full scan: no per-type budget sharing (full pool now
  emits every family completely; 12 015 → 24 210 tls12 items)

**Tests:** +8 (test_geneva_audit.py) covering all new families + Flowseal gaps.

**Round-robin interleave (standard.py generate):** capped scans now emit one
strategy per family round-robin, so every technique (incl. the new families)
is represented at any `--max` instead of letting the huge `fake` family eat
the budget. Full pool (max≥pool size) still emits everything: 24 210 tls12
items (was 12 015).

**E2E verified (Fryazino, --max 30, timeout 2s):** rst_fake (`rst:badsum`),
synack and wssize all produced PASS on youtube.com; no nfqws2 errors across
the 30-strategy scan.


### Architecture: AQ strategy genetics + domain isolation + tuning (day-5 follow-up)

**Adaptive queue works on strategy genetics, not domains.**
- Removed cluster (domain) weight boost from `ScanWeights`. A PASS now boosts
  the strategy's `family` (+1.0), `blob` (+0.5) and extracted **traits**
  (+0.4): repeats / fooling / ttl-bucket / pos / desync technique
  (`strategy_traits()`). Sibling strategies of the same genetics are tested
  next regardless of which domain they target — Geneva-style evolution,
  decoupled from the domain. Previously cluster boost made one domain (e.g.
  youtube) dominate: all parallel netns probed the same domain → false
  positives.
- `AdaptiveJobQueue.pop(exclude_domains=...)` + shared active-domain tracker in
  `_bridge_worker`: with `parallel=N`, the pool always probes **N distinct
  domains** simultaneously (isolated, no all-youtube). Configurable via
  `BLOCKCHECKS_AQ_DOMAIN_ISOLATE` / `[run] domain_isolate` (default on).

**Tuning knobs — all hardcoded timeouts moved to config.**
- New config constants (env `BLOCKCHECKS_*` or `[run]` in config.toml):
  `RETRY_IP_TIMEOUT` (1.0), `PIN_TIMEOUT` (3.0), `YTDLP_TIMEOUT` (20.0),
  `DOH_TIMEOUT` (5.0), `SUDO_WALL_TIMEOUT` (15.0), `HTTP3_TIMEOUT` (3.0),
  `PROBE_DEFAULT_TIMEOUT` (5.0).
- `[run]` now maps: timeout, bridge_batch, adaptive_epsilon, max_timeh/m,
  retry_ip_timeout, domain_isolate. `settings.example.toml` documents all.

**Bridge retry-on-IP removed.** nfqws2 bridge applies the strategy by domain
(scan_pick via shm `strategy.id`); the destination IP does not affect desync
selection. Single IP per probe (was: 2× per-IP timeout on every FAIL).

**Proxy is optional.** Default `SOCKS5_PROXY`/`settings.proxy` is now empty —
probes go **direct** (standard: the strategy must get a legitimate answer from
the server). Enable via env `BLOCKCHECKS_PROXY=...` or `[tools] proxy` in
config.toml. No CLI flag.

**Speed.** `--timeout 1` + no retry-on-IP → FAIL ~1-2s instead of ~7s; E2E
12× faster (~114 jobs/min vs ~9), 4 netns stay isolated across domains.



### Refactor + coverage — v1.2.2 day-5 (85%+ target, pre-release)

- **async_runner god-file split** (1764 → ~330 lines): moved to
   (models),  (config builders),
   (netns probe workers). async_runner keeps
  AsyncTestRunner +  re-exports so external imports and monkeypatch
  paths keep working.
- **Coverage 73% → 85%** across 18 core modules: added test_tcp_tls (13),
  test_lua_session (7), test_batch_bridge_probe (6), test_async_runner_methods (7),
  test_in_ns_workers (5), plus retry/config/multi/quic/udp coverage. pytest-cov
  and pytest-randomly added to dev deps (randomly required by mutmut).
- mutmut scoped to 15 modules; mutmut run requires test fixes for mutants/
  cwd (tests reading non-mutated sources) — documented, gate stays
  workflow_dispatch.

### Refactor + coverage — v1.2.2 day-5 (85%+ target, pre-release)

- **async_runner god-file split** (1764 → ~330 lines): moved to
  `engine/results.py` (models), `engine/nfqws_config.py` (config builders),
  `engine/in_ns_workers.py` (netns probe workers). async_runner keeps
  AsyncTestRunner + `__all__` re-exports so external imports and monkeypatch
  paths keep working.
- **Coverage 73% → 85%** across 18 core modules: added test_tcp_tls (13),
  test_lua_session (7), test_batch_bridge_probe (6), test_async_runner_methods (7),
  test_in_ns_workers (5), plus retry/config/multi/quic/udp coverage. pytest-cov
  and pytest-randomly added to dev deps (randomly required by mutmut).
- mutmut scoped to 15 modules; mutmut run requires test fixes for mutants/
  cwd (tests reading non-mutated sources) — documented, gate stays
  workflow_dispatch.

### Fixed — v1.2.2 test-plan findings (days 1-4)

- **netns_pool `_get_iface` picked a leftover veth/peer as the out-interface**:
  a leftover UP veth (`vh-bs-p-*-N@ifNNN`) from a prior pool or a concurrent
  `bs` is the first non-lo UP iface, so `iptables -o vh-...@ifNNN` failed with
  "interface name must be shorter than IFNAMSIZ (15)" and netns creation
  aborted (found by the day-4 stress run). `_get_iface` now excludes
  `veth*`/`vh-*`/`vn-*` and any `@`-suffixed (peer) names. +1 unit test.
- **CliApp `--no-*` flags were silently ignored**: pydantic-settings 2.14
  parses `--no-<field>` as a *negation*, so fields literally named `no_*`
  (no_wssize, no_http, no_quic, no_voice, no_secure_dns, no_auto_pin,
  no_settle_profile, …) could never be set True through the CLI — both
  `--no-x` and `--no-no-x` parsed to False. smoke_scan/release_smoke with
  `--no-*` did not actually disable their phases. Fix: `cliapp.main` captures
  `--no-*` flags and `_dispatch_subcommand` re-applies them to the parsed
  subcommand. Verified `--no-quic/--no-voice/--no-http/--no-wssize` → True;
  +1 unit test.
- **Settle profile auto-load could break `bs full`**: a stale
  `/root/.cache/blockcheckS/settle_profile.json` with `curl_timeout=0.5s`
  (from an earlier bench on a faster network) turned every TCP probe into a
  500ms FAIL on throttled Fryazino. `auto_load_profile` now rejects profiles
  whose defaults demand `curl_timeout < 2.0` (AUTO_LOAD_MIN_CURL) with a
  warning; explicit `--settle-profile` still forces. +3 unit tests.
- **`--data-block-sync` committed but never pushed**: `maybe_sync_data_block`
  called `sync_commit()` without `push=True`, and under sudo git could not
  find the user's credentials. Now `sync_commit(push=True)` and git runs via
  `sudo -u $SUDO_USER`. Verified live push (origin 58ff6b2). +1 unit test.
- `ProviderStore.write_hosts` merged with the existing hosts file instead of
  overwriting: a run that DNS-audits only a few domains (e.g. benchmark.txt)
  previously wiped unrelated pinned entries (googleapis, googlevideo, youtu.be,
  discordapp, discordcdn). Found via v1.2.2 day-2 E2E when the data_block hosts
  shrank from 13 to 7 domains. +1 unit test.
- `bs tcp --protocol http`: `Nfqws2Manager.start()` always injected
  `--payload=tls_client_hello` + wrapped the whole strategy in `--lua-desync=`.
  For full CLI strategy lines from custom list_http.txt (e.g.
  `--payload=http_req --lua-desync=http_hostcase`) this produced a duplicate
  `--payload` and nfqws2 exited immediately. Now full `--`-prefixed strategies
  are split via `lua_conf._split_cli_args` and not re-wrapped; plain
  `fake:...` strategies keep the default TLS wrap. Verified `bs tcp -d ya.ru
  --protocol http --test custom` → 3/3 PASS; +2 unit tests.

- `--fixed-ip` / `--no-auto-pin` moved to scan/pair only (`add_ip_pin_args`);
  tcp/udp are single-shot sync commands without the AsyncTestRunner auto-pin
  path, so declaring the flags there tripped the dead-CLI-flags gate.
- Integration `test_lua_bridge_compare`: wall timeout 300→500s, per-strategy
  `--timeout 5` (FAIL paths stay short on throttled Fryazino), child runs in
  its own process group and `killpg` cleans the whole sudo→bs→nfqws2 tree on
  timeout (no leaked procs / stale run.lock / PID-reuse false conflict);
  `test_lua_bridge_single_strategy` now probes 1 strategy (was silently 10).

### Added — IP pinning (hosts-analog) + retry-on-next-IP vs Fryazino per-IP throttling

- **`--fixed-ip <path>`** (env `BLOCKCHECKS_FIXED_IP`): hosts-analog pin file
  (`domain IP` or `IP domain` per line, `#` comments). Default (no flag) is
  **`data_block/providers/<provider>/hosts`** — the same Windows anti-hijack
  hosts file, so one file feeds both blockcheckS and a hand-copied Windows
  hosts. Pinned IPs override DoH order, so the Cloudflare DoH rotation can no
  longer land on a Fryazino-throttled discord IP (e.g. `162.159.136.232`).
  See `byedpi_engine.md` §5 Phase 6 diagnosis.
- **Auto-pin at startup**: unless `--no-auto-pin`, the runner probes each
  cached domain's candidate IPs with `fake:blob=stun` (PIN_STRATEGY) and pins
  the first PASS. The provider hosts file is loaded, its *other* domains kept,
  and only **changed** IPs are written back atomically — git stays clean when
  nothing moved. Verified: pin `136.232` (throttled) → auto-swap to `135.232`
  → 3/3 PASS; non-active hosts entries (discord.gg, discordcdn.com, …) kept.
- **Retry-on-next-IP**: on a failed probe, `_run_tcp_check`, `_run_tcp_check_multi`
  and `run_tcp_check_bridge` retry the curl worker against the remaining
  candidate IPs with a short `RETRY_IP_TIMEOUT` (2s) budget; nfqws2/daemon is
  started once. The used IP is recorded in `data["used_ip"]` / `TcpTestResult.used_ip`
  and logged to the DB.
- New `blockchecks.checkers.ip_pin` (bidirectional parse/load/dump/save,
  Windows `IP\tdomain` output); `DnsRunCache` gained `_pins`,
  `set_pins/add_pin/pinned_ip/pins/candidates/domains`.
- Covered by `tests/unit/test_ip_pin.py` (13 tests); full unit suite passes.

### Added — byedpi (ciadpi) install + first selection-speed benchmark

- Installed byedpi v0.17.3 (`ciadpi`) into `~/workspace/byedpi/` — SOCKS5
  proxy, no root. Verified: curl through `socks5h://127.0.0.1:port` → HTTP 200.
- Added `dev/byedpi_bench.py` — standalone benchmark (not the full `--engine
  byedpi`): translates the working nfqws2 slice (fake/blob/hostfakesplit) to
  ciadpi argv, runs curl_cffi through the per-strategy SOCKS proxy, measures
  test/sec; compares with `bs scan --classic` baseline.
- First results (discord.com, 5 strategies): nfqws2 15.19s / 0.33 t/s / 3-5
  PASS vs byedpi 10.72s / 0.47 t/s / 3-5 PASS → **1.19× speedup**, stable;
  nfqws2 classic flaky on Fryazino. Documented in `byedpi_engine.md` §5 Phase 6.
- Note: ciadpi `-l <file>` (no `@` prefix, unlike nfqws2 blob syntax).

### Docs — refresh `docs/custom_lua.md` (paths + done/backlog markers)

- Fixed stale module paths after the service-layer refactor:
  `engine/lua_bridge.py` → `service/lua_bridge_ipc.py` (+ lua_conf/lua_session/
  lua_netns), `engine/batch_probe.py` → `service/batch_probe.py`,
  `engine/nfqws2.py` / `engine/netns_pool.py` → `service/…`.
- Marked implemented sections `✅ done` (scan_pick hot-swap §7, smart-fallback
  §6, ProbeBatchService/build_bridge_conf/BridgeSession §9, circular answer §13)
  and ideation `— backlog` (§3–§5, §14). Status banner now reflects reality.
- `lua/README.md` — notes custom_lua.md as the idea source (done + backlog).

### Added — QUIC/HTTP3 via Lua bridge + backend map in lua/README.md

- **QUIC bridge**: `bs full` QUIC phase now groups strategies into a
  `lua_bridge` batch when the backend is lua_bridge (default):
  - `lua_conf._strategy_filter_lines` — new `protocol="quic"` branch:
    `--filter-udp=443 --filter-l7=quic --payload=quic_initial` (UDP qnum).
  - `lua_netns._bridge_iptables_add` — protocol-aware: UDP/NFQUEUE_UDP for quic.
  - `lua_session.BridgeSession.boot` — passes protocol to iptables.
  - `batch_bridge_probe.run_tcp_check_bridge` — `protocol=="quic"` probes via
    `check_http3` in the netns subprocess (was curl-only).
  - `scan_bridge.lua` `bs_l7_ok` accepts `quic_initial`.
- **Classic QUIC fallback unchanged** (`fake→badsum→ip_ttl` in `test_quic`);
  bridge QUIC uses the base strategy (no fallback chain yet).
- **`lua/README.md`** — full backend map: what runs via Lua bridge vs classic
  (TCP batch, QUIC batch vs single TCP, fan-out, pair, UDP voice).
- Tests: `build_bridge_conf` quic branch, `scan_bridge.lua` accepts
  `quic_initial`.

### Fixed — `--classic`/`--probe-backend` accepted on tcp/udp

- `--classic` / `--probe-backend` are now valid on `bs tcp` and `bs udp`
  (previously `unrecognized arguments` — they were only wired into
  scan/pair/full). Extracted `add_backend_args()` (classic + probe-backend)
  shared by all commands; `add_lua_bridge_args()` keeps lua-specific flags
  (bridge-batch/compare/extra) on scan/pair/full only.
- Verified live: `bs tcp --classic` → HTTP 200 PASS; `bs udp --classic` → 30ms
  PASS; `bs scan --classic` → `backend=classic` PASS.
- **Trottling confirmation**: GP control-plane standard discovery on
  discord.com shows pervasive `code=28` timeouts across dozens of strategies
  (Fryazino throttling), while fake+tls_mod strategies (`fake_default_tls +
  tls_mod rnd`, `luaexec patmod`) succeed — the same pattern blockcheckS finds
  (`fake:blob=...:tcp_ts=-1000`). Not a blockcheckS bug.
- dead_cli_flags now covers tcp/udp for the new backend dests.

### Changed — QUIC fallback timing + iptables hygiene

- **Fallback variants use a shorter timeout** (`min(timeout, 3.0)`): a TSPU
  drop happens immediately, so waiting a full 5s on each already-dropped
  fallback tripled QUIC wall-time (15s/strategy) under systematic drops.
  Base strategy keeps the full timeout; only fallbacks are quick drop-checks.
- **`_run_quic_check` flushes OUTPUT iptables** before adding the NFQUEUE rule,
  so fallback re-entry in the same netns no longer stacks duplicate rules.
- Tests: `test_quic_http3.py` — fallback uses short timeout for variants (base
  5.0, fallbacks 3.0).

### Added — QUIC fallback chain when the base strategy is dropped

- `test_quic` now tries a fallback chain when a QUIC strategy times out (TSPU
  drop): base `fake:blob=X` → `+badsum` → `+ip_ttl=1`. Disable with
  `BLOCKCHECKS_QUIC_FALLBACK=0`.
- Live diagnosis (2026-08): fake injections **bypass the TSPU** for QUIC — the
  QUIC Initial reaches the CDN (`ngtcp2_conn_writev_*` / `SSL: no alternative
  certificate`, NOT timeout), while `send:ipfrag` (split/disorder) is dropped
  (timeout). `_is_quic_dropped()` distinguishes a full drop from reached-CDN
  errors; `_quic_fallback_variants()` builds the fallback list.
- Tests: `test_quic_http3.py` — fallback variants (+badsum/+ip_ttl, skips
  existing, config/disabled), `_is_quic_dropped` (4).
- `docs/guide.md` QUIC fallback section added.

### Investigated — QUIC/HTTP-3 blocking mechanism on Fryazino (2026-08)

- **QUIC as a protocol is NOT blocked**: `check_http3('cloudflare.com')` → 301;
  raw QUIC Initial to a Cloudflare IP gets a reply; QUIC reaches `vk.com` and
  bare `googlevideo.com`.
- **Blocking is by SNI, not by IP**: the same Google rr-range IP
  `74.125.108.234` passes `cloudflare.com` / `cdn.example.com` / bare
  `googlevideo.com` (reach the CDN → certificate error) but **drops**
  `youtube.com`, `www.youtube.com`, `rr*.googlevideo.com` (timeout) on any IP.
  TSPU inspects the SNI inside the first QUIC Initial UDP packet and applies
  per-site rules; blocked SNI → whole UDP session dropped.
- Consequence: GGC-style IP substitution does not help for QUIC; masking the
  SNI to a white domain yields no CDN content. Needs SNI masking or a tunnel,
  not IP substitution. Documented in `docs/guide.md`.

### Added — voice-traffic >16KB preflight check + provider-result → AQ weights

- **Preflight UDP >16KB check** (`preflight.check_udp_16kb`, `PreflightReport.
  udp_16kb_blocked`): during startup, sends a >16KB UDP media burst to a
  discovered Discord voice endpoint to detect whether the TSPU drops the voice
  stream (dpi-detector analogue). Result feeds strategy selection.
- **Provider → AQ weight orchestration** (`adaptive_runner._apply_provider_weights`):
  `build_adaptive_queue` now reads `data_block` pass_strategies
  (`approved_only`) and boosts family/blob/cluster weights for strategies the
  provider already saw pass on the scanned domains — the adaptive scan tests
  the most promising candidates first. Wired into `bs full` AQ path.
- Tests: provider-weight boost + cross-domain skip (`test_adaptive_runner.py`).

### Added — Discord voice region endpoints + UDP >16KB media-burst probe

- **`--voice-region`** / `BLOCKCHECKS_VOICE_REGION` — select a Discord voice
  region for endpoint discovery (`finland`/`russia`/`frankfurt`/…). `discover_dns_alive`
  seeds region IPs from Maks-gaming; when a region is not published under
  `regions/` (russia/frankfurt 404), it falls back to the **global**
  `data/voice-ip-list.txt` (all regions) + region-host DNS resolution.
  Verified live: `bs udp --discover-dns 3 --voice-region russia` → 3/3 PASS.
- **`--voice-burst`** — `voice_burst_probe()` sends a **>16KB UDP media burst**
  (RTP-shaped, Opus-like chunks) to trigger the TSPU "voice traffic" heuristic
  (dpi-detector's 16-20KB drop). `voice_udp_probe` now tries STUN →
  IP-Discovery → burst. Wired through `_probe_worker` (`--burst`) and the
  async inline probe (`BLOCKCHECKS_VOICE_BURST`).
- `checkers/voice_dns.py`: `fetch_maks_region_ips()` (region via global domain
  list + DNS), `MAKS_GLOBAL_IP_LIST_URL`, `REGION_HOST_PREFIXES`.
- Tests: `test_udp_voice_probes.py` burst success/timeout/try_burst (4),
  `test_probe_worker.py` burst flag (2).

### Changed — googlevideo always uses the deterministic GGC probe (auto-fallback)

- **`config.ggc_enabled(domain)`** replaces the `GGC_ENABLED` constant: any
  googlevideo host is automatically probed via the GGC detector (no yt-dlp
  signature, valid beyond the 6-hour signed-URL TTL). `BLOCKCHECKS_GV_GGC=0`
  opts out (signed yt-dlp URL), `=1` forces GGC for any domain.
- **`domain_loader.auto_enable_gv_ggc(domains)`**: when a domain list contains
  googlevideo, sets `BLOCKCHECKS_GV_GGC=1` so subprocess curl workers (which
  read env, not the in-process function) use the GGC detector too. Wired into
  `load_run_domains` (`bs full`) and `resolve_preset_domains` /
  `prepare_dns_and_preflight` (`bs scan`/`bs pair`).
- Verified live: `bs tcp -d googlevideo.com` with **no** env → `HTTP 403`
  (GGC applied, PASS); `bs tcp -d discord.com` → `HTTP 200` (normal path).
- Tests: `test_gv_ggc.py` (10) — ggc_enabled precedence + auto_enable env
  behavior; `test_curl_probe.py` auto-fallback + signed-path (env=0) coverage.

### Added — deterministic GGC probe (bypass-detector, no 6h signed-URL TTL)

- googlevideo signed URLs expire in exactly 6h (21600s). New deterministic
  detector `BLOCKCHECKS_GV_GGC=1` hits a live Google cache (GGC) IP with
  SNI=`rr*.googlevideo.com` and `Range: bytes=0-1048575` (1MiB) to trigger the
  TSPU "video download" heuristic — valid indefinitely, no yt-dlp signature.
- **Bypass vs block detection**: a genuine Google CDN answer carries the unique
  `Server: gws | scone | gvs 1.0` header; the TSPU stub replies `Server: nginx |
  nts` or none. On 302/307 the `Location` must stay inside
  `*.googlevideo.com`/`*.google.com`, otherwise it is a TSPU regional redirect.
- `checkers/curl_probe.py`: `prepare_ggc_probe()`, `_ggc_redirect_is_google()`,
  PASS logic (CDN answered + Google Server header + Google-only redirect).
  `ggc` flag plumbed through `probe_request_dict` / `_curl_probe_worker` /
  `test_runner` payloads.
- Config: `GGC_HOST`, `GGC_FALLBACK_IP`, `GGC_RANGE_SIZE` (1MiB),
  `GGC_ENABLED` (`BLOCKCHECKS_GV_GGC`).
- Verified live: `bs tcp -d googlevideo.com` with GGC returns `HTTP 403` +
  `Server: gvs 1.0` → PASS (bypass), while direct egress is blocked (timeout).
- Tests: `test_curl_probe.py::TestGgcProbe` (6) — Server gws pass, nginx fail,
  no-header fail, Google redirect pass, TSPU redirect fail, `_ggc_redirect_is_google`.

### Fixed — googlevideo CDN probe via SOCKS proxy (2026-08-09)

- `checkers/curl_probe.py` — googlevideo videoplayback probes now route through
  `SOCKS5_PROXY` (`BLOCKCHECKS_PROXY`, default `socks5://127.0.0.1:11080`).
  Direct egress to the googlevideo CDN is DPI-blocked on Fryazino, so without a
  proxy every GV probe timed out / 403'd even though yt-dlp had a fresh signed
  URL. The proxy is passed per-request via the `proxy=` kwarg as
  `socks5h://…` (DNS through proxy); the `CurlOpt.PROXY` setopt path does not
  map `socks5h` correctly and yields 403.
- Verified live end-to-end: fresh rr-URL fetched through sing-box (SOCKS
  127.0.0.1:11080) and `bs tcp -d googlevideo.com` now returns
  `[OK] HTTP 206` (was 403 / timeout). Direct `curl --proxy socks5h://…` on the
  same URL returns HTTP 206, 300 KB range body.
- sing-box config updated to a fresh VLESS UUID
  (`9b175962-…`, Riga `94.158.219.192:31237`) and migrated to sing-box 1.13
  config schema (legacy inbound `sniff` fields removed); daemon runs via nohup.

### Changed — scripts audit + repeatable functional-test entry points (2026-08-09)

- **Removed obsolete/one-off scripts** from `scripts/`: `flag_campaign.py`,
  `retest_failed.py`, `b2_smoke_benchmark.sh`, `export_shortlist.sh` (dup of
  `bc-nfconf`), `export_shortlist_json.sh`, `gv5_quic_smoke.sh` (QUIC blocked
  on Fryazino), `gv_e2e_smoke.sh`. Removed `dev/oc_*` OpenCode API smokes
  (unrelated to testing).
- **Added repeatable functional-test scripts** in `scripts/`:
  - `smoke_scan.sh` — quick `bs scan` on a known-good matrix; backend selectable
    (default/classic/bridge/compare).
  - `smoke_full_quick.sh` — time-boxed `bs full`; verifies deadline-stop,
    nfqws2 export + run_summary.
  - `smoke_backend_matrix.sh` — functional test of backend selection
    (default→lua_bridge, `--classic`, `--probe-backend`, env, compare no-drift).
  - `gate_all.sh` — one-shot unit + quality + ruff + vulture (+ optional
    `--integration`).
  - `cleanup_env.sh` — reset netns / nfqws2 / shm / run.lock between runs.
- **Added `dev/functional_smoke.sh`** — end-to-end test of every `bs`
  subcommand (tcp/udp/composite/scan classic+bridge/pair/bench-settle/full/
  stop) + `bc-nfconf` export + shortlist round-trip. Live result: **11/11 PASS**.
- `dev/README.md` updated to document the remaining dev helpers + the smoke
  suite.

### Changed — lua_bridge is the standard backend, `--classic` opt-out (T-L3/T-L4/T-L5)

- **Default probe backend flipped to `lua_bridge`** (T-L3): `bs scan`/`pair`/
  `full` now use the persistent nfqws2 + `/dev/shm` IPC bridge without a flag.
  Verified live: `bs scan` (no flag) → `backend=lua_bridge`, 3/3 PASS.
- **`--classic`** (T-L4): force the legacy per-strategy nfqws2 restart backend.
  Verified live: `bs scan --classic` → `backend=classic`, 3/3 PASS.
- **`--probe-backend {classic,lua_bridge}`** (T-L4): explicit backend selection.
  Verified live: `--probe-backend classic` → `backend=classic`.
- **`BLOCKCHECKS_PROBE_BACKEND` env** (T-L5): backend override for scripts/CI.
- Backend precedence (single resolver `config.resolve_probe_backend`):
  `--classic` > `--probe-backend` > `--lua-bridge` > `BLOCKCHECKS_PROBE_BACKEND`
  > default `lua_bridge`.
- Unchanged invariants: pair **UDP bootstrap** and **fan-out waves** always use
  classic; `--lua-bridge-compare` dual path still logs drift (verified live:
  classic + bridge batches, 0 drift).
- Tests: `tests/unit/test_probe_backend.py` (10 cases) — precedence, env,
  CliApp parsing, always-classic paths.

### Added — wheel self-contained data + runtime nfqws2 debug (2026-08-09)

- **Wheel now ships baked data** (`[tool.setuptools.data-files]`): `blobs/*.bin`
  (23), `configs/*.conf` (28), `lua/blockchecks/*.lua` (3), `presets/strategies`,
  `presets/domains`, `presets/voice`. A plain `pip install` wheel is
  self-sufficient — no editable install required.
- `engine/config.py` — `_resolve_project_dir()` falls back to
  `sys.prefix/blockchecks` (where PEP 427 data-files land) so `PROJECT_DIR`,
  `BLOB_DIR`, `REPO_LUA_DIR` and presets resolve from the installed package.
  Verified: wheel installed in a clean venv resolves blobs/configs/lua/presets.
- **Runtime nfqws2 --debug toggle (SIGUSR1)** — must-have for multi-hour scans:
  `SIGUSR1` toggles `BLOCKCHECKS_NFQWS2_DEBUG` and restarts the bridge daemon on
  the next probe (reuses `BridgeSession.boot()` / recycle path). `bs full` and
  `bs scan`/`pair` both handle SIGUSR1. Verified live: SIGUSR1 ON → daemon
  restarts with `--debug`, `nfqws2_*.log` written (3337 B, zhoel-owned); second
  SIGUSR1 → debug OFF. Works without stopping the campaign.
- Tests: debug-env toggle forces lua daemon restart.

### Fixed (logging + XDG audit 2026-08-09)

- `cli/cliapp.py` — **`--nfqws2-debug` was silently ignored on the main CliApp
  path**: the env var `BLOCKCHECKS_NFQWS2_DEBUG` was only set by argparse's
  `dispatch()` (legacy path). Added `_apply_nfqws2_debug_env()` in
  `_dispatch_subcommand` and `expand_bare_nfqws2_debug()` so both `--nfqws2-debug 1`
  and bare `--nfqws2-debug` work. Verified live: `bs tcp --nfqws2-debug 1` now
  produces a debug log.
- `engine/paths.py` — **application logging was never configured**: module
  loggers (paths, presets) wrote to a root logger with no handlers, so
  `log.warning` was silently dropped in production. Added `configure_logging()`
  (FileHandler under `RUNTIME_LOGS_DIR/blockchecks.log` + stderr, level from
  `BLOCKCHECKS_LOG_LEVEL`, default WARNING), called from `cliapp.main()` and
  `parser._main_argparse`.
- `engine/paths.py` — `reclaim_sudo_ownership()` now also repairs **`.log`
  files** (single and inside directories). nfqws2 debug logs are created by the
  dropped-privilege daemon (overflow-uid) and stayed root/`UNKNOWN`-owned.
- `service/nfqws2.py` — after daemon start, the nfqws2 `--debug` log is
  reclaimed to `SUDO_UID/GID` (verified live: `nfqws2_q200_*.log` → zhoel).
- `engine/run_finalize.py` + `nfconf.py` — `run_summary_*.json` and exported
  `nfqws2_*.conf`/`user.list` are reclaimed when running as root.
- Tests: cliapp debug-flag propagation + bare form, logging configured under
  state/logs, reclaim of .log (single + directory), run_summary reclaim.

### Fixed (service-layer audit 2026-08-09)

- `service/lua_bridge_ipc.py` — **events.ndjson must be world-writable (0666)**:
  nfqws2 drops privileges (setuid overflow-uid) after init, so a root-owned
  0644 `events.ndjson` made Lua's `io.open("a")` return nil and `APPLIED` /
  `STRATEGY_FAIL` events were silently lost. Strategy selection tracking was
  broken — PASS recorded without confirmation that the strategy was picked up.
  Verified live: bridge batch PASS previously emitted "bridge PASS without
  APPLIED" warnings for every strategy; after fix 0 warnings at same PASS.
- `service/probe.py` — `invoke_curl_probe_worker` now catches `TimeoutExpired`
  and returns a failure dict instead of killing the whole batch (a hung worker
  lost all per-strategy results + DB logging).
- `service/batch_service.py` — `run_batch` catches **any** exception from the
  sync probe loop (not just `NetnsGoneError`) and emits per-item failure
  results, so a mid-batch crash can no longer drop unlogged strategies.
- `service/batch_service.py` — wssize retry no longer fires for config
  strategies (`is_config=True`); the old check inspected the config *path* for
  the substring "wssize", which is meaningless → spurious retry on every config.
- `service/batch_bridge_probe.py` + `engine/async_runner.py` — bridge probe
  surfaces `bridge_applied` (was an APPLIED event drained?) and warns on
  PASS-without-APPLIED instead of silently trusting the HTTP 200.
- Unit tests: TimeoutExpired dict, generic batch exception → fail results,
  wssize config skip, `bridge_applied` flag, events 0666 perms, publish
  consistency, probe-gen monotonicity, dead-pid `Nfqws2Manager.stop`,
  recycle preserves strategy id, settle `min_wait` floor.

### Added — Lua bridge (hot-swap nfqws2 per batch)

- **`--lua-bridge`** — persistent nfqws2 daemon per netns worker. Strategies hot-swapped
  via `/dev/shm` IPC (`strategy.id` + `strategy.gen` atomically published by Python,
  read by `scan_pick` Lua orchestrator on each ClientHello). Eliminates per-strategy
  `pkill`/`start_daemon`/`settle` cycle — amortized from 0.2s/test to 0.0004s/test.
- **`--bridge-batch N`** (default 500, max 2000) — strategies per bridge conf window
- **`--lua-bridge-compare`** — dual-run classic + bridge, log verdict drift
- **`--lua-extra`** — extra `--lua-init=@` paths for custom Lua hooks
- **`ProbeBatchService`** (`engine/batch_probe.py`, 484 lines) — unified batch-probing
  engine with two backends: `classic` (per-strategy daemon) and `lua_bridge`
  (persistent daemon with shm IPC)
- **Lua scripts** (`lua/blockchecks/`):
  - `init.lua` — 50ms timer fallback poll
  - `scan_bridge.lua` — `scan_pick` orchestrator (deterministic strategy-by-id)
  - `write_ipc.lua` — NDJSON event writer (`APPLIED`, future `STRATEGY_FAIL`)
- **Python IPC** (`engine/lua_bridge.py`, 413 lines):
  - `LuaBridge` — atomic publish/drain/teardown per netns
  - `BridgeSession` — boot → probe N strategies → shutdown lifecycle
- **Tests:** `test_lua_bridge.py` (96 lines), `test_lua_bridge_runner.py` (23 lines),
  `test_batch_probe.py` (169 lines), `test_batch_probe_runner.py` (54 lines)

### Changed

- `netns_pool.py` + `run_control.py` — teardown bridge shm on worker release / campaign stop
- `config.py` — `get_blockchecks_lua_scripts()`, `SHM_BASE`, `DEFAULT_BRIDGE_BATCH`
- `MANIFEST.in` — include `lua/blockchecks/*.lua`

### Fixed

- `async_runner.py` — `test_batch_tcp` delegates to `ProbeBatchService` (classic or bridge)
- `main_phases.py` — `_run_tcp_sequential_bridge()` for bridge path
- `generators/custom.py` — `UserMatrixGenerator` now supports `--user-matrix -` (read strategies
  from stdin), unblocking the `--lua-bridge-compare` integration tests (9/9 pass live)
- `cli/cliapp.py` — `SystemExit` carrying a string message (e.g. the active-run lock
  `bs stop` hint) is printed to stderr with rc=1 instead of crashing `int()` with a
  `ValueError` traceback; removed the shadowing local `import sys`

### Live-verified (this pass)

- `bs full` smoke: TCP 9 PASS / HTTP 123 PASS (flowseal, `--max-timem 2`), conf-export path ok
- `bench-settle`: 5×4 settle/curl grid all PASS, `settle_profile.json` written
- `bs stop` graceful (SIGTERM + wait, times out on in-flight subprocess probe →
  hints `--force`) and `bs stop --force` (SIGKILL, clears `run.lock`)
- Integration suite `tests/integration/ -m integration` — **9 passed** (requires a clean
  `run.lock`; leftover `bs scan` from an interrupted run makes tests fail fast)

---

## 1.1.0 — 2026-08-05

First stable release after alpha (`1.1.0a1`). Quality gates, CliApp CLI, baked blobs, Flowseal matrix expansion, `bs stop`, P0 perf defaults.

### Added (Flowseal unified + baked blobs)
- **Repo `blobs/`:** Flowseal+custom binaries committed; default `BLOB_DIR` prefers in-repo path (no download)
- **`FlowsealGenerator`:** full bat-technique axes (multi/split/fds/hf/md/syndata/tls_mod/QUIC/UDP); >1000 OK
- **`flowseal-fast`:** curated technique shortlist (not ALT2-branded)
- **Cookbook:** [docs/cookbook/blobs.md](docs/cookbook/blobs.md) — how to add a blob

### Added (todo debt close)
- **M8:** `bs full` default `--tcp-sources` includes `flowseal`
- **Matrix:** `repeats=4`; TTL overflow `256`/`512` on full axes; Flowseal multi-blob `r=4`
- **Phase 7:** ipfrag `disorder` / `next` / fuller pos; aliases `ipfrag_tcp`/`ipfrag_udp`; UDP multiline dual `--lua-desync`
- **V2-1:** pair/udp/full fan-out across discovered voice endpoints (`domain@ip:port` pair keys)
- **V2-3:** `scripts/voice_smoke.sh`
- **P5-1:** `python -m blockchecks.provider_import --seed-db PATH`

### Fixed (CLI / CliApp)
- **Short flags restored** on CliApp path (`-d`, `-M`, `-c`, …) via `cli_shortcuts` + `case_sensitive=True`
- **Bare `--generate`** again expands to `custom,configs` (argv preprocess before CliApp)
- **`bs --help`** shows one-line blurbs per subcommand (from argparse `help=`)
- **`write_secure_text`** moved to `engine.secure_io` (no longer dead in voice_discovery)

### Fixed (dpi-stack audit DS1)
- **Composite UDP qnum:** multiport `50000:50100` → `NFQUEUE_UDP` (Wave4 regression)
- **`test_batch_tcp` order:** `asyncio.gather` preserves strategy input order (pair filters)
- **curl_cffi hygiene:** `Session` + `with`, catch `RequestsError`; wire `read_timeout` via `LOW_SPEED_*`; DoH via Session
- **DAO latest-row:** `count_tcp_passes` / `domain_pass_stats` / `v_coverage` / `v_latest_run`; `get_best_udp` += THROTTLED; `get_best_pairs` dedupe
- **Generators:** `tls13` protocol metadata; `UserMatrixGenerator.protocol`; udp_quic/game/multiblob via `resolve_blob_path`
- **Keenetic circular scaffold:** `--out-range=-s34228` / `--in-range=-s5556` / `--in-range=x`
- **Voice:** Discord WS `match/case`; sing-box `@asynccontextmanager`; `--full-voice` messaging (gateway path)

### Changed (dpi-stack audit DS2)
- Shared `blob_cli_line` / `append_blob_cli_lines` / `extract_blob_names` in `blob_aliases`
- UDP family registry start (`udp_discord`/`quic`/`game`/`multiblob`)
- Status/verdict maps (tls/http3/dns audit); CLI dispatch maps; `PreflightOptions.from_args`
- `Nfqws2Manager` settle via `wait_nfqws2_ready`; `tls_clienthello` alias; user presets preferred

### Added
- **1.1.0a1 (alpha):** public `engine.probe.invoke_curl_probe_worker`; `--preset` / `-M` path jail; token refuse world-writable + `write_secure_text`
- **E3:** `engine.nfqws2.start_daemon` (+ `inject_debug_and_daemon`); async/composite use public API; `Nfqws2Manager` remains for sync/foreground
- **H2–H8 / migrate:** export reuses open store; AQ `filter_resume` gather; `--prolog-content`; DoH rotate; sing-box lock; `./state.db` → XDG migrate
- **Wave4:** `BLOCKCHECKS_POOL` / low-RAM soft-cap for `--parallel`; NFQUEUE_* in async+composite; `--queue-bypass` on composite; ELF arch check; `presets/domains/pi2.txt`
- Docs: architecture rewrite (DoH → preflight → AQ → curl subprocess → store; NetNsPool scale); B7 todo corrected (not required for netns parallel>4)

### Notes
- Xeon smoke (`-M gp-verified --max 24`, curl-parallel 1): `--parallel 4` ≈13.7s wall, `--parallel 8` ≈15.0s — with ≤8 strategies wall time is dominated by 5s FAIL timeouts + netns pool create; larger matrices benefit from more workers (architecture already isolates per-netns).

### Changed
- README: table of contents, badges, hero section, humor/jargon
- docs: presets README counts corrected; architecture module map expanded; database refs updated; glossary +15 terms; troubleshooting added to guide; blobs tier-1 clean-up

### Release polish (1.1.0 final)
- **`bs stop`** / `--stop`: graceful shutdown via `run.lock` (SIGTERM → flush → export)
- **VPS-2:** single CliApp subcommand dispatch (fixes accidental double `full` run)
- **P0 perf:** default `db_batch=500`, `settle_slack=3s`, nfqws2 foreground sleep 0.1s
- **Packaging:** repo `blobs/*.bin` included in sdist via `MANIFEST.in`

---

## 1.0.2 — 2026-08-03

### Fixed
- XDG: correct `settings.example.toml` priority docs; `finalize_store_args` always fills `out_dir`
- Export/shortlists defaults → `~/.local/share/blockcheckS/` (legacy `state/` still used if non-empty)
- `subprocess_env` preserves `PYTHONPYCACHEPREFIX` from caller `base`
- DAO: `flush()` uses `BEGIN IMMEDIATE` + rollback; `get_best_pairs` includes THROTTLED
- Removed dead `get_passing_pairs`; added indexes `(strategy_id,domain)` / `pair_results(domain)`

### Changed
- tmp-scripts cleanup: keep helpers in `dev/`, `strategy_debug_probe.py` → `scripts/`

## 1.0.1 — 2026-08-03

### Added
- **System deps check** (`engine/system_deps.py`): warn on missing `sudo`/`ip`/`iptables`; resolve nfqws2
- **Auto-fetch zapret2**: when nfqws2 missing, download official `bol-van/zapret2` release (sha256-verified)
  into `~/.local/share/blockcheckS/zapret2/` (+ `bin/nfqws2` symlink); lua + blobs seeded from the archive
- CLI: `--no-fetch-deps`, `--offline`, `--skip-deps-check`; env `BLOCKCHECKS_FETCH_DEPS`, `BLOCKCHECKS_LUA_DIR`

### Fixed
- nfqws2 daemon temp leak (`bs_nfq_*` unlink after settle)
- Campaign `chown_db` hardcoded user → `getpass.getuser()`
- `reclaim_sudo_ownership` now logs WARNING on chown OSError
- Hardcoded `/opt/zapret2/lua` paths → `LUA_INIT_DIR` / `get_lua_init_scripts()`
- Packaging: `requirements.txt` / `requirements-dev.txt` synced with `pyproject.toml` (incl. tomli)

### Docs
- Bilingual legal disclaimer in README
- Install contract: host `/opt/zapret2` **or** XDG auto-vendor

## 1.0.0 — 2026-08-03

Первый production-ready релиз: mass-scan DPI-стратегий для zapret2/nfqws2 с curl_cffi,
netns-изоляцией, adaptive queue и XDG layout.

### Added

- **CLI:** `bs` (tcp / udp / scan / pair / composite), `bs full`, `bc-nfconf`
- **AQ + time limit:** `--adaptive`, `--fan-out`, `--max-timeh` / `--max-timem`, graceful export on stop
- **BC2/GP curl repeats parity:** `--repeats` (1–10), `--parallel-repeats`, `--repeats-mode fast|stable`
- **B2 multi-domain fan-out:** `--curl-parallel` with googlevideo solo batches
- **Secure DNS + preflight:** DoH pre-resolve, DNS audit, IP-block cross-test (Phase 9)
- **Export:** keenetic + raw nfconf via `bs full` / `bc-nfconf`
- **Matrix M5–M7:** reverse/triple fake pairs, `http_tls_dual`, `udp_multiblob`
- **Global BC2 parity:** expanded foolings (`badsum`, IPv6), presets `bc2-parity-*`, fair-share `--max`
- **XDG layout:** `~/.config/blockcheckS/config.toml`, `~/.local/state/blockcheckS/` (state.db, export, logs, shortlists), `~/.cache/blockcheckS/`
- **DAO:** `engine/store/` — `RunStateStore` / `SqliteRunStore`; `db_logger.py` → deprecation shim
- **Docs:** `docs/cookbook/gp-bridge.md`, repeats glossary, `docs/package.md`, onboarding split
- **Scripts:** `scripts/release_smoke.sh` (Fryazino gate + B5 shortlist round-trip), `scripts/flag_campaign.py`

### Changed

- Version `0.3.0` → `1.0.0`
- `bs scan` — adaptive queue + time limit + optional `--out-dir` export
- `bs tcp` — `--repeats`, `--parallel-repeats`, `--repeats-mode`, `--max-timem`
- Runtime state moved from `~/.local/share/` to `~/.local/state/` per XDG spec
- Roadmap consolidated in `docs/todo.md` (removed root `research.md` / `GOALS.md` stubs)
- `--pair-max` applies to `bs full` only (not `bs pair`)

### Fixed

- Content validation redirect suffix match, curl timeout cap, HTTP/3 probe, CDN IP-block detect
- SQLite `busy_timeout=5000`, MANIFEST.in presets coverage, matrix default TCP sources
- DPI fake patterns single source; duplicate strategies/domains in presets
- `bs pair --adaptive`: run UDP pair matrix after AQ TCP (was TCP-only)
- Curl worker wall timeout scales with `--repeats` (`worker_wall_timeout`)
- AQ `pop_batch` solos googlevideo (match B2 `fanout_batches`)
- Pair resume: **completed-set only** from `pair_results` (idx skip removed — unsafe with parallel pairs)
- `bs full` pair phase passes `--resume` checkpoint + fingerprint
- `family_needs.finish_family` clears needs for `fakedsplit` / `fakeddisorder`
- THROTTLED counts as working for export / coverage / pair selection
- Pair rebuild preserves THROTTLED via `get_working_tcp_details` / `tcp_results_from_details`
- Removed orphan `pair_runner` / `pair_manager`; composite uses JSON curl worker
- Netns base allowlist; resolv.conf via `tee` (no `bash -c`)
- `ensure_strategy` sets `busy_timeout`; GV tiny 206 no longer auto-PASS
- SQLite views `v_working_tcp` / `v_coverage` / `v_latest_run` treat THROTTLED as working
- Sudo→user DB reclaim (`reclaim_sudo_ownership`); composite comma-domain normalize; deadline `stop_event`
- nfqws2 daemon copies config to temp before injecting `--daemon` (no mutate of `configs/*.conf`)

### Quality

- Unit tests via `pytest -m "not integration"`; `ruff check src tests` clean
- Fryazino release smoke + flag campaign product gates (BC2 parity markers, pair resume, shortlist/nfconf)
- Install contract: editable/checkout required for `configs/` (ONB-7); blobs on host `/opt/zapret2/blobs/`
