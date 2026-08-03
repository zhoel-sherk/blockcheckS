# Architecture — blockcheckS

Canonical data-flow reference for the async scan path (1.1+).

## Main runtime flow (`bs scan` / `bs pair` / `bs full`)

```mermaid
sequenceDiagram
  participant CLI as bs_or_main
  participant DNS as DoH_dns_secure
  participant PF as preflight
  participant MG as MatrixGenerator
  participant AQ as AdaptiveQueue_optional
  participant AR as AsyncTestRunner
  participant NP as NetNsPool
  participant NFQ as nfqws2_daemon
  participant CURL as curl_cffi_subprocess
  participant DB as StateDB

  CLI->>DNS: prepare_dns_for_run domains
  CLI->>PF: baseline reachability
  CLI->>MG: generate strategies
  CLI->>AQ: optional fan-out / adaptive
  CLI->>AR: test_batch_tcp / test_pair_matrix
  AR->>NP: acquire netns worker
  AR->>NFQ: start_daemon in netns
  AR->>CURL: invoke_curl_probe_worker GV-3
  CURL-->>AR: status latency content
  AR->>DB: log tcp_udp_pair results
  AR->>NP: release netns pkill flush
  CLI->>DB: finalize export nfconf
```

## NetNsPool scale (parallel workers)

Isolation is **per network namespace**, not distinct host NFQUEUE numbers.
Workers reuse qnum 200 (TCP) / 201 (UDP) **inside** each ns — queues are
netns-local, so `--parallel N` does not collide across workers.

```mermaid
flowchart TB
  subgraph host [Host]
    CLI[AsyncTestRunner Semaphore]
    Pool[NetNsPool bs-p-0..N]
    NAT[FORWARD + MASQUERADE]
    CLI --> Pool
  end
  subgraph ns0 [netns bs-p-0]
    IPT0[iptables OUTPUT q200 q201]
    N0[nfqws2 per strategy]
    C0[curl subprocess]
    C0 --> IPT0 --> N0
  end
  subgraph ns1 [netns bs-p-1]
    IPT1[own iptables]
    N1[own nfqws2]
  end
  Pool --> ns0
  Pool --> ns1
  ns0 --> NAT
```

Throughput lever on a Xeon-class host: raise `--parallel` first.
`nftables` vmap multiplexing (todo B7) is for host-shared / mark→queue designs,
**not** a prerequisite for `parallel > 4` under the current netns model.
Pi2 / ~1 GB RAM: keep `--parallel 1` (max 2).

## Module map

| Task | Module |
|------|--------|
| CLI / argparse | `blockchecks.cli` (entry: `bs.py`) |
| Mass orchestration | [`main.py`](../src/blockchecks/main.py) |
| Strategy matrix | [`engine/matrix_generator.py`](../src/blockchecks/engine/matrix_generator.py) |
| Domain loader + denylist | [`engine/domain_loader.py`](../src/blockchecks/engine/domain_loader.py) |
| Preset path jail | [`cli/presets.py`](../src/blockchecks/cli/presets.py) |
| Preflight | [`engine/preflight.py`](../src/blockchecks/engine/preflight.py) |
| Parallel TCP/UDP/pair | [`engine/async_runner.py`](../src/blockchecks/engine/async_runner.py) |
| Curl probe public API | [`engine/probe.py`](../src/blockchecks/engine/probe.py) |
| Curl probe subprocess | [`engine/_curl_probe_worker.py`](../src/blockchecks/engine/_curl_probe_worker.py) |
| Sync single-ns | [`engine/test_runner.py`](../src/blockchecks/engine/test_runner.py) |
| Adaptive runner / queue | `adaptive_runner.py`, `adaptive_queue.py` |
| TCP fan-out | [`engine/tcp_fanout.py`](../src/blockchecks/engine/tcp_fanout.py) |
| nfqws2 lifecycle | [`engine/nfqws2.py`](../src/blockchecks/engine/nfqws2.py) |
| netns + iptables | `netns_pool.py`, `firewall.py` |
| System deps / zapret2 fetch | [`engine/system_deps.py`](../src/blockchecks/engine/system_deps.py) |
| XDG paths | [`engine/paths.py`](../src/blockchecks/engine/paths.py) |
| TLS / content / DoH | `checkers/tcp_tls`, `curl_probe`, `dns_secure` |
| Voice UDP / discover | `udp_voice`, `voice_dns`, `voice_discovery` |
| Composite config test | [`checkers/composite_runner.py`](../src/blockchecks/checkers/composite_runner.py) |
| Export keenetic | `nfconf.py`, `conf_builder.py` |
| Persistence | `engine/store/` (RunStateStore / SqliteRunStore) |

## Canonical vs legacy paths

| Command | Runner | Notes |
|---------|--------|-------|
| `bs scan`, `bs pair` | **async** `async_runner` | canonical |
| `bs full` | **async** via `main.py` | mass matrix |
| `bs tcp`, `bs udp` | **sync** `test_runner` | single strategy |
| `bs composite` | one netns + one nfqws2 | multi-domain config |

Known limitation: `bs scan` forces `auto_discover=None` (see [guide.md](guide.md)).

## Voice discovery (discover-dns vs auto-discover)

UDP bootstrap does **not** run before `--auto-discover`. Paths are **mutually
exclusive** (`check_discover_mutex` in `voice_dns.py`).

```mermaid
flowchart TD
  start[pair_or_full_needs_voice_EP]
  mutex{discover_dns XOR auto_discover}
  dnsPath["--discover-dns N"]
  autoPath["--auto-discover N"]
  dnsResolve[resolve_finland_range + Maks IPs]
  bootDefault{bootstrap default on}
  bootSkip["--discover-dns-no-bootstrap"]
  bootNfq["udp_discover_bootstrap: nfqws2 q201 discord_udp fake"]
  dualProbe[STUN + IP Discovery 74B concurrency=4]
  aliveEP[alive endpoints list]
  singbox[sing-box SOCKS5 proxy]
  gwWS[Discord Gateway WS + Voice WS OP2]
  opReady[OP2 Ready: ip port ssrc]
  useEP[eps0 in pair matrix]

  start --> mutex
  mutex --> dnsPath
  mutex --> autoPath
  dnsPath --> dnsResolve --> bootDefault
  bootDefault -->|yes default| bootNfq --> dualProbe
  bootDefault -->|no| bootSkip --> dualProbe
  dualProbe --> aliveEP --> useEP
  autoPath --> singbox --> gwWS --> opReady --> useEP
  useEP --> eps0["pair matrix: eps0 only — V2-1 WIP"]
```

| Step | discover-dns | auto-discover |
|------|--------------|---------------|
| VPN | not required | sing-box SOCKS5 (`BLOCKCHECKS_PROXY`) |
| UDP bootstrap | **default on** (host NFQUEUE q201, `discord_udp`) | no |
| Opt-out | `--discover-dns-no-bootstrap` | — |
| Probe | STUN + IP Discovery on host | Gateway WS → Voice WS |
| Mutex | cannot combine with `--auto-discover` | cannot combine with `--discover-dns` |
| Code | `voice_dns.discover_dns_alive` | `voice_discovery` |
| Discord token | not needed | `BLOCKCHECKS_SETTINGS` (refuse world-writable) |

Bootstrap is recommended on DPI networks but **not hard-fail** — on error,
probing continues without nfqws2.

## googlevideo probe (GV-1 current)

Signed `videoplayback` URLs via yt-dlp cache (`bs_gv_url_cache.json`) are the
**current** path (`prepare_googlevideo_probe` / GV-3 worker). Apex
`https://googlevideo.com` alone is not the success criterion.

```mermaid
flowchart TD
  domGV[domain contains googlevideo]
  ytdlp[get_fresh_url via yt-dlp]
  cache[GV_URL_CACHE_FILE TTL]
  signedURL[signed videoplayback URL]
  nfqTCP[nfqws2 TCP in netns]
  curlVP[curl_cffi subprocess Range chunk]
  resultChunk[206 content_ok]
  domGV --> ytdlp --> cache --> signedURL --> nfqTCP --> curlVP --> resultChunk
```

## DNS resolution

**Default:** DoH pre-resolve (`dns_secure` / `prepare_dns_for_run`) when secure DNS
is enabled; netns still has `nameserver 8.8.8.8` as fallback for unresolved
lookups. `--no-secure-dns` skips DoH.

## Public vs internal API

**Public (stable):**

- Entry points: `bs`, `bc-main`, `bc-nfconf`
- `blockchecks.engine.StrategyItem`, `StateDB`, `matrix_fingerprint`
- `blockchecks.engine.probe.invoke_curl_probe_worker`, `probe_request_dict`
- `blockchecks.checkers.TlsResult`, `check_tls`
- `conf_builder.build_keenetic_conf`, `build_raw_conf`
- `cli.presets.resolve_domain_preset`, `resolve_strategy_preset`

**Internal (do not import from outside):**

- `_nfqws2_daemon` (→ unified `nfqws2.start_daemon` in 1.1), private settle helpers

See [package.md](package.md) for import graph. Operational guide: [guide.md](guide.md).
