# Presets — domain & strategy lists

## Domain presets (`presets/domains/`)

One domain per line, `#` comments.

```bash
# --preset alone is enough (-d optional; first domain used as primary)
bs scan --preset discord              # 22 Discord domains
bs scan --preset google-youtube       # 23 YouTube CDN domains
bs scan -d discord.com --preset critical   # -d + preset: all preset domains
bs scan --preset coverage             # 40 domains, full GP coverage
bs scan --preset benchmark            # 6 domains, lightweight test
bs scan --preset cloudflare           # 9 Cloudflare domains
bs scan --preset amazon-aws           # 11 AWS domains
bs scan --preset diagnostic           # 1 domain: web.telegram.org
bs scan --list-presets                # list domain + strategy presets
```

## Strategy presets (`presets/strategies/`)

BlockcheckS user-matrix format (one strategy per line, `#` comments).
`-M` accepts basename with or without `.tls` / `.txt`.

```bash
bs scan -d discord.com -M gp-verified          # GP top-10 strategies
bs scan -d discord.com -M flowseal-fast        # curated Flowseal ALT2 (M8)
bs scan -d discord.com -M http-tls-dual.tls     # M6 TLS side (pair with .http)
bs scan -d discord.com -M gp-verified.tls      # same (extension stripped)
bs scan -d discord.com -M gp-custom-tls12      # GP custom TLS 1.2 test
bs scan -d discord.com -M gp-custom-tls13      # GP custom TLS 1.3 test
bs scan -d discord.com -M gp-voice             # Discord Voice UDP
bs scan -d discord.com -M blockcheckS-best     # Our best strategies
# unknown -M name → exit code 1
```

## Voice discover (pair / udp)

```bash
# No VPN: DNS finland* + Maks-gaming IP list + dual UDP probe
# (RFC5389 STUN, then Discord IP Discovery 74B). On Linux, probes run
# through a temporary nfqws2 UDP bootstrap (discord_udp) by default.
bs pair -d discord.com --generate --discover-dns 5
bs pair -d discord.com --generate --discover-dns 5 --discover-dns-no-bootstrap
# VPN/gateway path (sing-box):
bs pair -d discord.com --generate --auto-discover 5
# Do not combine --discover-dns and --auto-discover (mutually exclusive).
# Exact session UDP port needs voice Ready (token); we probe 50000–50006 only.
# Discover probes use concurrency=4 (higher can drop replies via NFQUEUE bypass).
# Archived third-party lists (GhostRooter, etc.) are not used.
```

## Smoke presets (Phase 11 A8)

Quick validation without full `coverage.txt` stress:

```bash
# 6 domains — benchmark preset
bs scan --preset benchmark -M gp-verified --scan-level fast --max 20

# 4 critical services
bs scan --preset critical -M gp-verified --scan-level single

# Settle × curl timeout grid (needs sudo + nfqws2)
sudo bs bench-settle -d discord.com -M timeout-benchmark

# Lean mass run default (13 domains, denylist applied)
sudo bs full --scan-level fast --max 100 --preset benchmark
# or explicit:
sudo bs full --domains-file presets/domains/coverage-tcp.txt --max 100
```

Presets: `benchmark.txt` (6 dom), `critical.txt` (4 dom), `coverage-tcp.txt` (14 dom),
`gp-verified.tls` (7 strategies), `timeout-benchmark.tls` (3 strategies for A9).

## Full mass run (`bs full`)

Runs strategy × every domain in `presets/domains/coverage-tcp.txt` by default (curl_cffi),
then voice discover, optional QUIC/pairs, and exports configs:

```bash
sudo bs full                    # uncapped matrix × coverage + export
sudo bs full --parallel 4 --curl-parallel 4 --scan-level fast --max 500
# curl-parallel=1 (default) — one domain per nfqws2 restart (safest)
sudo bs full --max 500          # shrink matrix
bc-nfconf --db state.db --limit 3 --out-dir output
```

## AQ time-boxed runs (`--max-timeh` / `--max-timem`)

Graceful shutdown: flush DB, export conf (unless `--no-export-on-stop`), write `run_summary_*.json`.

```bash
# ~2h budget, adaptive + B2, benchmark domains
sudo bs full --fan-out --allow-dns-hijack \
  --domains-file presets/domains/benchmark.txt \
  --max-timeh 2 --db logs/my_run.db --out-dir logs/my_export

# 90 min scan with AQ
sudo bs scan -d discord.com --generate fake,multi_fake \
  --adaptive --max-timem 90 --db state.db --out-dir logs/scan_export

# Sync tcp with time limit
sudo bs tcp -d discord.com --strategy "fake:blob=stun:repeats=6" --max-timem 15
```

Writes `output/nfqws2_<timestamp>.conf` (keenetic) + `nfqws2_raw_<timestamp>.conf`
+ `user.list`. GP historically logged ~515k success links / ~968k raw curl
attempts without curl_cffi — `bs full` is the curl_cffi replacement at that scale.

## Adding your own

See [docs/cookbook/](../docs/cookbook/) for step-by-step guides.

```bash
# Create a file
echo "discord.com" >> presets/domains/my-service.txt
echo "fake:blob=stun:repeats=6:tcp_ts=-1000" >> presets/strategies/my-strats.tls

# Use it
bs scan --preset my-service
bs scan -d discord.com -M my-strats
bs scan -d discord.com -M my-strats.tls
```

## Format

**Domains** — one FQDN per line:
```
discord.com
discord.gg
```

**Strategies** — blockcheckS user-matrix format:
```
fake:blob=stun:repeats=6:tcp_ts=-1000
hostfakesplit:nofake2:tcp_md5:repeats=1
```

## Built-in vs file blobs (BLOB-4)

Strategy strings use **short aliases** (`stun`, `google`, `quic_gv_kyber_1`, …). Resolution order:

| Kind | Examples | Source |
|------|----------|--------|
| **Built-in** | `fake_default_tls`, `fake_default_http`, `fake_default_quic` | nfqws2 internal (no `.bin` file) |
| **File aliases** | `stun`, `max_ru`, `google`, `discord_udp`, `quic_dbank` | `/opt/zapret2/blobs/` or `files/fake/` |

Canonical alias map: `src/blockchecks/engine/blob_aliases.py` (`BLOB_ALIAS_MAP`).

```bash
# Install / refresh blobs from Flowseal + zapret2 stock
scripts/install_blobs.sh

# Verify all 22 aliases resolve
python3 scripts/verify_blobs.py

# Per-blob docs
cat presets/blobs/README.md
```

Built-in blobs need no install step. File blobs must exist before scan; missing blobs fail at nfqws2 start with a clear path error.

## GP shortlist export (P5-1)

Export winners for GP orchestrator (replaces blockcheck2 stdout parsing):

```bash
python3 -m blockchecks.shortlist_export --db state.db -o logs/shortlist.json
scripts/export_shortlist_json.sh state.db logs/shortlist.json

# Import back into presets / seed state.db
python3 -m blockchecks.shortlist_import -i logs/shortlist.json --seed-db --db state.db
```

Schema: `blockchecks.shortlist/v1` — see `logs/shortlist.json` example after export.
