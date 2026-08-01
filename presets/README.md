# Presets — domain & strategy lists

## Domain presets (`presets/domains/`)

One domain per line, `#` comments.

```bash
# --preset alone is enough (-d optional; first domain used as primary)
bs scan --preset discord              # 21 Discord domains
bs scan --preset google-youtube       # 23 YouTube CDN domains
bs scan -d discord.com --preset critical   # -d + preset: all preset domains
bs scan --preset coverage             # 37 domains, full GP coverage
bs scan --preset benchmark            # 8 domains, lightweight test
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

Presets: `benchmark.txt` (6 dom), `critical.txt` (4 dom), `coverage-tcp.txt` (13 dom),
`gp-verified.tls` (7 strategies), `timeout-benchmark.tls` (3 strategies for A9).

## Full mass run (`bs full`)

Runs strategy × every domain in `presets/domains/coverage-tcp.txt` by default (curl_cffi),
then voice discover, optional QUIC/pairs, and exports configs:

```bash
sudo bs full                    # uncapped matrix × coverage + export
sudo bs full --parallel 2 --resume
sudo bs full --max 500          # shrink matrix
bc-nfconf --db state.db --limit 3 --out-dir output
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
