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
# No VPN: local DNS finland* + Maks-gaming IP list + STUN alive filter
bs pair -d discord.com --generate --discover-dns 5
# VPN/gateway path (sing-box):
bs pair -d discord.com --generate --auto-discover 5
# Do not combine --discover-dns and --auto-discover (mutually exclusive).
# Archived third-party lists (GhostRooter, etc.) are not used.
```

## Adding your own

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
