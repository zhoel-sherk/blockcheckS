# Presets — domain & strategy lists

## Domain presets (`presets/domains/`)

One domain per line, `#` comments.

```bash
bs scan --preset discord              # 21 Discord domains
bs scan --preset google-youtube       # 23 YouTube CDN domains
bs scan --preset critical             # 4 most important
bs scan --preset coverage             # 37 domains, full GP coverage
bs scan --preset benchmark            # 8 domains, lightweight test
bs scan --preset cloudflare           # 9 Cloudflare domains
bs scan --preset amazon-aws           # 11 AWS domains
bs scan --preset diagnostic           # 1 domain: web.telegram.org
```

## Strategy presets (`presets/strategies/`)

BlockcheckS user-matrix format (one strategy per line, `#` comments).

```bash
bs scan -d discord.com -M gp-verified          # GP top-10 strategies
bs scan -d discord.com -M gp-custom-tls12      # GP custom TLS 1.2 test
bs scan -d discord.com -M gp-custom-tls13      # GP custom TLS 1.3 test
bs scan -d discord.com -M gp-voice             # Discord Voice UDP
bs scan -d discord.com -M blockcheckS-best      # Our best strategies
```

## Adding your own

```bash
# Create a file
echo "discord.com" >> presets/domains/my-service.txt
echo "fake:blob=stun:repeats=6:tcp_ts=-1000" >> presets/strategies/my-strats.tls

# Use it
bs scan --preset my-service
bs scan -d discord.com -M my-strats
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
