# tmp-scripts — blockcheckS research & test scripts

## Usage examples

### Async scan (TCP batch)
```bash
# Generate strategies from 'fake' generator
sudo python3 bs.py scan -d discord.com --generate fake --max 10 --parallel 4

# Multi-source
sudo python3 bs.py scan -d discord.com --generate fake,faked,hostfake --max 50 --parallel 4

# Custom list (blockcheck2.d format)
sudo python3 bs.py scan -d discord.com --generate custom --max 20

# User matrix
sudo python3 bs.py scan -d discord.com --user-matrix /path/to/strategies.txt

# Resume after crash
sudo python3 bs.py scan -d discord.com --generate fake --resume
```

### Pair matrix (TCP×UDP)
```bash
# Basic pair
sudo python3 bs.py pair -d discord.com --generate fake_multi --parallel 4

# With auto-discovery (needs sing-box)
sudo python3 bs.py pair -d discord.com --generate --auto-discover --full-voice

# UDP bypass
sudo python3 bs.py pair -d discord.com --generate --udp-bypass --parallel 4

# Specific sources
sudo python3 bs.py pair -d discord.com \
  --tcp-sources fake_multi,custom \
  --udp-sources custom \
  --parallel 4
```

### Legacy sync commands
```bash
sudo python3 bs.py tcp -d discord.com -c configs/simple_fake_alt2.conf
sudo python3 bs.py udp -c configs/udp_voice__fake_r6.conf --ip X.X.X.X
```

## User Matrix Format (--user-matrix)
```
# One strategy per line
# Lines starting with # are comments
fake:blob=stun:repeats=6:tcp_ts=-1000
fake:blob=max_ru:repeats=6:tcp_ts=-1000
hostfakesplit:tcp_md5:tcp_ts_up:repeats=1
```

## Architecture

See [docs/architecture.md](../docs/architecture.md) for data flow, module map, and CLI layout.

## Timeline
```
100 strategies × sync: ~500s
100 strategies × async 4: ~30s  (16x speedup)
100 strategies × async 8: ~15s  (33x speedup)
```
