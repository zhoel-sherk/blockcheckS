# blockchecks

Asynchronous DPI (Deep Packet Inspection) strategy testing framework for
**nfqws2** / **zapret2**.

It runs thousands of desync strategies against target domains inside isolated
network namespaces, using a browser-grade TLS fingerprint (JA4 via curl_cffi),
and reports which combinations actually work on a given network. Results are
stored in SQLite and can be exported to ready-to-use nfqws2 configuration
files for Keenetic / OpenWrt / Linux routers.

## Features

- **Fast**: ~1 test/sec (33× faster than the reference `blockcheck.sh`) via
  asyncio + a reused netns pool.
- **Accurate**: browser-grade JA4 TLS fingerprint (Chrome BoringSSL), content
  validation, DPI fake-detection.
- **TCP + UDP**: TCP strategy families, HTTP :80, QUIC/HTTP3, and Discord
  Voice UDP endpoint discovery (STUN + IP Discovery).
- **Resilient**: checkpoint/resume, SQLite state, adaptive priority queue.
- **Tooling**: static strategy validator (offline, 9+ rules), custom Lua
  registry, MCP server for LLM agents.
- **Portable**: installs on x86_64, arm64 and armv7l (Raspberry Pi 2+) without
  compiling native dependencies.

## Requirements

- Linux with root (needed for network namespaces + iptables)
- Python 3.10+
- nfqws2 / zapret2 (auto-fetched on first run)

## Quick start

```bash
pip install blockchecks

# First scan — ~30 strategies against discord.com
sudo bs scan -d discord.com --generate --parallel 4

# Resume after interruption (checkpoint/resume)
sudo bs scan -d discord.com --generate --resume
```

## Export a router config

```bash
# default: ~/.local/share/blockcheckS/export/nfqws2_<ts>.conf (+ raw, user.list)
bc-nfconf --db logs/run.db --out-dir /path/to/out

# optional: add an IP filter from the DNS cache (no DNS needed on the router)
bc-nfconf --db logs/run.db --out-dir /path/to/out --ipset
```

## Documentation

- [User guide](https://github.com/zhoel-sherk/blockcheckS/blob/master/docs/guide.md)
- [Architecture](https://github.com/zhoel-sherk/blockcheckS/blob/master/docs/architecture.md)
- [MCP server](https://github.com/zhoel-sherk/blockcheckS/blob/master/docs/mcp.md)
- [Changelog](https://github.com/zhoel-sherk/blockcheckS/blob/master/changelog.md)

## License

MIT — see [LICENSE](https://github.com/zhoel-sherk/blockcheckS/blob/master/LICENSE).

## Disclaimer

This software is an open-source analytical tool for educational, academic and
network-research purposes, intended for network administrators and systems
engineers to study DPI behaviors. Use entirely at your own risk.
