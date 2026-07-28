# blockcheckS — lightspeed DPI strategy tester

Замена `blockcheck.sh` / blockcheckw: быстрый подбор DPI-стратегий для
zapret2/nfqws2 с репрезентативными проверками (curl_cffi JA4, netns,
TCP×UDP matrix, checkpoint/resume).

## Установка

```bash
pip install -e ".[dev,discovery]"
# CLI:
bs --help
# или
python -m blockchecks.bs --help
```

Linux host с zapret2/nfqws2 и root (netns + iptables). Unit-тесты — без root.

## Отличия от blockcheck.sh

| blockcheck.sh | blockcheckS |
|--------------|-------------|
| ~60-120s на стратегию | ~3-5s на стратегию (parallel netns) |
| Curl/OpenSSL | curl_cffi / BoringSSL (браузерный JA4) |
| В основном TCP | TCP + UDP voice (STUN) |
| Последовательный shell | asyncio + NetNsPool |
| Легко «ложно-зелёный» | Контрактные pytest + content/DPI checks |

## Структура (v0.3)

```
blockcheckS/
├── src/blockchecks/     # пакет
│   ├── bs.py            # CLI: tcp | udp | scan | pair | composite
│   ├── engine/          # nfqws2, firewall, matrix, async runner, DB
│   └── checkers/        # tcp_tls, udp_voice, voice_dns/discovery
├── configs/             # nfqws2 .conf (Flowseal→zapret2)
├── tests/unit|integration/
├── docs/                # guide.md, todo.md
└── pyproject.toml
```

## Быстрый старт

```bash
# TCP batch
sudo bs scan -d discord.com --generate --parallel 4

# TCP×UDP pair matrix
sudo bs pair -d discord.com --generate --auto-discover 5

# Один .conf
sudo bs tcp -d discord.com -c configs/simple_fake__fake_ts.conf
sudo bs composite -c configs/composite_discord.conf

# Тесты (Windows/dev OK)
pytest -m "not integration"
```

Подробнее: [docs/guide.md](docs/guide.md). План: [docs/todo.md](docs/todo.md).

## Status

Пакет `blockchecks` 0.3.0: scan/pair/async, checkpoint fingerprint, unit suite.
Дальше — покрытие матриц bol-van/zapret2 и flowseal-like (см. todo).
