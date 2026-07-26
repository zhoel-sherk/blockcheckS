# blockcheckS — lightspeed DPI strategy tester

Замена стандартного `blockcheck.sh` из zapret2. В ~10 раз быстрее,
с поддержкой UDP-стратегий и легитимными TLS-отпечатками браузеров.

## Отличия от blockcheck.sh

| blockcheck.sh | blockcheckS |
|--------------|-------------|
| ~60-120s на стратегию | ~3-5s на стратегию |
| Curl с OpenSSL (JA4 t13d0202) | curl_cffi с BoringSSL (JA4 t13d1516h2) |
| Только TCP (HTTP/HTTPS/QUIC) | TCP + UDP (Discord voice, игры) |
| Последовательный перебор | Параллельный (8-16 потоков) |
| Shell-скрипт (~3000 строк) | Python (~500 строк) |
| Нет изоляции | Network namespace изоляция |
| Нет JA4 fingerprinting | 8 браузерных JA4 профилей |

## Архитектура

```
blockcheckS/
├── bs.py              # main: strategy discovery engine
├── strategies/         # built-in strategy sets
│   ├── tcp_tls.txt    # TLS strategies
│   ├── tcp_http.txt   # HTTP strategies
│   ├── udp_voice.txt  # Discord voice UDP
│   └── quic.txt       # QUIC/HTTP3
├── checkers/           # connectivity validators
│   ├── tcp_tls.py     # curl_cffi TLS check
│   ├── tcp_http.py    # HTTP check
│   ├── udp_stun.py    # STUN binding check
│   └── dns.py         # DNS tampering check
├── configs/            # nfqws2 config templates
└── reports/            # JSON output
```

## Режимы

```bash
# Быстрый скан: TCP TLS для доменов
sudo python3 bs.py --mode tcp --domains "youtube.com,discord.com"

# Полный скан: TCP + UDP + QUIC
sudo python3 bs.py --mode all --domains "discord.com"

# Кастомные стратегии из файла
sudo python3 bs.py --strategies my_strategies.txt --domains "discord.media"

# Параллельный режим
sudo python3 bs.py --mode tcp --parallel 8 --domains "youtube.com,discord.com"
```

## Status

**Phase 1 (current):** проектирование, базовая архитектура
**Phase 2:** TCP стратегии (curl_cffi + nfqws2)
**Phase 3:** UDP стратегии (STUN + DTLS для Discord voice)
**Phase 4:** QUIC стратегии
**Phase 5:** WebUI + GP-control-plane интеграция
