# blockcheckS — Research & Architecture

## 1. Why Replace blockcheck.sh?

blockcheck.sh (1948 строк shell) — проверенный, но медленный инструмент. Его главные ограничения:

| Проблема | Влияние |
|----------|---------|
| nfqws2 restart на каждую стратегию | 1000+ запусков/остановок daemon'а |
| Curl + OpenSSL (JA4 `t13d0202`) | Небраузерный TLS fingerprint — DPI может блокировать сам OpenSSL |
| Только последовательный перебор | 2s timeout × 1000 стратегий = 2000+s |
| Shell eval для каждой строки | Медленный парсинг |
| Нет UDP кроме QUIC | Discord voice, игры — не тестируются |
| 5 firewall бэкендов | Избыточно для Linux-only использования |

**Цель blockcheckS:** протестировать тот же набор стратегий в **~10 раз быстрее**, с легитимными TLS-отпечатками браузеров, и добавить UDP voice тестирование.

---

## 2. Анализ blockcheck.sh

### 2.1 Архитектура тестирования

```
main()
 ├── check_system()         → OS detection, firewall type, curl capabilities
 ├── check_prerequisites()  → verify binaries, kernel modules
 ├── check_dns()            → DNS spoofing check + DoH fallback
 ├── ask_params()           → TEST, DOMAINS, IPVS, REPEATS, SCANLEVEL
 │
 └── for domain in DOMAINS:
     └── for ipv in [4,6]:
         ├── if HTTP:   check_domain_http(domain)
         ├── if TLS12:  check_domain_https_tls12(domain)
         ├── if TLS13:  check_domain_https_tls13(domain)
         └── if HTTP3:  check_domain_http3(domain)
             │
             └── check_domain_http_tcp/udp()
                 ├── check_domain_prolog()           # тест без обхода — нужен ли вообще?
                 ├── check_dpi_ip_block()            # IP vs SNI блокировка
                 ├── pktws_ipt_prepare_tcp/udp()     # ★ firewall rules (1 раз за фазу)
                 ├── pktws_check_domain_http_bypass()
                 │   └── test_runner(func_name)       # ★ загружает все *.sh из TEST/
                 │       └── for each strategy variant:
                 │           ├── pktws_start(args)    # ★ START nfqws2
                 │           ├── curl_test()          # curl --max-time 2
                 │           ├── ws_kill()            # ★ KILL nfqws2
                 │           └── if success: record
                 └── pktws_ipt_unprepare_tcp/udp()   # cleanup
```

### 2.2 Главное узкое место: pktws_start → ws_kill

Каждый вызов `pktws_curl_test_update()` запускает и убивает nfqws2:

```bash
# ~1000 раз за полный скан:
pktws_start "$PKTWS_OPT $1"    # spawn nfqws2 daemon
minsleep                        # wait for init
curl_test ...                   # curl (2-6s)
ws_kill                         # kill -9 + wait
```

**Решение для blockcheckS:** держать nfqws2 запущенным, менять конфиг через `--lua-desync=...` без перезапуска. Или: перезапускать только при смене несовместимых параметров (qnum, filter-*, blobs).

### 2.3 Стандартные стратегии (13 файлов, ~1000 вариантов)

| Файл | Стратегии | Кол-во вариантов |
|------|-----------|:---:|
| `10-http-basic.sh` | HTTP hostname tricks | ~5 |
| `15-misc.sh` | tcpseg + ip_id=rnd | ~32 |
| `17-oob.sh` | Out-of-band data | ~12 |
| `20-multi.sh` | multisplit/multidisorder | ~50 |
| `23-seqovl.sh` | Sequence overlap | ~80 |
| `24-syndata.sh` | SYN data injection | ~60 |
| `25-fake.sh` | Fake packets + TTL/fooling | ~128 |
| `30-faked.sh` | Fake + disorder | ~120 |
| `35-hostfake.sh` | Hostname-level fake | ~128 |
| `50-fake-multi.sh` | Fake + multisplit | ~120 |
| `55-fake-faked.sh` | Fake + faked-split | ~120 |
| `60-fake-hostfake.sh` | Fake + hostfake | ~128 |
| `90-quic.sh` | QUIC/HTTP3 fake | ~15 |

### 2.4 Кастомные стратегии (custom/)

Формат: текстовые файлы со строками — готовый nfqws2 args.

```
list_http.txt          → HTTP стратегии
list_https_tls12.txt   → HTTPS TLS 1.2
list_https_tls13.txt   → HTTPS TLS 1.3
list_quic.txt          → QUIC/HTTP3
list_udp_voice.txt     → Discord Voice UDP (добавлен нами)
```

Каждая непустая/некомментная строка → `pktws_curl_test_update()`.

### 2.5 Протоколы и тестовые функции

| Протокол | Функция curl | Порт | Транспорт | Payload filter |
|----------|-------------|------|-----------|----------------|
| HTTP | `curl_test_http` | 80 | TCP | `--payload=http_req` |
| HTTPS TLS 1.2 | `curl_test_https_tls12` | 443 | TCP | `--payload=tls_client_hello` |
| HTTPS TLS 1.3 | `curl_test_https_tls13` | 443 | TCP | `--payload=tls_client_hello` |
| HTTP3/QUIC | `curl_test_http3` | 443 | UDP | `--payload=quic_initial` |

### 2.6 Firewall (только Linux)

```
iptables -t mangle -A OUTPUT -d <target_ip> -p tcp --dport <port> \
  -j MARK --set-mark 0x10000000
iptables -t mangle -A OUTPUT -m mark --mark 0x10000000 \
  -p tcp --dport <port> -j NFQUEUE --queue-num <qnum>
```

nfqws2 получает пакеты через NFQUEUE, модифицирует, возвращает VERDICT.

---

## 3. Архитектура blockcheckS (Python)

### 3.1 Модули

```
blockcheckS/
├── bs.py                  # Main entry point + CLI
├── engine.py              # ★ Core: strategy testing engine
│   ├── Nfqws2Manager       # nfqws2 lifecycle (start, reconfigure, stop)
│   ├── StrategyLoader      # Load strategies from files (standard + custom)
│   ├── TestRunner          # Run strategies against domains
│   └── ResultCollector     # Record results, dedup, intersection
├── checkers/               # Connectivity validators
│   ├── tcp_http.py         # curl_cffi HTTP check
│   ├── tcp_tls.py          # curl_cffi HTTPS TLS 1.2/1.3 check
│   ├── udp_stun.py         # STUN binding check
│   └── dns.py              # DNS tampering check
├── fw.py                   # Firewall management (iptables/nftables)
├── strategies/             # Built-in strategy sets (ported from blockcheck2.d/)
│   ├── standard/           # 13 original scripts → Python generators
│   └── custom/             # Text-based strategy lists
├── configs/                # nfqws2 config templates
└── reports/                # JSON output
```

### 3.2 Nfqws2Manager — reuse вместо restart

```python
class Nfqws2Manager:
    """Управляет жизненным циклом nfqws2.

    Ключевая оптимизация: НЕ перезапускать daemon между стратегиями.
    Только при смене несовместимых параметров (qnum, filter-*, blobs).
    """

    def start(self, base_args: list[str]) -> None:
        """Запустить nfqws2 с базовыми аргументами (qnum, filter-*, lua-init, hostlist)."""

    def reconfigure(self, strategy_args: list[str]) -> None:
        """Применить новую стратегию БЕЗ перезапуска.
        Отправляет SIGHUP или переписывает конфиг-файл."""

    def stop(self) -> None:
        """Остановить nfqws2."""

    def needs_restart(self, new_args: list[str]) -> bool:
        """Проверить, требуют ли новые аргументы перезапуска."""
```

### 3.3 StrategyLoader

```python
class StrategyLoader:
    """Загружает стратегии из файлов и генерирует варианты."""

    def load_standard(self, test_dir: str) -> list[Strategy]:
        """Загрузить .sh файлы из blockcheck2.d/<test_dir>/.
        Портируем логику скриптов в Python-генераторы."""

    def load_custom(self, test_dir: str, protocol: str) -> list[str]:
        """Загрузить строки из list_*.txt файлов."""

    def generate_variants(self, base: Strategy) -> list[Strategy]:
        """Размножить стратегию с вариациями TTL, fooling, repeats."""
```

### 3.4 TestRunner — параллельное тестирование

```python
class TestRunner:
    """Запускает стратегии параллельно."""

    def __init__(self, nfqws2: Nfqws2Manager, checkers: dict, max_workers: int = 8):
        ...

    async def test_strategy(self, strategy: str, domain: str) -> Result:
        """Протестировать одну стратегию:
        1. nfqws2.reconfigure(strategy)
        2. curl_cffi check (async)
        3. return Result(success, latency, http_status, error)
        """

    async def test_batch(self, strategies: list[str], domain: str) -> list[Result]:
        """Параллельный запуск группы стратегий."""
```

### 3.5 curl_cffi checker

```python
async def check_tls(domain: str, protocol: str = "tls12", timeout: float = 2.0) -> CheckResult:
    """Проверить TLS-соединение через curl_cffi с браузерным fingerprint."""
    try:
        resp = curl_cffi.get(
            f"https://{domain}",
            impersonate="chrome124",
            http_version=2,
            timeout=timeout,
        )
        return CheckResult(success=200 <= resp.status_code < 400,
                          http_status=resp.status_code,
                          latency_ms=...)
    except curl_cffi.CurlError as e:
        return CheckResult(success=False, error=str(e))
```

**Преимущество перед OpenSSL:** curl_cffi использует BoringSSL (JA4 `t13d1516h2` вместо `t13d0202`). DPI не блокирует браузерные отпечатки.

---

## 4. Ожидаемое ускорение

### Текущая производительность (blockcheck.sh)

```
1 стратегия = start(0.3s) + curl(2.0s) + kill(0.2s) = ~2.5s
1000 стратегий × 2.5s = 2500s (~42 минуты)
```

### Ожидаемая производительность (blockcheckS)

```
Переиспользование nfqws2:     start(0.3s) однократно
Параллельный curl:            8 стратегий одновременно
reconfigure (без перезапуска): ~0.01s

1000 стратегий / 8 parallel × 2.0s curl = ~250s (~4 минуты)
```

**Ускорение: ~10x (42 мин → 4 мин)**

### Для custom-тестов (10-20 стратегий)

```
20 стратегий / 4 parallel × 2.0s = ~10 секунд
```

---

## 5. Фазовый план

### Phase 1: MVP — TCP TLS стратегии (неделя 1)

**Объём:** Только HTTPS TLS 1.2 + TLS 1.3. Один протокол, один транспорт.

- [x] `fw.py` — iptables OUTPUT mangle + NFQUEUE (только Linux)
- [ ] `Nfqws2Manager` — start, reconfigure, stop
- [ ] `StrategyLoader` — load custom list files
- [ ] `TestRunner` — async parallel curl_cffi
- [ ] `checkers/tcp_tls.py` — curl_cffi Chrome impersonation
- [ ] `bs.py` — CLI: `--mode tcp --domains "discord.com"`
- [ ] Тест на 20 custom-стратегиях → должно быть < 30 секунд

### Phase 2: UDP + QUIC (неделя 2)

- [ ] `checkers/udp_stun.py` — STUN binding для Discord voice
- [ ] `checkers/tcp_http.py` — HTTP проверка
- [ ] QUIC стратегии (порт из blockcheck2.d/standard/90-quic.sh)
- [ ] Discord voice UDP (list_udp_voice.txt)
- [ ] `--mode all` — все протоколы

### Phase 3: Стандартные стратегии (неделя 2-3)

- [ ] Портировать 13 `.sh` скриптов → Python генераторы
- [ ] `strategies/standard/` — mirror структуры blockcheck2.d/standard/
- [ ] TTL/fooling/autottl вариации как параметры генератора
- [ ] `--mode standard` — полный набор

### Phase 4: GP-интеграция (неделя 3-4)

- [ ] Совместимость с GP custom TEST директорией
- [ ] JSON-вывод для GP парсинга
- [ ] WebUI: кнопка "Run blockcheckS" в GP
- [ ] Бенчмарк: blockcheck.sh vs blockcheckS (ожидаем 8-12x)

---

## 6. Интеграция с GP-control-plane

### Путь интеграции

```
GP WebUI → "Run Strategy Test" → blockcheckS.py
                                    ├── загружает стратегии из blockcheck2.d/{TEST}/
                                    ├── тестирует через nfqws2 + curl_cffi
                                    ├── возвращает JSON: [{strategy, domain, success, latency}]
                                    └── GP записывает в strategy_domain_results
```

### Совместимость с существующими custom-тестами

blockcheckS должен читать те же файлы что и blockcheck.sh:
```
/opt/zapret2/blockcheck2.d/custom/list_https_tls12.txt
/opt/zapret2/blockcheck2.d/custom/list_udp_voice.txt
```

### Формат вывода для GP

```json
{
  "test": "custom",
  "domain": "discord.com",
  "protocol": "tls12",
  "results": [
    {"strategy": "--lua-desync=fake:blob=...:repeats=6", "success": true, "latency_ms": 488, "http_status": 200},
    {"strategy": "--lua-desync=hostfakesplit:...", "success": false, "latency_ms": 2005, "error": "timeout"}
  ],
  "summary": {"total": 20, "passed": 15, "failed": 5, "time_sec": 12.3}
}
```

---

## 11. Тройное сравнение: blockcheck.sh vs blockcheckw vs blockcheckS

| | blockcheck.sh | blockcheckw | **blockcheckS** |
|---|:---:|:---:|:---:|
| **Язык** | Bash | Rust | **Python 3.11+** |
| **Скорость** | ~1 strat/s | ~150 strat/s | ⏳ цель: ~50 strat/s |
| **UDP/QUIC** | ✅ curl --http3 | ❌ | ✅ **Discord voice + STUN + QUIC** |
| **UDP Discord voice** | ❌ | ❌ | ✅ **Flowseal blob** |
| **TLS fingerprint** | OpenSSL | rustls | **curl_cffi BoringSSL (JA4 t13d1516h2)** |
| **Firewall** | iptables + nftables | nftables vmap (O(1)) | nftables vmap + iptables |
| **Parallel** | ❌ sequential | ✅ tokio async (до 2048 workers) | ✅ asyncio (8-16 workers) |
| **Flowseal blobs** | ❌ | ❌ | ✅ **встроенная поддержка** |
| **Data transfer check** | ❌ | ✅ 32KB minimum | ✅ 32KB minimum |
| **DPI cap detection** | ❌ | ✅ 10-25KB | ✅ |
| **Block classification** | binary | 7-level | 7-level (портировано) |
| **DNS spoof detection** | ✅ | ✅ | ✅ |
| **Strategy corpus** | ~1000 (generated) | 13,943 (pre-dumped) | гибрид: generators + custom lists |
| **nfqws2 lifecycle** | restart per strat | restart per strat | **reuse (reconfigure без restart)** |
| **Output** | text | JSON + vanilla text | JSON + vanilla text |
| **GP integration** | ✅ custom TEST | ❌ | ✅ **native GP JSON output** |
| **Binaries** | N/A | x86_64, arm64, mips, ppc... | кроссплатформен (Python) |

---

## 12. Зависимости

### Python
- `curl_cffi>=0.14` — браузерные TLS-отпечатки
- `asyncio` — параллельный I/O
- `pyroute2` (опционально) — netlink вместо subprocess для iptables

### Системные
- nfqws2 (`/opt/zapret2/nfq2/nfqws2`)
- iptables (или nftables)
- Lua скрипты (`zapret-lib.lua`, `zapret-antidpi.lua`, `zapret-auto.lua`)

### Блобы
- `discord_udp.bin` — Discord voice (Flowseal)
- `tls_clienthello.bin` — TLS ClientHello
- Остальные из `/opt/zapret2/blobs/`

---

## 8. Анализ blockcheckw (Rust, rcd27)

### 8.1 Что такое blockcheckw

Rust-замена blockcheck.sh. **150x быстрее** (9000 стратегий за ~2 мин vs ~90 мин).
Работает через nftables vmap (O(1) dispatch) + tokio async + hyper/rustls in-process HTTP.

**Ключевое ограничение для нас: TCP-only, нет UDP, нет curl_cffi, нет Flowseal-блоба.**

### 8.2 Что blockcheckw делает лучше blockcheck.sh

| Фича | Как сделано | Применить в blockcheckS? |
|------|-------------|:---:|
| **150x throughput** | nftables vmap O(1) + tokio async + in-process HTTP | ✅ |
| **7-level block classification** | not_blocked, throttled, sni_blocked, ip_blocked, syn_blocked, host_dead, dns_failed | ✅ |
| **Real data transfer check** | 32KB minimum download (ловит "fake working" DPI) | ✅ |
| **16KB DPI cap detection** | DpiDataLimit verdict (10-25KB range) | ✅ |
| **Success sink** | Mutex<Vec<Vec<String>>> — сохраняет результаты при Ctrl+C | ✅ |
| **DNS spoof detection** | system DNS vs DoH comparison | ✅ |
| **Strategy ranking** | По coverage + структурной простоте | ✅ |
| **Self-update** | `--upgrade` download from GitHub Releases | P3 |
| **9 CPU архитектур** | x86_64, arm64, mips, ppc, riscv | P3 (Python кроссплатформен) |
| **OpenTelemetry tracing** | OTLP export | P3 |

### 8.3 Архитектура nftables vmap (ключевое для скорости)

```
# ОДИН вызов nft для всех worker'ов в батче:
add map inet zapret postnat_qmap { type mark : verdict; }
add element inet zapret postnat_qmap { 
    0x20000001 : jump wp_200,   # worker 1
    0x20000002 : jump wp_201,   # worker 2
    ...
}
```
O(1) hash lookup — время не растёт с числом worker'ов. blockcheck.sh использует линейный iptables.

**Для blockcheckS:** использовать nftables vmap (через subprocess `nft`) или pyroute2 netlink.

### 8.4 In-process HTTP vs curl fork

blockcheckw: hyper + rustls — HTTP in-process, без fork.
blockcheck.sh: curl — fork+exec на каждый тест (~600 форков за скан).

**Для blockcheckS:** curl_cffi тоже in-process (через ctypes/libcurl), без fork.

### 8.5 Стратегии: pre-dumped vs generated

blockcheckw: 13,943 стратегий предварительно сгенерированы (`include_str!` в бинарь).
blockcheck.sh: генерирует на лету в bash-скриптах.

**Для blockcheckS:** гибрид. Python-генераторы для быстрых вариаций (TTL, repeats) + текстовые файлы для custom-стратегий (как в blockcheck.sh).

---

## 9. UDP / curl_cffi / Flowseal-like тесты — план для blockcheckS

### 9.1 Почему blockcheckS ДОЛЖЕН поддерживать UDP

blockcheck.sh тестирует QUIC/HTTP3 через `curl_test_http3`. blockcheckw вообще не тестит UDP.
Но **Discord voice — это UDP** (STUN на порт 50004 к Google Cloud IP). 
Ни blockcheck.sh, ни blockcheckw не могут найти работающую voice-стратегию.

**blockcheckS будет ПЕРВЫМ DPI strategy tester'ом с полноценной UDP-поддержкой.**

### 9.2 curl_cffi как замена curl/rustls

| Библиотека | JA4 | TLS stack | Браузерный? |
|-----------|-----|-----------|:---:|
| curl (OpenSSL) | `t13d0202` | OpenSSL | ❌ |
| hyper + rustls | Другой | rustls | ❌ |
| **curl_cffi** | `t13d1516h2` | **BoringSSL** | ✅ Chrome 124 |

**Преимущество:** DPI не блокирует браузерные отпечатки (подтверждено на Fryazino.net).
blockcheck.sh с OpenSSL возвращает ложные FAIL для стратегий, которые работают в браузере.
curl_cffi решает эту проблему.

### 9.3 Flowseal-подход: бинарные блобы для десинхронизации

Flowseal ALT2 доказал эффективность **предварительно захваченных пакетов** как блобов:

| Блоб | Использование | Статус в blockcheckS |
|------|--------------|:---:|
| `ACTIVE_DISCORD_UDP.bin` (1200B) | Discord voice UDP fake | ✅ Уже есть |
| `ACTIVE_GAME_UDP.bin` | Game traffic UDP fake | ⏳ Скачать из Flowseal |
| `tls_clienthello_www_google_com.bin` (681B) | Google TLS fake | ✅ Уже есть |
| `stun.bin` (100B) | STUN binding fake | ✅ Уже есть |
| `tls_clienthello_max_ru.bin` (664B) | RU-domain TLS | ✅ Уже есть |

**blockcheckS должен тестировать Flowseal-блобы как отдельную категорию стратегий.**

### 9.4 UDP voice checker для blockcheckS

```python
# checkers/udp_voice.py
class UdpVoiceChecker:
    """Проверяет Discord voice UDP через STUN + опционально discord.py DTLS."""
    
    async def check_stun(self, ip: str, port: int, strategy: str) -> bool:
        """Быстрая проверка: STUN binding через nfqws2."""
    
    async def check_dtls(self, token: str, guild_id: int, channel_id: int, strategy: str) -> VoiceResult:
        """Полная проверка: discord.py VoiceClient + DTLS + latency sampling."""
```

---

## 10. Ключевые решения (обновлено)

1. **nfqws2 reuse вместо restart** — главный источник ускорения (10x)
2. **nftables vmap** — O(1) dispatch для параллельных worker'ов (как blockcheckw)
3. **curl_cffi вместо curl/rustls** — браузерный JA4, легитимный TLS fingerprint
4. **Python (не Rust)** — быстрое прототипирование, интеграция с dpi-tester, те же зависимости
5. **UDP voice — killer feature** — ни blockcheck.sh, ни blockcheckw не умеют
6. **Flowseal blobs** — встроенная поддержка бинарных блобов для десинхронизации
7. **7-level block classification** — портировать из blockcheckw
8. **32KB data transfer check** — ловить "fake working" DPI
9. **Success sink** — сохранять результаты при Ctrl+C
10. **Только Linux** — iptables/nftables, без FreeBSD/OpenBSD/Windows
