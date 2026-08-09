# ByeDPI Engine — план интеграции в blockcheckS

> **Версия:** 1.1.0  
> **Бинарник:** `ciadpi` (byedpi) v0.17.3 — `/home/zhoel/workspace/patches/byedpi-ideas/ciadpi`  
> **Upstream:** [hufrea/byedpi](https://github.com/hufrea/byedpi) (MIT, ~3.3k★)  
> **Android client:** [romanvht/ByeByeDPI](https://github.com/romanvht/ByeByeDPI) — встроенный **подборщик стратегий** (autotest)  
> **Статус:** Plan (не реализовано)  
> **Анализ:** 2026-08-05 (upstream README + ByeByeDPI `proxytest_strategies.list`)

---

## 1. Зачем нужен byedpi

nfqws2 требует root, netns, iptables и ~3s старта на каждую стратегию. Byedpi — SOCKS5-прокси на C (~96KB), стартует за ~50ms, **не требует root**. Даже без `--auto` mode даёт 3–5× ускорение per-strategy.

**Два режима тестирования:**

| Режим | Когда | blockcheckS |
|-------|--------|-------------|
| **Process-per-strategy** | Нужен детерминизм: одна стратегия = один результат в DB | **Phase 1** (основной) |
| **`--auto` chains** | Production proxy: триггеры `torst`/`ssl_err`/`redirect` переключают группы | §10 / production only |

ByeByeDPI autotest использует process-per-strategy (рестарт ciadpi на каждую строку каталога) — тот же подход, что в §2.

### Сравнение

| | nfqws2 | byedpi (ciadpi) |
|---|---|---|
| Механизм | NFQUEUE (kernel packet interception) | SOCKS5 proxy (userspace) |
| Root | Да (iptables/netns) | Нет |
| Default listen | — | `127.0.0.1:1080` (`-p`) |
| Старт процесса | ~3s (netns + settle) | ~50ms |
| Per-strategy аргументы | `--lua-desync=...` | `-f`, `-s`, `-d`, `-o`, `-A`, … |
| Custom blobs | `--blob=NAME:@path` | `-l` / `--fake-data @path` |
| Multi-strategy | `--new` profiles или restart | `--auto=trigger` groups (1 процесс) |
| IP кеширование | Нет | `--cache-ttl` + `--cache-dump` |

---

## 2. Архитектурное решение

**Подход: один процесс byedpi на стратегию.** Не `--auto` groups.

Причина — тестирование требует **независимой** проверки каждой стратегии. `--auto=torst` даёт недерминизм (стратегия выбирается по триггеру). Process-per-strategy даёт детерминизм, а 50ms старта — пренебрежимо мало на фоне 3-8s curl-пробы.

```
blockcheckS (Python)
  └─ для каждой стратегии:
       ├─ ByedpiManager.start()  → ciadpi --port {N} --fake -1 --ttl 8 ...
       ├─ curl через socks5://127.0.0.1:{N}
       ├─ запись результата в SQLite
       └─ ByedpiManager.stop()
```

Параллельно: N стратегий = N процессов ciadpi на разных портах, curl через asyncio + `asyncio.to_thread()`.

---

## 3. Маппинг стратегий: nfqws2 ↔ byedpi

### Таблица соответствия

| nfqws2 стратегия | byedpi CLI | Статус |
|---|---|---|
| `fake:blob=stun:repeats=6:tcp_ts=-1000` | `-f -1 -l @stun.bin -t 8` | ⚠️ PARTIAL — **нет TCP repeats=6** (один fake-send; UDP: `-a 6`) |
| `fake:blob=max_ru:repeats=6:tcp_ts=-1000` | `-f -1 -l @max_ru.bin -t 8` | ⚠️ PARTIAL |
| `fake:blob=google:repeats=6:tcp_ts=-1000` | `-f -1 -l @google.bin -t 8` | ⚠️ PARTIAL |
| `fake:blob=X:repeats=N:tcp_md5` | `--fake -1 --fake-data @X.bin --md5sig` | ✅ |
| `fake:blob=X:repeats=N:badsum` | — | ❌ byedpi без badsum |
| `hostfakesplit:nofake2` | `--split 1+sm` | ✅ |
| `hostfakesplit:disorder_after:nofake2` | `--split 1+sm --disorder 1+sm` | ✅ |
| `hostfakesplit:nofake2:tcp_md5` | `--split 1+sm --md5sig` | ✅ |
| `hostfakesplit:nofake2:tcp_ts=-1000` | `--split 1+sm --ttl 8` | ✅ |
| `hostfakesplit:nofake2:tcp_ack=-66000:tcp_ts_up` | — | ❌ byedpi без tcp_ack/tcp_ts_up |
| `fakedsplit:pos=1:pattern=stun` | `--fake 1 --disorder 1` | ✅ |
| `fakedsplit:pos=midsld:pattern=google` | `--fake 0+sm --disorder 0+sm` | ✅ |
| `fakeddisorder:pos=1:pattern=google` | `--disorder 1 --fake 1` | ✅ |
| `multisplit:pos=1,midsld` | `--split 1 --split 0+sm` | ✅ |
| `multisplit:pos=1:seqovl=68` | — | ❌ byedpi без seqovl |
| `tlsrec:pos=3+s` | `-r 3+s` | ✅ |
| `oob:urp=b` | `-o 0` (OOB URG byte) | ✅ |
| `oob:urp=s` | `-o 0+sm` | ✅ |
| — (нет в nfqws2) | `-q` / `--disoob` (disorder + OOB) | byedpi-only |
| — | `-n {sni}` / `--fake-sni` | byedpi-only (динамический fake SNI) |
| — | `-A torst,ssl_err,redirect` | ≈ `circular` + event triggers |
| — | `-M h,d,r` / `--mod-http` | byedpi-only (HTTP header case) |
| — | `-Y` / `--drop-sack` | byedpi-only (Linux) |
| — | `-a N` / `--udp-fake` | partial UDP (≠ nfqws2 voice UDP) |
| `syndata` (bare) | `-f -1` + `-Q rand` | ✅ (`--fake-tls-mod`) |

### Позиционная магия byedpi

Формат `pos_t`: `offset[:repeats:skip][+flag1[flag2]]`

| Суффикс | Значение | nfqws2 эквивалент |
|---------|----------|-------------------|
| `+s` | Внутри SNI | `pos=host+N` |
| `+h` | Внутри Host | `pos=http+N` |
| `+n` | Нулевое смещение | `pos=0` |
| `+e` | Конец данных | `pos=-1` |
| `+m` | Середина данных | `pos=midsld` |

**Пример:** nfqws2 `hostfakesplit:nofake2` → byedpi `--split 1+sm` (split в середине SNI, 1 сегмент).

### Fooling-маппинг

| nfqws2 fooling | byedpi |
|----------------|--------|
| `tcp_ts=-1000` | `--ttl 8` или `--md5sig` (другой механизм, та же цель — fake-пакет умер до сервера) |
| `tcp_md5` | `--md5sig` ✅ |
| `badsum` | ❌ |
| `badseq` / `tcp_seq=...` | ❌ |
| `tcp_ack=...` / `tcp_ts_up` | ❌ |
| `tcp_flags_set/unset` | ❌ |
| `ip_ttl=N` | `--ttl N` ✅ |
| `ip_autottl=...` | ❌ |
| `drop-sack` | `-Y` / `--drop-sack` ✅ (Linux) |
| `hostspell=hoSt` | `-M h` / `--mod-http h` ✅ |
| `tls_mod=rnd` | `-Q rand` / `--fake-tls-mod rand` ✅ |

**Примечание:** nfqws2 `tcp_ts=-1000` и byedpi `--ttl 8` / `--md5sig` — разные механизмы (timestamp vs TTL/md5 на fake). На Fryazino оба часто работают как «fake не доходит до сервера».

### Blob-маппинг

| nfqws2 blob alias | byedpi (`-l` / `--fake-data`) |
|-------------------|-------------------------------|
| `stun` | `@blobs/stun.bin` (repo `blobs/` или `BLOB_DIR`) |
| `max_ru` | `@blobs/tls_clienthello_max_ru.bin` |
| `google` | `@blobs/tls_clienthello_www_google_com.bin` |
| `4pda` | `@blobs/tls_clienthello_4pda_to.bin` |
| `discord_udp` | ❌ (UDP only) |
| `quic_*` | ❌ (QUIC only) |

Используется `resolve_blob_path()` из `engine/blob_aliases.py` (приоритет: repo `blobs/`).

**Строковый fake без файла:** `-l ':HEX'` или `-e` / `--oob-data` для OOB байта (см. upstream README).

### Cross-translator: нужен ли?

**Вердикт: partial translator + отдельный native каталог.** Единый синтаксис невозможен.

| Подход | Решение |
|--------|---------|
| nfqws2 lua-desync → ciadpi argv | ✅ `parse_strategy_to_byedpi()` для ~8 семейств; `SKIP` на unmappable |
| Native ciadpi one-liners (ByeByeDPI 60) | ✅ Matrix source `byedpi`, без reverse-маппинга |
| byedpi → nfqws2 reverse | ⚠️ Low priority (`-q`, `-n`, `-A`, `-M`, `-Y` слабо мапятся) |
| Один процесс `--auto` для matrix | ❌ Недетерминизм; только process-per-strategy |

**Критическая семантика:** nfqws2 `repeats=N` = N× rawsend одного пакета. byedpi `offset:repeats:skip` = несколько **позиций split**, не repeat-send. **Не путать.** Fryazino winners с `repeats=6` — эмпирическая валидация обязательна.

### Оценка покрытия nfqws2 → byedpi (blockcheckS, 2026-08-05)

Метод: классификация по §3–7 (FULL / PARTIAL / NO) на реальных генераторах и `configs/`.

| Источник | STRICT FULL | FULL + PARTIAL (usable) |
|----------|-------------|-------------------------|
| **configs/** (23 TCP из 28) | **13%** (3/23) | **30%** (7/23) |
| **Standard TCP families** (17 семейств) | 18% (3/17) | 59% (10/17) |
| **Standard enumerated** (8 341 стратегий) | **21%** | **35%** |
| **Flowseal TCP** (6 338) | **2%** | **10%** |
| **Fooling strings** (16 уникальных) | 25% (4/16) | — |
| **QUIC + UDP + HTTP** | **0%** | **0%** |

**Итого для пары nfqws2+byedpi:** ~**30–35%** стратегий имеют путь перевода; strict 1:1 — ~**20–22%**.

**Лучший слайс (Fryazino-confirmed):** single-line `fake:blob=X:tcp_ts=-1000`, `fakedsplit`, `fakeddisorder`, `hostfakesplit` без seqovl — `simple_fake_alt2`, `alt9`, `FakedTcpGenerator` (100% FULL).

**Структурные блокеры (не случайность):**

1. **seqovl** — ~40% TCP семейств, ~65% enumerated output (`multisplit` largest family)
2. **Unmapped foolings** — `badsum`, `badsid`, `tcp_ack:tcp_ts_up` в fast-scan axes
3. **Non-TCP** — QUIC/UDP voice/HTTP целиком nfqws2-only
4. **Multiline lua-desync** — dual/triple fake → PARTIAL даже когда строки мапятся
5. **TCP `repeats=N`** — нет аналога в ciadpi

**Dual-engine routing:**

```
TCP/TLS prescreen → --engine byedpi (fast, no root)
  → top-N confirm → nfqws2 netns (ground truth)
UDP / QUIC / voice → nfqws2 only
Native byedpi catalog → byedpi only (OOB, -A, -n, -M)
```

---

## 4. Файлы и реализация

### 4.1. Новый модуль: `src/blockchecks/engine/byedpi.py` (~200 строк)

```python
"""Byedpi engine — SOCKS5 proxy-based DPI strategy testing."""

from __future__ import annotations

import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass

from blockchecks.engine.blob_aliases import resolve_blob_path
from blockchecks.engine.config import BLOB_DIR


@dataclass
class ByedpiManager:
    """One ciadpi process per strategy, SOCKS5 proxy on localhost."""

    port: int
    proxy_url: str
    bin_path: str
    strategy: str  # original nfqws2 strategy string (for DB logging)
    byedpi_flags: list[str]  # translated CLI args
    _proc: subprocess.Popen | None = None

    @classmethod
    def from_strategy(cls, strategy: str, bin_path: str, port: int = 0) -> ByedpiManager:
        """Parse strategy, translate to byedpi flags, find free port."""
        if port == 0:
            port = _find_free_port()
        byedpi_flags = parse_strategy_to_byedpi(strategy)
        return cls(
            port=port,
            proxy_url=f"socks5://127.0.0.1:{port}",
            bin_path=bin_path,
            strategy=strategy,
            byedpi_flags=byedpi_flags,
        )

    def start(self) -> str:
        """Launch ciadpi, wait for port, return proxy_url."""
        args = [self.bin_path, "-p", str(self.port), "-i", "127.0.0.1", "-K", "tls"]
        args.extend(self.byedpi_flags)
        self._proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _wait_port(self.port, timeout=3.0)
        return self.proxy_url

    def stop(self) -> None:
        """Send SIGTERM, wait, SIGKILL if needed."""
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=1)


# ── Strategy parser ────────────────────────────────────────────────

_UNMAPPED_FOOLINGS = frozenset(
    {
        "badsum",
        "badseq",
        "tcp_ack",
        "tcp_seq",
        "tcp_flags_unset",
        "tcp_flags_set",
        "ip_autottl",
        "ip6_",
        "seqovl",
        "seqovl_pattern",
        "ipfrag",
        "tcpseg",
        "padencap",
    }
)

_SUPPORTED_FAMILIES = frozenset(
    {
        "fake",
        "hostfakesplit",
        "fakedsplit",
        "fakeddisorder",
        "multisplit",
        "multidisorder",
        "tlsrec",
        "oob",
        "syndata",
    }
)

_BYEDPI_POS_MAP = {
    "midsld": "0+sm",
    "mid": "0+m",
    "start": "0",
    "end": "-1+e",
    "host": "0+s",
}
_BYEDPI_POS_MAP_PAT = re.compile(r"pos=([^:\]]+)(?::(\d+))?(?::(\d+))?")
_BLOB_PAT = re.compile(r"blob=([a-zA-Z0-9_]+)")
_REPEATS_PAT = re.compile(r"repeats=(\d+)")


def _pos_to_byedpi(pos_value: str) -> str:
    """Convert nfqws2 position to byedpi pos_t format."""
    if pos_value.isdigit():
        return pos_value
    return _BYEDPI_POS_MAP.get(pos_value, pos_value)


def parse_strategy_to_byedpi(strategy: str) -> list[str]:
    """Parse one nfqws2-strategy line → byedpi CLI args list.

    Returns empty list if strategy is unsupported (UDP/QUIC/unmapped foolings).
    """
    args: list[str] = []
    line = strategy.strip()

    # ── Unsupported foolings check ──
    lower = line.lower()
    for bad in _UNMAPPED_FOOLINGS:
        if bad in lower:
            return []  # SKIP — byedpi doesn't support this

    # ── Family routing ──
    if "hostfakesplit" in line:
        # --split 1+sm [--disorder 1+sm] [--ttl 8 / --md5sig]
        args.extend(["--split", "1+sm"])
        if "disorder_after" in line or "disorder" in line:
            args.extend(["--disorder", "1+sm"])
        if "tcp_md5" in line:
            args.append("--md5sig")
        elif "tcp_ts" in line:
            args.extend(["--ttl", "8"])

    elif "fakedsplit" in line:
        m = _BYEDPI_POS_MAP_PAT.search(line)
        pos = _pos_to_byedpi(m.group(1)) if m else "1"
        args.extend(["--fake", pos, "--disorder", pos])

    elif "fakeddisorder" in line:
        m = _BYEDPI_POS_MAP_PAT.search(line)
        pos = _pos_to_byedpi(m.group(1)) if m else "1"
        args.extend(["--disorder", pos, "--fake", pos])

    elif "multisplit" in line or "multidisorder" in line:
        # Extract multiple positions
        pos_match = re.search(r"pos=([^:\]]+)", line)
        if pos_match:
            positions = pos_match.group(1).split(",")
            for p in positions:
                p = p.strip()
                args.extend(["--split", _pos_to_byedpi(p)])
        if "multidisorder" in line or "disorder" in line:
            for p in positions[:1]:  # disorder only on first pos
                args.extend(["--disorder", _pos_to_byedpi(p.strip())])

    elif "tlsrec" in line:
        m = _BYEDPI_POS_MAP_PAT.search(line)
        pos = _pos_to_byedpi(m.group(1)) if m else "1+s"
        args.extend(["--tlsrec", pos])

    elif "oob" in line:
        pos_match = re.search(r"urp=([bsmc])", line)
        if pos_match:
            urp_map = {"b": "0", "s": "0+sm", "m": "0+m", "c": "-1+e"}
            pos = urp_map.get(pos_match.group(1), "0")
            args.extend(["--oob", pos])

    elif "syndata" in line:
        args.extend(["--fake", "-1"])
        if "tls_mod" in line:
            args.append("--fake-tls-mod")
            if "rnd" in line:
                args.append("rand")
            else:
                args.append("orig")

    elif "fake" in line:
        args.extend(["--fake", "-1"])
        # Blob
        blob_m = _BLOB_PAT.search(line)
        if blob_m:
            blob_name = blob_m.group(1)
            blob_path = resolve_blob_path(blob_name)
            if blob_path and os.path.isfile(blob_path):
                args.extend(["--fake-data", f"@{blob_path}"])
        # Fooling
        if "tcp_md5" in line:
            args.append("--md5sig")
        elif "tcp_ts" in line:
            args.extend(["--ttl", "8"])

    return args


# ── Utility ────────────────────────────────────────────────────────


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(port: int, timeout: float = 3.0) -> None:
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except (OSError, ConnectionRefusedError):
            time.sleep(0.05)
    raise TimeoutError(f"ciadpi did not bind port {port} within {timeout}s")
```

### 4.2. DB: `byedpi_results` таблица

**Файл:** `src/blockchecks/engine/store/schema.py` (+12 строк в `INIT_SCRIPT`)

```sql
CREATE TABLE IF NOT EXISTS byedpi_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    strategy_id INTEGER REFERENCES strategies(id),
    domain TEXT NOT NULL,
    status TEXT NOT NULL,
    http_code INTEGER DEFAULT 0,
    latency_ms REAL DEFAULT 0,
    proxy_port INTEGER DEFAULT 0,
    byedpi_flags TEXT DEFAULT '',
    nfqws2_original TEXT DEFAULT '',
    error TEXT DEFAULT '',
    timestamp TEXT NOT NULL DEFAULT ''
);
```

### 4.3. DB: `log_byedpi()` метод

**Файл:** `src/blockchecks/engine/store/sqlite_store.py` (+20 строк)

```python
async def log_byedpi(
    self,
    strategy: str,
    domain: str,
    status: str,
    latency_ms: float = 0,
    byedpi_flags: str = "",
    nfqws2_original: str = "",
    http_code: int = 0,
    proxy_port: int = 0,
    error: str = "",
) -> None:
    """Persist one byedpi probe result."""
```

**Файл:** `src/blockchecks/engine/store/__init__.py` (+3 строки в Protocol)

```python
async def log_byedpi(
    self, strategy: str, domain: str, status: str, latency_ms: float = 0, **kwargs
) -> None: ...
```

### 4.4. `curl_probe.py` — `proxy` field

**Файл:** `src/blockchecks/checkers/curl_probe.py` (+10 строк)

```python
@dataclass
class CurlProbeRequest:
    # ... existing fields ...
    proxy: str | None = None  # socks5://127.0.0.1:PORT


# В run_curl_probe():
if req.proxy:
    session = curl_cffi.Session(
        impersonate="chrome124",
        http_version=2,
        proxies={"https": req.proxy, "http": req.proxy},
    )
else:
    session = curl_cffi.Session(impersonate="chrome124", http_version=2)
```

### 4.5. `async_runner.py` — byedpi path

**Файл:** `src/blockchecks/engine/async_runner.py` (+30 строк)

```python
# В AsyncTestRunner.__init__:
self.engine = kwargs.get("engine", "nfqws2")
self.byedpi_bin = kwargs.get("byedpi_bin", "")

# В test_tcp (новый параметр test_func или engine-branch):
if self.engine == "byedpi" and self.byedpi_bin:
    mgr = ByedpiManager.from_strategy(item.strategy, self.byedpi_bin)
    proxy = mgr.start()
    req = CurlProbeRequest(domain=domain, proxy=proxy, timeout=timeout)
    result = run_curl_probe(req)
    mgr.stop()
    return TcpTestResult(
        success=result.success,
        latency_ms=result.latency_ms,
        http_code=result.http_status,
        read_rate_bps=result.read_rate_bps,
        error=result.error,
        throttled=result.throttled,
    )
else:
    # existing nfqws2 + netns path
```

### 4.6. CLI флаги

**Файл:** `src/blockchecks/cli/parser.py` (+15 строк)

```
--engine {nfqws2,byedpi}    default: nfqws2
--byedpi-bin PATH            default: auto-detect (which ciadpi or ~/.local/bin/ciadpi)
```

### 4.7. system_deps.py — byedpi check

**Файл:** `src/blockchecks/engine/system_deps.py` (+15 строк)

```python
def resolve_byedpi_bin() -> str | None:
    """Find ciadpi binary. Order: env → patches → PATH → ~/.local/bin."""
    env = os.environ.get("BLOCKCHECKS_BYEDPI", "")
    if env and os.path.isfile(env):
        return env
    vendor = os.path.join(PROJECT_DIR, "../patches/byedpi-ideas/ciadpi")
    for path in (
        vendor,
        "ciadpi",
        "/usr/local/bin/ciadpi",
        os.path.expanduser("~/.local/bin/ciadpi"),
    ):
        if os.path.isfile(path) or shutil.which(path):
            return path
    return None
```

---

## 5. Roadmap

### Phase 1 — Core engine (~200 строк, 2-3 часа)

- [ ] `engine/byedpi.py` — `ByedpiManager` + `parse_strategy_to_byedpi()`
- [ ] `tests/unit/test_byedpi.py` — тесты маппинга стратегий (20+ test cases)
- [ ] Ручной smoke: `python -c 'from blockchecks.engine.byedpi import *; mgr = ByedpiManager.from_strategy("fake:blob=stun:repeats=6:tcp_ts=-1000", bin_path); proxy = mgr.start(); print(proxy); mgr.stop()'`

### Phase 2 — DB + store (~35 строк, 1 час)

- [ ] `store/schema.py` — `byedpi_results` таблица
- [ ] `store/sqlite_store.py` — `log_byedpi()` метод
- [ ] `store/__init__.py` — Protocol export
- [ ] `tests/unit/test_sqlite_store.py` — тест `log_byedpi`

### Phase 3 — Curl integration (~10 строк, 30 мин)

- [ ] `curl_probe.py` — `proxy` field + session c прокси
- [ ] Ручной тест: curl через byedpi SOCKS5

### Phase 4 — Async runner (~30 строк, 1 час)

- [ ] `async_runner.py` — `engine` parameter + byedpi branch
- [ ] `tests/unit/test_async_runner.py` — мок byedpi path

### Phase 5 — CLI + system deps (~30 строк, 30 мин)

- [ ] `cli/parser.py` — `--engine` + `--byedpi-bin`
- [ ] `system_deps.py` — `resolve_byedpi_bin()`

### Phase 6 — Benchmark (~1 час) — ✅ первый замер (2026-08-09)

- [x] `bs scan -d discord.com --user-matrix <5-стратегий> --classic` (baseline, nfqws2)
- [x] byedpi (ciadpi + curl_cffi через SOCKS) — тот же набор
- [x] Записать `test/sec` в этот документ

**Результат (discord.com, 5 стратегий: 3×`fake:blob=X` + fakedsplit + hostfakesplit):**

| Движок | total | test/sec | PASS | Примечание |
|--------|-------|----------|------|------------|
| nfqws2 classic | 15.19s | 0.33 | 3/5 | Fryazino нестабилен (бывает >70s/виснет) |
| byedpi (ciadpi SOCKS) | 10.72s | 0.47 | 3/5 | стабильно |
| **Speedup** | | **1.19×** | | |

- Вердикты согласованы (3/5 PASS обоими); FAIL-стратегии (`fakedsplit`, `hostfakesplit`) ждут полный timeout 5s — раздувают total у обоих.
- На чистых PASS-стратегиях byedpi: ~0.73 t/s; nfqws2 на Fryazino виснет — преимущество byedpi выше.
- **Вывод:** byedpi стабильнее и быстрее на TCP/TLS prescreen; nfqws2 нужен для UDP/QUIC/voice и ground-truth.

#### Диагностика "нестабильности" nfqws2 (2026-08-10, tshark/tcpdump)

**Вердикт: не баг nfqws2 и не общий сбой сети, а IP-специфичный троттлинг Fryazino.**

- Симптом: те же 3 fake-стратегии дают то 3/3 PASS (1s), то 0/3 FAIL (26s+) при идентичных флагах.
- Причина: `prepare_dns_for_run()` берёт `dns_cache.primary_ip()` = **первый IP из DoH-ответа** (dns_secure.py:339). DoH (Cloudflare) **ротирует A-записи** discord.com: порядок меняется между запросами (проверено 5×: 136/138/128/135/137 .232).
- **162.159.136.232 сейчас троттлится Fryazino**: на нём FAIL директ, nfqws2 fake, и byedpi (`curl (97) cannot complete SOCKS5`). Остальные 4 IP — PASS 75-85ms. Все 5 IP пингуются (15ms) — это DPI-троттлинг TLS-handshake, не потеря маршрута.
- tshark подтверждает: на троттленом IP SYN→SYN+ACK проходит, **ClientHello уходит, ответа нет** (silent drop, SNI-based — см. Fryazino в AGENTS.md §6). Поedpi на рабочем IP шлёт CH в 3 сегментах (1388+396+1) и получает ответ.
- `settle=0ms` в логе — норма (wait_nfqws2_ready видит процесс), не признак бага.
- Лог "0 байт" при зависании — **артефакт буферизации stdout**: `bs` без `-u` буферизует при редиректе в файл; при kill буфер теряется. Для диагностики нужен `PYTHONUNBUFFERED=1`.

**Рекомендации:**
1. Бенчмарк: зафиксировать `--resolve`/pre-resolve на рабочий IP или прогонять несколько раз (поedpi и nfqws2 дают один вердикт на рабочем IP).
2. Код: в `_run_tcp_check` при FAIL можно перебирать следующие `dns_cache.resolve()` IP (retry-on-next-IP) вместо мгновенного FAIL.
3. При сравнении движков указывать выбранный IP — иначе результат зависит от ротации DoH, а не от движка.

#### Реализовано (2026-08-10) — hosts-analog pin + retry-on-next-IP

- **`--fixed-ip <path>`** (env `BLOCKCHECKS_FIXED_IP`): hosts-analog файл
  `domain IP` (комментарии `#`). Pinned IP перекрывает DoH-порядок.
- **Авто-пин**: при старте (если не `--no-auto-pin`) проверяет кандидатов
  стратегией `fake:blob=stun` (PIN_STRATEGY), пинит первый PASS, атомарно
  перезаписывает файл. Проверено: pin `136.232` (троттлится) → авто-замена
  на `138.232` → 3/3 PASS.
- **Retry-on-next-IP**: `_run_tcp_check`/`_multi`/`run_tcp_check_bridge` при
  FAIL повторяют curl-worker со следующими IP (короткий `RETRY_IP_TIMEOUT`),
  nfqws2 поднимается один раз. Использованный IP в `used_ip` → лог/DB.
- Модуль `blockchecks/checkers/ip_pin.py`; тесты `tests/unit/test_ip_pin.py`.

### Phase 7 — ByeByeDPI catalog import (~2 часа)

- [ ] `presets/byedpi/proxytest_strategies.list` — vendor 60 строк из [ByeByeDPI](https://github.com/romanvht/ByeByeDPI/blob/master/app/src/main/assets/proxytest_strategies.list)
- [ ] `CiadpiLineParser` — short/long flags, `{sni}` placeholder
- [ ] Matrix source `byedpi` → `StrategyItem(strategy=ciadpi_line, protocol=tcp)`
- [ ] `presets/domains/byedpi_*.txt` из `proxytest_*.sites`

### Phase 8 — Probe enhancements (~1–2 часа)

- [ ] Optional `PARTIAL_BLOCK` — truncated Content-Length (SiteCheckUtils parity)
- [ ] Success-rate scoring mode для `--engine byedpi`
- [ ] `BLOCKCHECKS_BYEDPI_SNI` env

---

## 6. Ожидаемая производительность

| Метрика | nfqws2 | byedpi | Ускорение |
|---------|--------|--------|-----------|
| Старт процесса | ~3s (netns + settle) | ~50ms | 60× |
| Per-strategy total | 3-8s | 0.5-3s | 3-5× |
| 100 стратегий | ~80s | ~20s | 4× |
| Root required | Да | Нет | — |
| Netns overhead | Да (~50ms) | Нет | — |

---

## 7. Ограничения byedpi

| Что не работает | Почему |
|-----------------|--------|
| `badsum`, `badseq` foolings | byedpi не модифицирует TCP checksum/sequence |
| `tcp_ack=-66000:tcp_ts_up` | byedpi не модифицирует TCP timestamp/ACK |
| `seqovl`, `padencap`, `tcpseg` | byedpi не делает sequence overlap / padding / segmentation |
| `ipfrag`, `ip6_*` | byedpi работает выше IP-уровня |
| `ip_autottl` | byedpi использует фиксированный TTL (`-t` / `--ttl`) |
| UDP `fake:blob=discord_udp:repeats=6` | `-a N` есть, но не эквивалентно nfqws2 UDP voice |
| QUIC `fake:blob=quic_initial:repeats=11` | byedpi не трогает QUIC Initial (`-K tls,http,udp`) |
| `--lua-desync=` multiline | Одна строка → ciadpi one-liner; multiline nfqws2 не 1:1 |
| `circular:fails=` | Нет аналога; есть `-A` auto-chains |
| **disorder на Windows** | Ретрансмиссия с max ACK — нужен `-s 1+s -d 3+s` (upstream README) |

**Для неподдерживаемых foolings парсер возвращает пустой список → статус `SKIP`.**

---

## 8. ByeByeDPI Android — подборщик стратегий (autotest)

Репозиторий: [romanvht/ByeByeDPI](https://github.com/romanvht/ByeByeDPI). Обёртка вокруг **ciadpi** (submodule byedpi). **Не** combinatorial generator — статический каталог + sequential restart.

### 8.1 Два UI-потока

| Поток | Где | Что делает |
|-------|-----|------------|
| **Pinned strategy picker** | `MainActivity.showStrategyPicker()` | Закреплённые команды из history → apply → restart VPN/Proxy |
| **Autotest («Подбор стратегий»)** | `TestActivity` | Перебор каталога → score по доменам → JSON |

Autotest требует **CMD mode** (`byedpi_enable_cmd_settings=true`).

### 8.2 Autotest flow

```
proxytest_strategies.list (60) OR user commands
        ↓
union(active domain lists)
        ↓
FOR EACH strategy (sequential):
    updateCmdArgs — {sni} → google.com (configurable)
    stop ciadpi → start Proxy → wait ≤3s
    delay(delaySec × 500ms)
    checkSitesAsync(sites, parallel≤20) via SOCKS5 127.0.0.1:1080
    success% = successCount / (sites × requestsPerSite)
        ↓
sort: completed → success% → successCount → proxy_test_results.json
```

Стратегии **sequential**; домены **parallel** (default 20).

### 8.3 Каталог (`proxytest_strategies.list`)

60 curated one-liners (asset lines 1–60). Загрузка: `TestActivity.loadCmds()`; `{sni}` → pref `byedpi_proxytest_sni` (default `google.com`). Override: pref `byedpi_proxytest_usercommands` (multiline).

**Универсальный суффикс:** все 60 строк заканчиваются на `-a1` (1 UDP fake).

| Паттерн | Strategies |
|---------|------------|
| `-a1` UDP fake | 60/60 |
| `-d` disorder | 39 |
| `-s` split | 37 |
| `-o` OOB | 33 |
| `-f` fake | 33 |
| `-r` TLS record split | 33 |
| `-q` / `-Qr` disoob / fake-tls-mod rand | 28 |
| `-A` auto-chains | 23 |
| `-n {sni}` fake-sni | 17 |
| `-t` fake TTL | 15 |
| `-S` md5sig | 7 |
| `-M` mod-http | 5 |
| `-m` tlsminor | 4 |

**Позиционные модификаторы** (`+s`, `+sm`, `+se`, `+sh`, `+h`, `+nme`, `+hm`, `+nr`, `+sn`): offset[:repeats:skip][+flags]. Примеры: `s3:5+sm`, `r-5+se`, `d2:5:2+h`.

**Профили:** fake-SNI chains (~13), OOB-heavy (~12), `-A` auto (~11), disorder/split ladders (~7), minimal 1–5 flags (строки 46–60).

Примеры:

```text
-o1 -a1 -r-5+se                    ← default app cmd (PreferencesUtils)
-o1 -a1 -r-5+se
--fake -1 --ttl 8 --split 1+s --disorder 3+s -a1   ← line 22 GNU long form
-n {sni} -Qr -f-1 -r1+s -a1
```

**ciadpi flags в каталоге, но не в nfqws2:** `-q`, `-Q`/`-Qr`, `-n`, `-A`, `-M`, `-m`, `-O`, `-e`, pos_t `+h`/`:repeats:skip`.

**В ciadpi есть, но не в 60-strategy каталоге:** `-Y` drop-sack, `-F` TFO, `-g` def-ttl, `-K` proto, `-H` hosts, `-R` round, `-L` auto-mode, `-T` timeout-auto, `-u/-y` cache, `-l` fake-data file, `-N` no-domain.

### 8.4 Domain presets (assets)

`DomainListUtils` → `filesDir/domain_lists.json`; built-in sync из assets unless user-edited.

| File | ID | Domains |
|------|----|---------|
| `proxytest_youtube.sites` | youtube | 13 |
| `proxytest_googlevideo.sites` | googlevideo | 19 |
| `proxytest_discord.sites` | discord | 21 |
| `proxytest_telegram.sites` | telegram | 52 |
| `proxytest_social.sites` | social | 16 |
| `proxytest_general.sites` | general | 6 |
| `proxytest_cloudflare.sites` | cloudflare | 4 |
| `proxytest_türkiye.sites` | türkiye | 8 |

**Default active lists:** `lang != tr` → youtube + googlevideo (**32** hosts); `lang == tr` → türkiye + discord (**29**).

### 8.5 Pass/fail — отличие от blockcheckS

`SiteCheckUtils`: SOCKS5 + `HttpURLConnection`, read до `Content-Length` (cap 1 MiB), `Connection: close`.

- **PASS:** HTTP response received AND (`declaredLength ≤ 0` OR `actualLength ≥ declaredLength`)
- **FAIL (block):** truncated body → "Block detected"; exception → 0 для attempt
- **Нет проверки HTTP status** — non-2xx с полным body = success

blockcheckS: `curl_cffi` + HTTP code — truncation **не** детектируется → идея `PARTIAL_BLOCK` probe (§9).

### 8.6 Scoring & timing defaults

| Setting | Pref key | Default | Effect |
|---------|----------|---------|--------|
| Inter-strategy delay | `byedpi_proxytest_delay` | 1 (0–10) | `delay × 500ms` around each strategy |
| Requests/domain | `byedpi_proxytest_requests` | 1 (1–20) | repeats per domain |
| Timeout | `byedpi_proxytest_timeout` | 5s (1–15) | connect + read |
| Parallel sites | `byedpi_proxytest_limit` | 20 (1–50) | `Semaphore` in SiteCheckUtils |
| Proxy wait | hardcoded | 3s max | poll `appStatus` every 100ms |
| Post-running settle | hardcoded | +500ms | after Running |

Score: `successCount / (sites × requests)`; sort completed → success% → count. Results: `filesDir/proxy_test_results.json`. Crash recovery: pref `is_test_running`.

### 8.7 Ключевые файлы

- [TestActivity.kt](https://github.com/romanvht/ByeByeDPI/blob/master/app/src/main/java/io/github/romanvht/byedpi/activities/TestActivity.kt)
- [SiteCheckUtils.kt](https://github.com/romanvht/ByeByeDPI/blob/master/app/src/main/java/io/github/romanvht/byedpi/utility/SiteCheckUtils.kt)
- [DomainListUtils.kt](https://github.com/romanvht/ByeByeDPI/blob/master/app/src/main/java/io/github/romanvht/byedpi/utility/DomainListUtils.kt)
- [PreferencesUtils.kt](https://github.com/romanvht/ByeByeDPI/blob/master/app/src/main/java/io/github/romanvht/byedpi/utility/PreferencesUtils.kt) — default cmd `-o1 -a1 -r-5+se`
- [proxytest_strategies.list](https://github.com/romanvht/ByeByeDPI/blob/master/app/src/main/assets/proxytest_strategies.list)
- [StrategyResultAdapter.kt](https://github.com/romanvht/ByeByeDPI/blob/master/app/src/main/java/io/github/romanvht/byedpi/adapters/StrategyResultAdapter.kt) — apply result → pinned strategy

---

## 9. Идеи для blockcheckS

### Каталог

1. Vendor `presets/byedpi/proxytest_strategies.list` (60 seeds).
2. Matrix source `byedpi` — curated list, не combinatorics.
3. Domain bundles из `proxytest_*.sites`.

### Probe / scoring

4. Status `PARTIAL_BLOCK` (truncated Content-Length).
5. Success-rate ranking primary для `--engine byedpi`.
6. Sequential strategies × parallel domains (как ByeByeDPI).

### byedpi-only generator axes

7. OOB / disoob (`-o`, `-q`).
8. Auto-chain (`-A torst,ssl_err`).
9. fake-sni (`-n`, `{sni}`).
10. HTTP mod (`-M h,d,r`).
11. drop-sack (`-Y`, Linux).

### CLI

12. `BLOCKCHECKS_PROXY=` empty — не использовать dead SOCKS (RKN-blocked VLESS).
13. `CiadpiParser` — short (`-f-1`) + long (`--fake -1`) flags.
14. Export pinned shortlist top-N после scan.
15. `SCAN_PROFILE=ru|tr` для default domain lists.

---

## 10. Расширение на будущее

- **`--auto` chains** — production SOCKS, не matrix A/B (нужна атрибуция группы).
- **`--auto-mode=2`**, **`--cache-ttl`** — production only.
- **byedpi-only families** в `matrix_generator` source `byedpi`.
- **`{list:Name}` macro** — runtime expand hosts into `-H` (ByeByeDPI CMD).
