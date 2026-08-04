# ByeDPI Engine — план интеграции в blockcheckS

> **Версия:** 1.1.0-alpha (target 1.1.0 release)  
> **Бинарник:** `ciadpi` (byedpi), `/home/zhoel/workspace/patches/byedpi-ideas/ciadpi`  
> **GitHub:** https://github.com/hufrea/byedpi (3.3k stars, MIT)  
> **Статус:** Plan (не реализовано)

---

## 1. Зачем нужен byedpi

nfqws2 требует root, netns, iptables и ~3s старта на каждую стратегию. Byedpi — SOCKS5-прокси на C (~96KB), стартует за ~50ms, не требует root. Даже без `--auto` mode даёт 3-5× ускорение per-strategy.

### Сравнение

| | nfqws2 | byedpi (ciadpi) |
|---|---|---|
| Механизм | NFQUEUE (kernel packet interception) | SOCKS5 proxy (userspace) |
| Root | Да (iptables/netns) | Нет |
| Старт процесса | ~3s (netns + settle) | ~50ms |
| Per-strategy аргументы | `--lua-desync=...` | `--fake`, `--split`, `--disorder`, etc. |
| Custom blobs | `--blob=NAME:@path` | `--fake-data @path/to/file.bin` |
| Multi-strategy | `--new` profiles или restart | `--auto=trigger` groups (1 процесс) |
| IP кеширование | Нет | `--cache-ttl N` + `--cache-file` |

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
| `fake:blob=stun:repeats=6:tcp_ts=-1000` | `--fake -1 --fake-data @stun.bin --ttl 8` | ✅ Mapped |
| `fake:blob=max_ru:repeats=6:tcp_ts=-1000` | `--fake -1 --fake-data @max_ru.bin --ttl 8` | ✅ |
| `fake:blob=google:repeats=6:tcp_ts=-1000` | `--fake -1 --fake-data @google.bin --ttl 8` | ✅ |
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
| `tlsrec:pos=3+s` | `--tlsrec 3+s` | ✅ |
| `oob:urp=b` | `--oob 0` | ✅ |
| `syndata` (bare) | `--fake -1 --fake-tls-mod rand` | ✅ |
| `syndata:blob=discord_udp` | — | ❌ UDP only, byedpi только TCP |

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
| `drop-sack` | `--drop-sack` ✅ |
| `hostspell=hoSt` | `--mod-http hcsmix` ✅ |

### Blob-маппинг

| nfqws2 blob alias | byedpi |
|-------------------|--------|
| `stun` | `--fake-data @/opt/zapret2/blobs/stun.bin` |
| `max_ru` | `--fake-data @/opt/zapret2/blobs/tls_clienthello_max_ru.bin` |
| `google` | `--fake-data @/opt/zapret2/blobs/tls_clienthello_www_google_com.bin` |
| `4pda` | `--fake-data @/opt/zapret2/blobs/tls_clienthello_4pda_to.bin` |
| `discord_udp` | ❌ (UDP only) |
| `quic_*` | ❌ (QUIC only) |

Используется существующая `BLOB_ALIAS_MAP` из `engine/blob_aliases.py` для резолва alias → файл.

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
    strategy: str             # original nfqws2 strategy string (for DB logging)
    byedpi_flags: list[str]   # translated CLI args
    _proc: subprocess.Popen | None = None

    @classmethod
    def from_strategy(cls, strategy: str, bin_path: str,
                      port: int = 0) -> ByedpiManager:
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
        args = [self.bin_path, "-p", str(self.port), "-i", "127.0.0.1",
                "--proto", "tls"]
        args.extend(self.byedpi_flags)
        self._proc = subprocess.Popen(
            args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
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

_UNMAPPED_FOOLINGS = frozenset({
    "badsum", "badseq", "tcp_ack", "tcp_seq", "tcp_flags_unset",
    "tcp_flags_set", "ip_autottl", "ip6_", "seqovl", "seqovl_pattern",
    "ipfrag", "tcpseg", "padencap",
})

_SUPPORTED_FAMILIES = frozenset({
    "fake", "hostfakesplit", "fakedsplit", "fakeddisorder",
    "multisplit", "multidisorder", "tlsrec", "oob", "syndata",
})

_BYEDPI_POS_MAP = {
    "midsld": "0+sm",
    "mid": "0+m",
    "start": "0",
    "end": "-1+e",
    "host": "0+s",
}
_BYEDPI_POS_MAP_PAT = re.compile(
    r"pos=([^:\]]+)(?::(\d+))?(?::(\d+))?"
)
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
    self, strategy: str, domain: str, status: str, latency_ms: float = 0,
    byedpi_flags: str = "", nfqws2_original: str = "",
    http_code: int = 0, proxy_port: int = 0, error: str = "",
) -> None:
    """Persist one byedpi probe result."""
```

**Файл:** `src/blockchecks/engine/store/__init__.py` (+3 строки в Protocol)

```python
async def log_byedpi(self, strategy: str, domain: str, status: str,
                     latency_ms: float = 0, **kwargs) -> None: ...
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
    """Find ciadpi binary. Order: env → PATH → ~/.local/bin → vendor."""
    env = os.environ.get("BLOCKCHECKS_BYEDPI", "")
    if env and os.path.isfile(env):
        return env
    for path in ("ciadpi", "/usr/local/bin/ciadpi",
                 os.path.expanduser("~/.local/bin/ciadpi")):
        if shutil.which(path) or os.path.isfile(path):
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

### Phase 6 — Benchmark (~1 час)

- [ ] `bs scan -d discord.com --generate standard --max 100 --engine nfqws2` (baseline)
- [ ] `bs scan -d discord.com --generate standard --max 100 --engine byedpi` (comparison)
- [ ] Записать `test/sec` в `docs/byedpi_engine.md`

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
| `ip_autottl` | byedpi использует фиксированный TTL (`--ttl N`) |
| UDP `fake:blob=discord_udp:repeats=6` | `--udp-fake N` есть, но не эквивалентно nfqws2 |
| QUIC `fake:blob=quic_initial:repeats=11` | byedpi не трогает QUIC Initial |
| `--lua-desync=` multiline | Только первая строка маппится |
| `circular:fails=` | Нет аналога, process-per-strategy |

**Для неподдерживаемых foolings возвращается пустой список аргументов → статус `SKIP` в результатах.**

---

## 8. Расширение стратегий на будущее

- **`--auto=torst` для sequential testing** — один процесс, несколько `--auto` групп. Требует поочерёдного курла через разные группы с проверкой какая именно сработала. Оставим на future work.
- **`--auto-mode=2` (swop)** — сортировка стратегий по частоте срабатывания. Полезно для production proxy, не для тестирования.
- **`--cache-ttl` + `--cache-file`** — кеширование успешных стратегий по IP. Production feature.
- **byedpi-only strategy families** — `--tlsrec`, `--fake-sni`, `--mod-http hcsmix` — стратегии которых нет в nfqws2. Могут быть добавлены как отдельное семейство генератора (`byedpi` source в matrix_generator).
