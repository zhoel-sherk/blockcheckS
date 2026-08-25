"""GGC host/IP pool: SNI под управлением подборщика (zapret2#299/#300 контекст).

Режимы ``BLOCKCHECKS_GGC_MODE``:
- **synthetic** (основной): правдоподобные ``rr{N}---sn-{code}.googlevideo.com``
  генерируются на каждую пробу (точная мимикрия формата, включая дефисные
  суффиксы вида ``-30ze``). DNS у синтетики NXDOMAIN → IP берётся из цепочки
  пулов (см. ниже).
- **real**: живые узлы из файла пула (TTL ≤ 6ч — реальные ссылки/узлы живут
  недолго); резолв обычный DoH.
- **fixed** (legacy A/B базлайн): единственный хост из ``BLOCKCHECKS_GGC_HOST``.

Цепочка IP для synthetic/fallback (dns-hijack на googlevideo — не новость,
хардкод — последний рубеж):
  запись пула → dns.db провайдера (DoH-verified, по хосту) →
  [google] fallback_ips / BLOCKCHECKS_GGC_IPS (явный override) →
  CACHE/ggc_ips.json (кэш резолва, свежие вперёд) → GGC_FALLBACK_IP (legacy).

Выбранный хост возвращается вызывающему и попадает в tcp_results.probe_host.
"""

from __future__ import annotations

import json
import os
import random
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from blockchecks.engine.config import GGC_FALLBACK_IP, GGC_HOST
from blockchecks.engine.paths import CACHE_DIR

log = __import__("logging").getLogger("blockchecks.ggc_pool")

MODE_ENV = "BLOCKCHECKS_GGC_MODE"
MODES = ("synthetic", "real", "fixed")

#: Точная мимикрия наблюдаемого формата узлов Google cache:
#: rr5---sn-5goeenes.googlevideo.com | rr3---sn-uxaxjvh-30ze.googlevideo.com
#: Код может содержать внутренние дефисы (sn-1-ien4): алфавитные сегменты
#: через '-', общая длина кода 4–16.
_RR_RE = re.compile(
    r"^rr(\d{1,3})---sn-(?=[a-z0-9-]{4,16}\.)[a-z0-9]+(?:-[a-z0-9]+)*\.googlevideo\.com$",
    re.IGNORECASE,
)
_CODE_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
_REGION_PREFIXES = (
    "5goeenes", "uxaxjvh", "1-ien4", "a5mek", "h5qfk", "un57", "xjvho",
)
_REGION_SUFFIXES = ("", "-30ze", "-5uae", "-okge", "-4g26", "-ne6")

REAL_POOL_FILE_ENV = "BLOCKCHECKS_GGC_REAL_POOL"
IPS_CACHE_NAME = "ggc_ips.json"
IPS_TTL_SEC = 7 * 24 * 3600  # как dns_records в dns.db
REAL_POOL_TTL_SEC = 6 * 3600  # реальные ссылки rr* живут максимум ~6ч
_NO_REPEAT = 8  # не повторять последние K синтетических кодов

#: Последний рубеж цепочки — проверенные живые Google edge (TCP 443 OK
#: с этой сети 25.08; legacy 74.125.108.234 мёртв и исключён).
DEFAULT_LAST_RESORT_IPS = [
    "64.233.161.198",  # redirector-edge
    "108.177.14.147",
    "74.125.131.103",
    "64.233.161.99",
]
_ROTATION = {"i": 0}


@dataclass
class GgcTarget:
    host: str
    mode: str
    ip_hint: str | None = None  # из записи пула real; для synthetic пусто
    pool_size: int = 0


@dataclass
class _GgcState:
    last_codes: list[str] = field(default_factory=list)


_STATE = _GgcState()


def current_mode() -> str:
    env = os.environ.get(MODE_ENV, "").strip().lower()
    if env in MODES:
        return env
    try:
        from blockchecks.engine.settings import _load_user_toml

        google = (_load_user_toml() or {}).get("google")
        if isinstance(google, dict):
            mode = str(google.get("mode") or "").strip().lower()
            if mode in MODES:
                return mode
    except Exception as exc:
        log.warning("GGC mode from config.toml failed: %s", exc)
    return "synthetic"


# ── генерация синтетики ────────────────────────────────────────────────────


def generate_sn_code() -> str:
    """Правдоподобный sn-code: реальный регион + короткий довесок ≤8 символов,
    опциональный дефисный суффикс (-30ze) — ровно как у живых узлов."""
    prefix = random.choice(_REGION_PREFIXES)
    room = 8 - len(prefix)
    tail = "".join(
        random.choice(_CODE_ALPHABET)
        for _ in range(random.randint(0, max(0, min(3, room))))
        if room > 0
    )
    code = f"{prefix}{tail}"[:8]
    suffix = random.choice(_REGION_SUFFIXES)
    return f"{code}{suffix}" if suffix else code


def generate_synthetic_host() -> str:
    """rr{N}---sn-{code}.googlevideo.com; без повторов последних N кодов."""
    for _ in range(32):
        n = random.randint(1, 60)
        code = generate_sn_code()
        key = f"{n}:{code}"
        if key not in _STATE.last_codes:
            _STATE.last_codes.append(key)
            _STATE.last_codes = _STATE.last_codes[-_NO_REPEAT:]
            return f"rr{n}---sn-{code}.googlevideo.com"
    return f"rr1---sn-{generate_sn_code()}.googlevideo.com"


def is_ggc_host(host: str) -> bool:
    return bool(_RR_RE.match(host or ""))


# ── real-пул (только тесты) ────────────────────────────────────────────────


def real_pool_path() -> Path:
    env = os.environ.get(REAL_POOL_FILE_ENV, "").strip()
    if env:
        return Path(env).expanduser()
    return CACHE_DIR / "ggc_real_hosts.json"


def load_real_pool(*, max_age_sec: float = REAL_POOL_TTL_SEC) -> list[str]:
    path = real_pool_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    ts = float(data.get("timestamp", 0))
    if max_age_sec > 0 and time.time() - ts > max_age_sec:
        log.warning("%s", f"  ggc: real pool expired ({path.name}), age={int(time.time()-ts)}s")
        return []
    return [
        h
        for h in data.get("hosts", [])
        if isinstance(h, str) and is_ggc_host(h)
    ]


# ── цепочка IP ─────────────────────────────────────────────────────────────


def ips_cache_path() -> Path:
    return CACHE_DIR / IPS_CACHE_NAME


def remember_ggc_ip(host: str, ip: str) -> None:
    """Кэшировать успешный резолв любого ggc-хоста (подключаемый список IP)."""
    if not ip or not is_ggc_host(host):
        return
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            data = json.loads(ips_cache_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {"ips": {}}
        entries = {k: v for k, v in data.get("ips", {}).items()
                   if time.time() - float(v.get("ts", 0)) < IPS_TTL_SEC}
        entries[host] = {"ip": ip, "ts": time.time()}
        # держим не более 256 свежих записей
        trimmed = dict(sorted(entries.items(), key=lambda kv: -kv[1]["ts"])[:256])
        ips_cache_path().write_text(
            json.dumps({"ips": trimmed}, indent=0), encoding="utf-8"
        )
    except OSError as exc:
        log.warning("%s", f"  ggc: ips-cache write failed: {exc}")


def cached_ips() -> list[str]:
    """Свежие уникальные IP из кэша резолва (новые вперёд)."""
    try:
        data = json.loads(ips_cache_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    now = time.time()
    seen: set[str] = set()
    out: list[str] = []
    for _, entry in sorted(data.get("ips", {}).items(),
                           key=lambda kv: -float(kv[1].get("ts", 0))):
        ip = str(entry.get("ip", ""))
        if ip and float(entry.get("ts", 0)) >= now - IPS_TTL_SEC and ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def configured_fallback_ips() -> list[str]:
    env = os.environ.get("BLOCKCHECKS_GGC_IPS", "").strip()
    if env:
        return [ip.strip() for ip in env.split(",") if ip.strip()]
    try:
        from blockchecks.engine.settings import _load_user_toml

        google = (_load_user_toml() or {}).get("google")
        if isinstance(google, dict) and isinstance(google.get("fallback_ips"), list):
            return [str(ip) for ip in google["fallback_ips"]]
    except Exception as exc:
        log.warning("GGC fallback_ips from config.toml failed: %s", exc)
    return []


def resolve_ip_chain(host: str) -> str | None:
    """IP по всей цепочке: dns.db → конфиг/env → кэш → ротация живых IP."""


    try:
        from blockchecks.data_block.provider import get_provider_dir
        from blockchecks.data_block.store import ProviderStore

        recs = ProviderStore(get_provider_dir()).load_dns_records_sync()
    except Exception as exc:
        log.warning("GGC dns.db lookup failed for %s: %s", host, exc)
        recs = {}
    pool: list[str] = []
    ips, _src = recs.get(host, ([], ""))
    if ips:
        pool = list(ips)  # точное имя хоста — самый сильный сигнал
    else:
        # Явная конфигурация оператора выше глобального кэша:
        # это сознательный override, а не «что-то недавно резолвилось».
        configured = configured_fallback_ips()
        if configured:
            pool = configured
        else:
            cached = cached_ips()
            if cached:
                pool = cached
            else:
                pool = list(DEFAULT_LAST_RESORT_IPS)
    if not pool:
        return GGC_FALLBACK_IP if host == GGC_HOST else None
    # Перебор при повторных ошибках DNS: каждый вызов берёт следующий IP,
    # неудачные адреса естественно вымываются из начала очереди кэшем.
    i = _ROTATION["i"] % len(pool)
    _ROTATION["i"] += 1
    return pool[i]


# ── выбор цели ─────────────────────────────────────────────────────────────


def pick_target(domain_hint: str | None = None) -> GgcTarget:  # noqa: ARG001
    """Хост+подсказка IP для очередной GGC-пробы. Никогда не бросает.

    ``domain_hint`` — домен из матрицы (googlevideo.com и т.п.), пока не
    влияет на выбор; зарезервировано для пер-доменных пулов.
    """
    mode = current_mode()
    if mode == "fixed":
        return GgcTarget(host=GGC_HOST, mode=mode, ip_hint=None, pool_size=1)
    if mode == "real":
        pool = load_real_pool()
        if pool:
            host = random.choice(pool)
            return GgcTarget(host=host, mode=mode, ip_hint=None, pool_size=len(pool))
        log.warning("%s", "  ggc: mode=real but pool empty/expired — synthetic fallback")
    host = generate_synthetic_host()
    ip_hint = None
    try:
        data = json.loads(ips_cache_path().read_text(encoding="utf-8"))
        entry = data.get("ips", {}).get(host)
        if entry and time.time() - float(entry.get("ts", 0)) < IPS_TTL_SEC:
            ip_hint = str(entry.get("ip"))
    except (OSError, ValueError):
        pass
    return GgcTarget(host=host, mode=current_mode(), ip_hint=ip_hint)


__all__ = [
    "MODES",
    "GgcTarget",
    "cached_ips",
    "configured_fallback_ips",
    "current_mode",
    "generate_sn_code",
    "generate_synthetic_host",
    "is_ggc_host",
    "load_real_pool",
    "pick_target",
    "real_pool_path",
    "remember_ggc_ip",
    "resolve_ip_chain",
]
