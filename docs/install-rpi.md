# Установка на Raspberry Pi 2+ (armv7l / armv6l)

blockcheckS устанавливается на 32-битные ARM-платы (RPi 2/3 32-bit) **без
компиляции native-зависимостей**: все обязательные пакеты имеют prebuilt
wheels для armv7l на PyPI.

## Что было проблемой и как решено

| Пакет | armv7l wheel | Статус |
|---|---|---|
| `curl-cffi` | ✅ `cp310-abi3-manylinux_2_28_armv7l` | Уже на PyPI (0.15/0.16) |
| `pydantic-core` | ✅ `cp312-manylinux_2_17_armv7l` | Уже на PyPI |
| `psutil` | ❌ **0 wheels** → заставлял gcc | **Удалён** из deps, заменён на stdlib `/proc` |
| `blockchecks` (сам) | чистый Python | Wheel собирается setuptools без native |

До этого на RPi2 единственным пакетом без wheel был `psutil` — pip собирал
его из sdist, требуя gcc. Теперь `metrics.py` читает `/proc/<pid>/status`
(VmRSS/VmSize) и `/proc/*/ns/net` напрямую (stdlib), поэтому сборки нет.

## Установка

```bash
# Рекомендуемый способ — скрипт (venv + pip + smoke-проверка без psutil):
bash scripts/setup-standalone.sh

# Или вручную:
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e .            # все deps — с armv7l wheels
.venv/bin/python -c "import blockchecks"   # smoke
```

## nfqws2 для ARM

blockcheckS сам скачивает подходящий nfqws2: `system_deps.py` мапит
`armv7l`/`armv6l` → `binaries/linux-arm` официального релиза zapret2.
Первый запуск `bs tcp` загрузит его в `~/.local/share/blockcheckS/zapret2/`.

Проверка стратегии (нужен root + netns):

```bash
sudo -E .venv/bin/bs tcp -d discord.com -s "fake:blob=stun:repeats=6:tcp_ts=-1000" --skip-deps-check
```

## Требования на RPi2

- Linux 32-bit (armv7l); netns (`sudo ip netns`) и iptables для изоляции тестов
- Python 3.10+ (wheels `cp310-abi3` работают на 3.10+)

## CI-проверка

GitHub Actions job `armv7l-smoke` (workflow_dispatch) поднимает
`linux/arm/v7` через QEMU и проверяет: `pip install .` без компиляции +
`import blockchecks` + `/proc`-метрики. Реальный RPi2 проходить не обязан.
