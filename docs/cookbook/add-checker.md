# Cookbook: add a checker

Checkers live in [`src/blockchecks/checkers/`](../src/blockchecks/checkers/). They
validate connectivity (TLS, UDP, voice) and return dataclasses.

## 1. Define result dataclass

Follow [`tcp_tls.py`](../src/blockchecks/checkers/tcp_tls.py):

```python
@dataclass
class MyResult:
    success: bool = False
    latency_ms: float = 0.0
    error: str | None = None
```

## 2. Implement check function

```python
def check_my_thing(target: str, timeout: float = 5.0) -> MyResult: ...
```

Keep I/O in the checker; runners orchestrate netns/nfqueue, workers run probes.

## 3. Wire into runner

| Runner | When |
|--------|------|
| [`async_runner.py`](../src/blockchecks/engine/async_runner.py) | `bs scan`, `bs pair`, `bs full` |
| [`test_runner.py`](../src/blockchecks/engine/test_runner.py) | `bs tcp`, `bs udp` (sync) |
| [`in_ns_workers.py`](../src/blockchecks/engine/in_ns_workers.py) | subprocess probe worker (`--mode curl\|udp`) |

For async batch tests, prefer calling the checker from the subprocess worker
(`python -m blockchecks.engine.in_ns_workers --mode curl`, see
[`service/probe.py`](../src/blockchecks/service/probe.py)); the old
`_probe_worker.py`/`_curl_probe_worker.py` are back-compat proxies only.

## 4. Unit test

Add tests in `tests/unit/test_checkers.py` or new file. Mock network; no root.

```bash
pytest tests/unit/test_checkers.py -q
```

## 5. Export (optional)

Add to [`checkers/__init__.py`](../src/blockchecks/checkers/__init__.py) if public API.

See [architecture.md](../architecture.md) for public vs internal boundaries.
