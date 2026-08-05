# Cookbook: add a generator family

Strategy generators live in [`engine/generators/`](../src/blockchecks/engine/generators/)
(facade: [`matrix_generator.py`](../src/blockchecks/engine/matrix_generator.py)).

## 1. Add family method

In [`generators/standard.py`](../src/blockchecks/engine/generators/standard.py)
(or new generator class), add a method that yields strategy strings:

```python
def my_family(self, scan_level: str, max_count: int) -> list[StrategyItem]:
    items = []
    for blob in ("stun", "max_ru"):
        items.append(
            StrategyItem(
                label=f"my_fake_{blob}",
                strategy=f"fake:blob={blob}:repeats=6:tcp_ts=-1000",
            )
        )
    return items[:max_count] if max_count else items
```

## 2. Register in generator dispatch

Hook into `StandardGenerator.generate()` or `register_generator()` in
[`generators/base.py`](../src/blockchecks/engine/generators/base.py).

## 3. Protocol gate

Matrix respects `protocol` (`tls12`, `tls13`, `quic`, `udp_voice`). Skip UDP
families when `protocol` is TCP-only.

## 4. Unit test

Add case in [`tests/unit/test_matrix_generator.py`](../../tests/unit/test_matrix_generator.py):

```python
def test_my_family_generates():
    gen = StandardGenerator()
    items = asyncio.run(gen.generate(protocol="tls12", scan_level="full", max_count=0))
    labels = [i.label for i in items]
    assert any("my_fake" in lb for lb in labels)
```

## 5. Try locally

```bash
sudo bs scan -d discord.com --generate standard --max 20 --scan-level full
```

See [glossary.md](../glossary.md) for `scan_level` semantics.
