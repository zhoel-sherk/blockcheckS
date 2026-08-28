# Cookbook: add a generator family

Strategy families live in [`engine/generators/families/`](../../src/blockchecks/engine/generators/families/),
exposed through the [`standard.py`](../../src/blockchecks/engine/generators/standard.py) facade
(`StandardGenerator`) and [`matrix_generator.py`](../../src/blockchecks/engine/matrix_generator.py).

## 1. Add the family axis

Families are parameterized by a dict in `StandardGenerator.STRATEGY_FAMILIES`
(`standard.py`), expanded by a `_fam_*` method provided by one of the mixins:

- `families/fake.py` → `FakeFamiliesMixin`
- `families/split.py` → `SplitFamiliesMixin`
- `families/tamper.py` → `TamperFamiliesMixin`

In `families/<module>.py`, add an expander following the dispatch contract
`(self, items, seen, family, scan_level, known_working)`, delegating dedup/append
to `self._add`:

```python
def _fam_my_fake(self, items, seen, family, scan_level, _known_working):
    for blob in family.get("blobs", ["stun", "max_ru"]):
        for r in family.get("repeats", [6]):
            strat = f"fake:blob={blob}:repeats={r}:tcp_ts=-1000"
            self._add(items, seen, f"std_my_fake_{blob}_r{r}", strat)
            if scan_level == "single":
                return items
    return items
```

## 2. Register in dispatch + families list

- Add `"my_fake": { "blobs": [...], "repeats": [6, 3] }` to
  `StandardGenerator.STRATEGY_FAMILIES`.
- Add `"my_fake": "_fam_my_fake"` to `StandardGenerator._FAMILY_EXPANDERS`
  (`standard.py`).
- Add `"my_fake"` to the right protocol list: `TCP_FAMILIES` (TLS) /
  `HTTP_FAMILIES` / `QUIC_HTTP3_FAMILIES` / `UDP_VOICE_FAMILIES` — without this
  the protocol gate in `generate()` filters the family out.

## 3. Protocol gate

Matrix respects `protocol` (`tls12`, `tls13`, `quic`, `udp_voice`). Skip UDP
families when `protocol` is TCP-only.

## 4. Unit test

Add a case in [`tests/unit/test_families_params.py`](../../tests/unit/test_families_params.py)
(or a new family test):

```python
def test_my_family_generates():
    gen = StandardGenerator(strategy_types=["my_fake"])
    items = asyncio.run(gen.generate(protocol="tls12", scan_level="full", max_count=100))
    labels = [i.label for i in items]
    assert any("my_fake" in lb for lb in labels)
```

## 5. Try locally

```bash
sudo bs scan -d discord.com --generate standard --max 20 --scan-level full
```

See [glossary.md](../glossary.md) for `scan_level` semantics.
