# Blobs cookbook

blockcheckS ships **baked binaries** under [`blobs/`](../../blobs/) at the repo
root. Strategy strings use short **aliases** (`stun`, `max_ru`, `google`, …)
resolved by [`blob_aliases.py`](../../src/blockchecks/engine/blob_aliases.py).

Upstream Flowseal pack (reference only):
[Flowseal/zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube).

## Defaults

1. `BLOCKCHECKS_BLOBS` if set
2. Else repo `blobs/` when it contains `*.bin`
3. Else `/opt/zapret2/blobs` (+ `files/fake` search)

`scripts/install_blobs.sh` is **optional** (extra / host-local sync). Core Flowseal
aliases resolve from the repo without network.

## Add a new blob

1. Copy the file into the repo:

```bash
cp /path/to/my_payload.bin blobs/my_payload.bin
```

2. Register an alias in `BLOB_ALIAS_MAP` inside
   `src/blockchecks/engine/blob_aliases.py`:

```python
"my_payload": "my_payload.bin",
```

3. Optionally include it in `FlowsealGenerator` axes (`_TCP_PREFERRED` /
   `_QUIC_PREFERRED` / `_UDP_PREFERRED`) or a preset under `presets/strategies/`.

4. Verify:

```bash
PYTHONPATH=src python scripts/verify_blobs.py
# or
python -c "from blockchecks.engine.blob_aliases import resolve_blob_path; print(resolve_blob_path('my_payload'))"
```

5. Commit the `.bin` (see `.gitattributes`: `*.bin binary`).

## Flowseal matrix

```bash
# Full technique matrix (may be >1000 strategies; use --max)
sudo bs scan -d discord.com --tcp-sources flowseal --max 200 --parallel 4

# Curated shortlist
bs scan -d discord.com -M flowseal-fast
```
