# GP ↔ blockcheckS bridge

Shortlist export/import and flag mapping between GP-control-plane and blockcheckS.

## Flag mapping

| GP (`DiscoveryOptions`) | blockcheck2 env | blockcheckS |
|-------------------------|-----------------|-------------|
| `repeats` (1..10) | `REPEATS` | `--repeats N` |
| `repeat_parallel` | `PARALLEL=1` | `--parallel-repeats` |
| `curl_parallelism` | `GP_MD_CURL_PARALLELISM` | `--curl-parallel N` (B2 fan-out) |
| `scan_level` quick/standard/force | `SCANLEVEL` | `--scan-level single/fast/full` |

**Do not confuse:** `repeat_parallel` (N curl attempts per strategy) vs `curl_parallelism` / `--curl-parallel` (N domains per nfqws2 session).

## Repeats modes

| Mode | blockcheckS flag | BC2-like behavior |
|------|------------------|-----------------|
| fast (default) | `--repeats-mode fast` | Stop on first PASS (mass-scan speed) |
| stable | `--repeats-mode stable` | Run all N attempts; PASS if any succeeded |

With `--repeats-mode stable` and `--scan-level fast|single`, FAIL stops repeat loop early (BC2 `SCANLEVEL=quick`).

## Workflow: time-boxed scan → GP shortlist

```bash
# 1. blockcheckS adaptive mass scan (~2h)
sudo bs full --fan-out --allow-dns-hijack \
  --domains-file presets/domains/benchmark.txt \
  --max-timeh 2 --db logs/bs_run.db --out-dir logs/bs_export

# 2. Export shortlist JSON for GP
python3 -m blockchecks.shortlist_export --db logs/bs_run.db -o logs/shortlist.json

# 3. Optional: seed blockcheckS DB from shortlist
python3 -m blockchecks.shortlist_import -i logs/shortlist.json --seed-db --db logs/seed.db

# 4. GP multi-domain discovery uses blockcheck2 with same repeats env
#    (see gp-control-plane DiscoveryOptions.to_blockcheck_env)
```

## nfconf export

```bash
bc-nfconf --db logs/bs_run.db --limit 3 --out-dir logs/bs_export \
  --domains-file presets/domains/benchmark.txt
```

Produces `nfqws2_*.conf` (keenetic) + raw + user.list — deploy to Keenetic or use as GP seed.
