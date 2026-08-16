# Long-term strategy tuning runs (series A→F)

Sequential 20h coverage runs, each using a different strategy-pool / backend /
adaptive mode, to maximize domain coverage and find working strategies across
the full pool (incl. the new Geneva/Flowseal audit families).

## Variants

| Var | DB | Method | Key params |
|---|---|---|---|
| A | `logs/run_A_base.db` | Adaptive baseline | coverage.txt, bridge-batch 10, timeout 2, lua-bridge, `--adaptive --adaptive-epsilon 0.1` |
| B | `logs/run_B_new.db` | Full new pool | coverage.txt, `--max 30000`, timeout 2, `--scan-level full`, `geneva.lua` |
| C | `logs/run_C_adaptive.db` | Adaptive + fan-out | `--fan-out --adaptive --adaptive-epsilon 0.1` |
| D | `logs/run_D_classic.db` | Classic backend | `--classic` (no lua-bridge) |
| E | `logs/run_E_flowseal.db` | Flowseal-only | `--tcp-sources flowseal` |
| F | `logs/run_F_stable.db` | Stable repeats | `--repeats 3 --repeats-mode stable` |

All runs:
- domains: `presets/domains/coverage.txt` (~40)
- `--max-timeh 20 --resume --data-block-sync --parallel 4 --bridge-batch 10`
- `--allow-dns-hijack --skip-prolog/ip-block/port-block --isp-interface eth3`
- `--no-wssize --no-settle-profile --timeout 2` (все варианты)
- PASS exported to `data_block/providers/<provider>/strategies.db` (`pass_strategies`)

## Launch

```bash
scripts/run_long_term_series.sh 20 A     # sequential A→F, 20h each
# or single variant:
scripts/run_variant.sh A 20               # just A
scripts/run_coverage_new.sh 20            # standalone B (with geneva.lua)
```

Monitors (in tmux):
- orchestrator: `tmux attach -t bs-series`
- current variant: `tmux attach -t bs-run-<LETTER>`
- progress: `scripts/monitor_series.sh [A|B|C|D|E|F]`
- graceful stop current variant: `bs stop`
- per-run logs: `logs/run_<LETTER>_<ts>.log` (path in `logs/run_<LETTER>_LATEST.logpath`)

## Reading results

```bash
# top strategies by domain coverage
.venv/bin/python3 - <<'EOF'
from blockchecks.engine.store import RunStateStore
import asyncio
async def main():
    db = RunStateStore(path="logs/run_A_base.db")
    for s in await db.get_best_by_coverage(limit=20):
        print(s)
asyncio.run(main())
EOF
```

PASS strategies accumulate in `data_block/providers/llc_trc_fiord/strategies.db`
(`pass_strategies`, UNIQUE(strategy,domain)) across ALL variants.

## Notes

- Sequential (never parallel) — 4 netns pool is shared; parallel runs would
  fight for netns + bandwidth.
- `--data-block-sync` enabled for every variant: PASS goes straight into the
  provider data_block (no separate provider created).
- `geneva.lua` (`fool=bs_*`) loaded via `BLOCKCHECKS_LUA_EXTRA` in variant B
  (and standalone run_coverage_new.sh).
- If a variant crashes (OOM/SIGKILL), `--resume` continues it on next launch;
  the orchestrator waits for the tmux session to end, so a crashed run must be
  relaunched manually.
