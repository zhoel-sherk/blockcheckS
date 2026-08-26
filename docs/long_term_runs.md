# Long-term strategy tuning runs (series A→F, plus G)

Sequential 20h coverage runs, each using a different strategy-pool / backend /
adaptive mode, to maximize domain coverage and find working strategies across
the full pool (incl. the new Geneva/Flowseal audit families).

## Variants

| Var | DB | Method | Key params |
|---|---|---|---|
| A | `logs/run_A_base.db` | Adaptive baseline | coverage.txt, bridge-batch 10, timeout 2, lua-bridge (AQ default ON since 1.3.1; scripts pass `--adaptive-epsilon 0.1` explicitly) |
| B | `logs/run_B_new.db` | Full new pool | coverage.txt, `--max 30000`, timeout 2, `--scan-level full`, `geneva.lua` |
| C | `logs/run_C_adaptive.db` | Adaptive + fan-out | `--fan-out --adaptive-epsilon 0.1` (AQ + fan-out; `--adaptive` redundant — default ON) |
| D | *(retired)* | Campaign classic | per-strategy nfqws2 restart — **removed**; use A |
| E | `logs/run_E_flowseal.db` | Flowseal-only | `--tcp-sources flowseal` |
| F | `logs/run_F_stable.db` | Stable repeats | `--repeats 3 --repeats-mode stable` |
| G | `logs/run_G_udp_voice.db` | Discord-voice UDP | `bs pair` generate_udp full, `custom,standard_udp,configs,flowseal`, `--udp-bypass`, EP `35.217.48.152:50004` + `--discover-dns`; **not** in A→F |

All runs:
- domains: `presets/domains/coverage.txt` (~40)
- **Profile shortcut (1.3.7):** `--profile 20h` bundles
  `--scan-level full --resume --no-preflight --no-wssize --timeout 2.0
  `--allow-dns-hijack --fan-out` (see [guide.md](guide.md#профили))
- `--max-timeh 20 --resume --data-block-sync --parallel 4 --bridge-batch 10`
- `--allow-dns-hijack --no-preflight --isp-interface eth3`
- `--no-wssize --no-settle-profile --timeout 2` (все варианты)
- Adaptive queue ON by default (`--no-adaptive` to disable); legacy `--adaptive`
  flag kept as inverse alias only
- PASS exported to XDG `data_block/providers/<provider>/strategies.db` (`pass_strategies`)

## Launch

```bash
scripts/run_long_term_series.sh 20 A     # sequential A→F, 20h each
# or single variant:
scripts/run_variant.sh A 20               # just A
scripts/run_variant.sh G 20               # Discord-voice UDP (not part of A→F)
scripts/run_coverage_new.sh 20            # standalone B (with geneva.lua)
```

Monitors (in tmux):
- orchestrator: `tmux attach -t bs-series`
- current variant: `tmux attach -t bs-run-<LETTER>`
- progress: `scripts/monitor_series.sh [A|B|C|D|E|F|G]`
- graceful stop current variant: `bs stop`
- per-run logs: `logs/run_<LETTER>_<ts>.log` (path in `logs/run_<LETTER>_LATEST.logpath`)

## Reading results

```bash
# top strategies by domain coverage
.venv/bin/python3 - <<'EOF'
from blockchecks.engine.store import open_run_store
import asyncio
async def main():
    db = open_run_store("logs/run_A_base.db")
    for s in await db.get_best_by_coverage(limit=20):
        print(s)
    await db.close()
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

## Week coverage (Discord → YouTube → lists)

Not A→F. New SQLite `logs/week_cov.db`; provider `strategies.db` is append-only
(`--data-block-sync`). One tmux `bs-week`, one `bs full` at a time.

| Stage | Hours | Preset / command |
|---|---:|---|
| S0 | ~30 min | DoH pin (`updates.discord.com`, `dl.discordapp.net`, …) — done before launch |
| S1 | 48 | `bs full --preset discord --tcp-only` |
| S2 | 48 | `--preset google-youtube --tcp-only --resume` |
| S3 | 24 | `--preset coverage-tcp` (16 domains, incl. updates + gateway) |
| S4 | 8+8+8 | amazon-aws → cloudflare → diagnostic |
| S5 | 24 | Discord UDP `bs pair` → `logs/week_cov_udp.db` |

```bash
scripts/run_week_coverage.sh              # S1→S5, refuses if A→F tmux is up
scripts/run_week_coverage.sh S3           # resume from coverage-tcp
scripts/run_week_coverage.sh export       # bc-nfconf + pass_strategies dump
tmux attach -t bs-week
scripts/monitor_series.sh week
bs stop                                   # stop current bs; orchestrator continues
```

Do **not** pass `--profile 20h` on the first pin; S1+ uses `--no-preflight`.
TCP stages do **not** use `--allow-unsafe-domains`. Old `logs/run_A_*.db` stay.
