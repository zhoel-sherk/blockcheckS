# dev/ — local debug helpers

Ad-hoc scripts for GP/control-plane smoke and `bs tcp` debugging.
Not part of the installable `blockchecks` package; not run by CI.

## Scripts

| Script | What it does | How to run |
|---|---|---|
| `run_bs_tcp_debug.sh` | Single-strategy nfqws2 debug run (known-good baseline) | `bash dev/run_bs_tcp_debug.sh` |
| `run_gp_debug.sh` | GP-verified strategy regression with debug output | `bash dev/run_gp_debug.sh` |
| `functional_smoke.sh` | End-to-end functional test of every `bs` subcommand (sudo) | `bash dev/functional_smoke.sh` |
| `byedpi_bench.py` | byedpi/ciadpi strategy micro-benchmark | `python3 dev/byedpi_bench.py` |

## Test-campaign smoke scripts (in `scripts/`)

These are the repeatable functional-test entry points used during audits:

| Script | What it does |
|---|---|
| `scripts/smoke_scan.sh` | Quick `bs scan` on a known-good user matrix; backend selectable |
| `scripts/smoke_full_quick.sh` | Time-boxed `bs full`; verifies deadline-stop, export, run_summary |
| `scripts/smoke_backend_matrix.sh` | Functional test of `--classic` / `--probe-backend` / env / compare |
| `scripts/gate_all.sh` | One-shot unit + quality + ruff + vulture (optionally integration) |
| `scripts/cleanup_env.sh` | Reset netns / nfqws2 / shm / run.lock between campaigns |

All scripts assume project `.venv` and optional OpenCode install.
Run from repo root.
