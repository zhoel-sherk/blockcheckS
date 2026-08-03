# dev/ — local debug helpers

Ad-hoc scripts for GP/control-plane smoke and `bs tcp` debugging.
Not part of the installable `blockchecks` package; not run by CI.

## Scripts

| Script | What it does | How to run |
|---|---|---|
| `oc_api_head.py` | OpenCode serve API smoke — session + git rev-parse | `python3 dev/oc_api_head.py` (needs OpenCode at `127.0.0.1:4096`) |
| `oc_api_smoke.py` | Robust OC API smoke — auto-discovers endpoint shapes | `python3 dev/oc_api_smoke.py` |
| `oc_smoke.sh` | OpenCode CLI smoke — `opencode run` read-only test | `bash dev/oc_smoke.sh` |
| `run_bs_tcp_debug.sh` | Single-strategy nfqws2 debug run (known-good baseline) | `bash dev/run_bs_tcp_debug.sh` |
| `run_gp_debug.sh` | GP-verified strategy regression with debug output | `bash dev/run_gp_debug.sh` |

All scripts assume project `.venv` and optional OpenCode install.
Run from repo root.
