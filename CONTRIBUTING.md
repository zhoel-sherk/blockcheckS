# Contributing to blockcheckS

Thanks for helping improve the lightspeed DPI strategy tester for zapret2/nfqws2.

## Prerequisites

| Requirement | When |
|-------------|------|
| Linux (Ubuntu 22.04+ recommended) | runtime / integration tests |
| Python 3.10+ | always |
| `pip install -e ".[dev,discovery]"` | development |
| zapret2/nfqws2 at `/opt/zapret2` (or `BLOCKCHECKS_NFQWS2`) | integration / real scans |
| root/sudo | netns + iptables tests |

Windows is supported for **unit tests only** (`pytest -m "not integration"`).

## Setup

```bash
git clone https://github.com/zhoel-sherk/blockcheckS.git
cd blockcheckS
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,discovery]"
```

Optional environment (copy from [`settings.example.env`](settings.example.env)):

```bash
export BLOCKCHECKS_NFQWS2=/opt/zapret2/nfq2/nfqws2
export BLOCKCHECKS_BLOBS=/opt/zapret2/blobs
```

## Checks before opening a PR

```bash
ruff check src tests
pytest -m "not integration and not quality and not mutation" -q
```

Static quality gates (policy in `pyproject.toml`: vulture, McCabe/C90, SIM, ARG, archon, AST, dead CLI flags):

```bash
pytest -m quality -q
```

CLI entry uses **pydantic CliApp** (`blockchecks.cli.cliapp`); flag definitions remain in `cli/parser.py` `add_*` helpers. Legacy argparse entry: `BLOCKCHECKS_ARGPARSE=1`.

Optional mutation testing (scoped via `[tool.mutmut]`, slow; also CI `workflow_dispatch`):

```bash
./scripts/mutmut_gate.sh
# or: pytest -m mutation
```

Optional (Linux + nfqws2 + sudo):

```bash
sudo pytest -m integration -q
```

Smoke after CLI changes:

```bash
bs --help
bs pair -h
```

## What not to commit

See [`.gitignore`](.gitignore). Never commit:

- `state.db`, `logs/`, `output/`
- tokens, `settings.ini`, credentials
- `*.egg-info/`, `.venv/`
- `.mutmut-cache/`, mutmut HTML reports

## Where to change what

| Task | Start here |
|------|------------|
| Architecture / data flow | [docs/architecture.md](docs/architecture.md) |
| Quality thresholds / layers | [`pyproject.toml`](pyproject.toml) (`tool.blockchecks.*`, `tool.vulture`, `tool.mutmut`) |
| Add a checker | [docs/cookbook/add-checker.md](docs/cookbook/add-checker.md) |
| Add a strategy family | [docs/cookbook/add-generator.md](docs/cookbook/add-generator.md) |
| Add a CLI flag | [docs/cookbook/add-cli-flag.md](docs/cookbook/add-cli-flag.md) |
| Package layout | [docs/package.md](docs/package.md) |
| SQLite schema / queries | [docs/database.md](docs/database.md) |
| Product roadmap | [docs/todo.md](docs/todo.md) (not for day-one onboarding) |

## PR checklist

- [ ] `ruff check src tests` passes
- [ ] `pytest -m "not integration and not quality and not mutation"` passes
- [ ] `pytest -m quality` passes (or CI quality job)
- [ ] Docs updated if CLI or public API changed
- [ ] No secrets, `state.db`, or machine-specific paths

## Known limitations

- `--user-matrix -` (strategy list from stdin) is **not** supported by
  `UserMatrixGenerator`; pass a regular file path instead. The `bs pair
  --lua-bridge-compare` integration test currently uses stdin and is skipped in
  CI for this reason.

## Install note

Use **editable install** from a git checkout (`pip install -e .`). Strategy
`.conf` files live in repo-root [`configs/`](configs/), not inside the wheel
package — see [docs/package.md](docs/package.md).
