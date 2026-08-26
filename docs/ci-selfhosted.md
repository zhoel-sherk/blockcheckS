# Self-hosted CI probe runner

Optional GitHub Actions runner for the **full** `integration` job
(`.github/workflows/ci.yml`). GitHub `ubuntu-latest` has no nfqws2, sudo netns,
or ISP path — so the full suite stays **`workflow_dispatch` only**.

Push/PR CI runs `lint-and-quality`, sharded `unit-tests`, and `integration-safe`
(SQLite concurrency + firewall shape; no nfqws2 PATH gate). It does **not**
start a full integration matrix on a live probe host.

## Label

Register the runner with label **`[probe]`** (exactly that token in
`runs-on`). Do not attach this label to a GitHub-hosted machine.

## nfqws2

The daemon must be on `PATH`, or set:

```bash
export BLOCKCHECKS_NFQWS2=/opt/zapret2/nfq2/nfqws2
```

Default resolution also looks at `/opt/zapret2/nfq2/nfqws2`. The dispatch
`integration` job fails loudly if `nfqws2` is missing (`command -v`); that is
intentional.

## Do not run full `cleanup_env.sh` during week_cov

`scripts/cleanup_env.sh` without flags does a **host-wide** `pkill nfqws2` and
deletes all blockcheckS netns. During `week_cov` / A→F that kills the campaign.

If a runner must tidy leftovers while a series is live:

```bash
sudo bash scripts/cleanup_env.sh --orphans-only --exclude-prefix=bs-p-<pid>-
```

Without `--exclude-prefix`, the script infers it from `run.lock`. Without a lock
and without a prefix, `--orphans-only` exits 2 rather than wiping live ns.

## Refuse if `run.lock` exists

`~/.local/state/blockcheckS/run.lock` means `bs full` / `scan` / `pair` / `serve`
already owns the host. Do **not** start the full integration job (or any other
nfqws2/netns suite) on that machine until `bs stop` and the lock is gone.

## No fork-PR on a public repo / this LAN probe host

A self-hosted `[probe]` runner on the LAN (this Xeon / Fiord path) must **not**
run workflows from **fork pull requests**. Fork PRs can execute untrusted code
as the runner user with sudo and LAN access.

Keep the probe runner on a private repo, or disable fork PR workflows for that
runner. Public `ubuntu-latest` jobs are fine; they never get `[probe]`.

## Dispatch-only jobs

These stay `workflow_dispatch` (not push/PR):

| Job | Why |
|---|---|
| `integration` | Full `tests/integration` + loud nfqws2 gate; needs `[probe]` |
| `mutation` | mutmut; slow, not a merge gate |
| `armv7l-smoke` | QEMU arm32 install smoke; slow |

Do **not** wire full integration to automatic push on this Xeon.
