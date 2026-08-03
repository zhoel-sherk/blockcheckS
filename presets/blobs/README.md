# Blobs (baked in-repo)

Runtime resolution prefers **`blobs/` at the repo root** (committed binaries).
Override with `BLOCKCHECKS_BLOBS`. Fallback: `/opt/zapret2/blobs` and
`/opt/zapret2/files/fake`.

Alias map: `src/blockchecks/engine/blob_aliases.py`.

## Core Flowseal set (in `blobs/`)

| Alias | File |
|-------|------|
| `stun` | `stun.bin` |
| `stun2` | `stun2.bin` |
| `max_ru` | `tls_clienthello_max_ru.bin` |
| `google` | `tls_clienthello_www_google_com.bin` |
| `4pda` | `tls_clienthello_4pda_to.bin` |
| `quic_google` | `quic_initial_www_google_com.bin` |
| `quic_dbank` | `quic_initial_dbankcloud_ru.bin` |
| `discord_udp` | `discord_udp.bin` |
| `game_udp` | `game_udp.bin` |

Plus extras already baked (`quic_*`, `tls_vk`, `http_iana`, …).

**No download required** for `bs scan --tcp-sources flowseal`. Optional host sync:
`scripts/install_blobs.sh` (fills `/opt/zapret2/blobs` only).

## Built-in (no file)

| Alias | nfqws2 |
|-------|--------|
| `fake_default_tls` / `_http` / `_quic` | yes |
| `0x00000000` | null blob |

## Add a new blob

See [docs/cookbook/blobs.md](../../docs/cookbook/blobs.md).
