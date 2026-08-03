# Blob manifest (BLOB-1)

Runtime blobs live under `/opt/zapret2/blobs/` (or `BLOCKCHECKS_NFQWS2` parent).
blockcheckS strategy strings use **aliases** (`stun`, `max_ru`, `google`, …) resolved
by nfqws2 at runtime — not wheel-packaged binaries.

## Tier-1 (present in `/opt/zapret2/blobs/`)

| Alias | File | Use |
|-------|------|-----|
| `stun` | `stun.bin` | Dual-fake, UDP STUN |
| `max_ru` | `tls_clienthello_max_ru.bin` | General TLS / YouTube |
| `google` | `tls_clienthello_www_google_com.bin` | Google hostlist |
| `4pda` | `tls_clienthello_4pda_to.bin` | Alt TLS fingerprint |
| `discord_udp` | `discord_udp.bin` | Voice UDP 50000–50100 |
| `quic_google` | `quic_initial_www_google_com.bin` | QUIC / HTTP3 |
| `quic_dbank` | `quic_initial_dbankcloud_ru.bin` | VK/social QUIC |
| `quic_gv_kyber_1` | `quic_gv_kyber_1.bin` → `files/fake/quic_initial_*_googlevideo_com_kyber_1.bin` | YouTube CDN QUIC (GV-5) |
| `quic_gv_kyber_2` | `quic_gv_kyber_2.bin` | YouTube CDN QUIC alt kyber |
| `stun2` | `stun2.bin` | Alt STUN (Flowseal) |
| `quic_4pda` | `quic_4pda.bin` | Alt QUIC 4pda |
| `quic_tencent` | `quic_tencent.bin` | Tencent QUIC |
| `quic_steam` | `quic_steam.bin` | Steam QUIC |
| `discord_ipdisc` | `discord_ipdisc.bin` | Official zapret 74B voice alt |
| `wireguard_init` | `wireguard_init.bin` | WG initiation UDP |
| `http_iana` | `http_iana.bin` | HTTP fake desync |

Alias resolution: `src/blockchecks/engine/blob_aliases.py` (`BLOB_ALIAS_MAP`).
Install symlinks: `scripts/install_blobs.sh`.

## Built-in (no file)

| Alias | nfqws2 built-in |
|-------|-----------------|
| `fake_default_tls` | yes |
| `fake_default_http` | yes |
| `fake_default_quic` | yes |

## Tier-1 gaps (BLOB-2 — copy from Flowseal/bol-van)

| Alias | Source | Priority |
|-------|--------|----------|
| `game_udp` | `ACTIVE_GAME_UDP.bin` | high |
| `tls_vk` | `tls_clienthello_vk_com.bin` | medium |
| `quic_vk` | `quic_initial_vk_com.bin` | medium |

Wheel policy: do **not** vendor blobs in the Python package; symlink or deploy
to `/opt/zapret2/blobs/` on the test host (see `ONB-7` vs `BLOB-1` in docs/todo.md).
