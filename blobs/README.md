# Baked strategy blobs

Committed `.bin` payloads for nfqws2 `--blob=` / Flowseal-style strategies.

- Prefer this directory at runtime (see `BLOCKCHECKS_BLOBS` / `config.BLOB_DIR`).
- Alias map: `src/blockchecks/engine/blob_aliases.py`
- How to add a file: [docs/cookbook/blobs.md](../docs/cookbook/blobs.md)
- Upstream reference: https://github.com/Flowseal/zapret-discord-youtube

## TLS ClientHello blobs (TCP :443 fake payloads)

| Alias | File | Size | Source / note |
|---|---|---|---|
| `google` / `tls_clienthello` | `tls_clienthello_www_google_com.bin` | 681 B | www.google.com ClientHello (Flowseal bin) — базовый Google-фейк |
| `max_ru` | `tls_clienthello_max_ru.bin` | 664 B | max.ru ClientHello (Flowseal) — подтверждён на LLC Fiord |
| `4pda` | `tls_clienthello_4pda_to.bin` | 284 B | 4pda.to ClientHello (Flowseal) |
| `tls_vk` | `tls_clienthello_vk_com.bin` | 517 B | vk.com ClientHello |
| `tls_5ka` | `tls_5ka.bin` | 654 B | **5ka.ru ClientHello (NEW, Flowseal 2026)** — Пятёрочка, обход РКН |
| `tls_funpay` | `tls_funpay.bin` | 562 B | funpay.com ClientHello (Hellcat-95, PR #16591) |
| `tls_rzd` | `tls_rzd.bin` | 658 B | www.rzd.ru ClientHello (Hellcat-95, PR #16591) |

## QUIC Initial blobs (UDP :443 fake payloads)

| Alias | File | Size | Source / note |
|---|---|---|---|
| `quic_google` | `quic_initial_www_google_com.bin` | 1200 B | www.google.com QUIC Initial (Flowseal) — базовый |
| `quic_dbank` | `quic_initial_dbankcloud_ru.bin` | 1357 B | dbankcloud.ru QUIC Initial (Flowseal) |
| `quic_4pda` | `quic_4pda.bin` | 1250 B | 4pda.to QUIC Initial (Flowseal) |
| `quic_tencent` | `quic_tencent.bin` | 1231 B | tencent.com QUIC Initial (Flowseal) |
| `quic_steam` | `quic_steam.bin` | 1200 B | steamcommunity.com QUIC Initial (Flowseal) |
| `quic_vk` | `quic_initial_vk_com.bin` | 1357 B | vk.com QUIC Initial |
| `quic_5ka` | `quic_5ka.bin` | 1250 B | **5ka.ru QUIC Initial (NEW, Flowseal 2026)** — Пятёрочка |
| `quic_rutube` | `quic_rutube.bin` | 1357 B | **rutube.ru QUIC Initial (NEW, Flowseal 2026)** — Rutube |
| `quic_funpay` | `quic_funpay.bin` | 1200 B | funpay.com QUIC Initial (Hellcat-95, PR #16591) |
| `quic_cloudflare` | `quic_cloudflare.bin` | 1200 B | www.cloudflare.com QUIC Initial (Hellcat-95, PR #16591) |
| `quic_alfabank` | `quic_alfabank.bin` | 1200 B | alfabank.ru QUIC Initial (Hellcat-95, PR #16591) |
| `quic_gv_kyber_1` | `quic_gv_kyber_1.bin` | 1230 B | googlevideo CDN QUIC + Kyber/ML-KEM key-share #1 |
| `quic_gv_kyber_2` | `quic_gv_kyber_2.bin` | 1230 B | googlevideo CDN QUIC + Kyber key-share #2 |
| `quic_gv_rr2` | `quic_gv_rr2.bin` | 1200 B | googlevideo CDN QUIC (rr2 snapshot) |
| `quic_initial` | `quic_initial.bin` | 1200 B | generic QUIC Initial (zapret2 default) |

## UDP voice / STUN blobs

| Alias | File | Size | Source / note |
|---|---|---|---|
| `discord_udp` | `discord_udp.bin` | 1200 B | Flowseal ACTIVE_DISCORD_UDP.bin — Discord voice IP-discovery/media |
| `discord_ipdisc` | `discord_ipdisc.bin` | 74 B | Discord IP-discovery-with-port (70 B discovery) |
| `game_udp` | `game_udp.bin` | 1250 B | Flowseal ACTIVE_GAME_UDP.bin — game UDP fake |
| `stun` | `stun.bin` | 100 B | STUN binding request (Flowseal) |
| `stun2` | `stun2.bin` | 120 B | STUN variant 2 (Flowseal) |

## Other

| Alias | File | Size | Source / note |
|---|---|---|---|
| `wireguard_init` | `wireguard_init.bin` | 148 B | WireGuard handshake initiation |
| `http_iana` | `http_iana.bin` | 427 B | fake HTTP GET to www.iana.org |

## New blobs (2026-08)

Added from Flowseal zapret-discord-youtube (2026 tree):
- **5ka.ru** (`tls_5ka`, `quic_5ka`) — Пятёрочка (X5 Retail), россия, часто под РКН-фильтрацией.
  Источник: [PR #16589](https://github.com/Flowseal/zapret-discord-youtube/pull/16589) (merged).
- **rutube.ru** (`quic_rutube`) — Rutube, российский видеохостинг.
- **funpay.com / www.cloudflare.com / alfabank.ru** (`quic_funpay`, `quic_cloudflare`,
  `quic_alfabank`) и **funpay.com / www.rzd.ru** (`tls_funpay`, `tls_rzd`) —
  из [PR #16591](https://github.com/Flowseal/zapret-discord-youtube/pull/16591)
  (Hellcat-95, закрыт без мержа; блобы взяты из коммита 8c35287).
