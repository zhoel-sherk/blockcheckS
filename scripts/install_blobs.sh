#!/usr/bin/env bash
# Optional: sync extra / host-local blobs into BLOCKCHECKS_BLOBS (default /opt/zapret2/blobs).
# Core Flowseal blobs are baked in-repo under blobs/ — no download required for bs scan --tcp-sources flowseal.
# Sources: Flowseal GitHub (bin/), zapret2 files/fake/, local cache
set -euo pipefail

BLOBS="${BLOCKCHECKS_BLOBS:-/opt/zapret2/blobs}"
FAKE="${BLOCKCHECKS_FAKE_FILES:-/opt/zapret2/files/fake}"
CACHE="${BLOCKCHECKS_BLOB_CACHE:-${XDG_CACHE_HOME:-$HOME/.cache}/blockcheckS/blob-cache}"
FLOWSEAL_BASE="${FLOWSEAL_BLOB_URL:-https://raw.githubusercontent.com/Flowseal/zapret-discord-youtube/main/bin}"
REPO_BLOBS="$(cd "$(dirname "$0")/.." && pwd)/blobs"

echo "NOTE: repo blobs/ is preferred at runtime; this script only fills $BLOBS extras."
if [[ -d "$REPO_BLOBS" ]]; then
  echo "NOTE: baked set: $(ls -1 "$REPO_BLOBS"/*.bin 2>/dev/null | wc -l) files in $REPO_BLOBS"
fi

mkdir -p "$CACHE"

if [[ ! -d "$BLOBS" ]]; then
  echo "ERROR: blobs dir missing: $BLOBS" >&2
  exit 1
fi

link_blob() {
  local alias="$1"
  local src="$2"
  if [[ ! -f "$src" ]]; then
    echo "SKIP $alias — source not found: $src"
    return 0
  fi
  sudo ln -sf "$src" "$BLOBS/${alias}.bin"
  echo "OK   $alias -> $src"
}

fetch_flowseal() {
  local fname="$1"
  local dest="$CACHE/$fname"
  if [[ -f "$dest" ]] && [[ "$(stat -c%s "$dest")" -gt 20 ]]; then
    echo "CACHE $fname"
    return 0
  fi
  local code
  code=$(curl -fsSL -o "$dest" -w "%{http_code}" "$FLOWSEAL_BASE/$fname" --max-time 30 || echo "000")
  if [[ "$code" != "200" ]]; then
    echo "FAIL fetch $fname HTTP $code" >&2
    rm -f "$dest"
    return 1
  fi
  echo "FETCH $fname ($(stat -c%s "$dest") bytes)"
}

echo "=== install_blobs -> $BLOBS ==="
echo "--- Flowseal downloads ---"
for f in \
  ACTIVE_GAME_UDP.bin \
  ACTIVE_DISCORD_UDP.bin \
  stun2.bin \
  quic_initial_4pda.to.bin \
  quic_initial_tencent_com.bin \
  quic_initial_steamcommunity_com.bin \
  ; do
  fetch_flowseal "$f" || true
done

echo "--- symlinks ---"
# GV kyber (stock zapret2)
link_blob quic_gv_kyber_1 \
  "$FAKE/quic_initial_rr1---sn-xguxaxjvh-n8me_googlevideo_com_kyber_1.bin"
link_blob quic_gv_kyber_2 \
  "$FAKE/quic_initial_rr1---sn-xguxaxjvh-n8me_googlevideo_com_kyber_2.bin"
link_blob quic_gv_rr2 \
  "$FAKE/quic_initial_rr2---sn-gvnuxaxjvh-o8ge_googlevideo_com.bin"

# VK (stock)
link_blob tls_clienthello_vk_com "$FAKE/tls_clienthello_vk_com.bin"
link_blob quic_initial_vk_com "$FAKE/quic_initial_vk_com.bin"

# Flowseal tier-1
link_blob game_udp "$CACHE/ACTIVE_GAME_UDP.bin"
link_blob stun2 "$CACHE/stun2.bin"
link_blob quic_4pda "$CACHE/quic_initial_4pda.to.bin"
link_blob quic_tencent "$CACHE/quic_initial_tencent_com.bin"
link_blob quic_steam "$CACHE/quic_initial_steamcommunity_com.bin"

# Optional: compare discord_ipdisc vs discord_udp
link_blob discord_ipdisc "$FAKE/discord-ip-discovery-with-port.bin"
link_blob wireguard_init "$FAKE/wireguard_initiation.bin"
link_blob http_iana "$FAKE/http_iana_org.bin"

# Short aliases (BLOB-3)
[[ -f "$BLOBS/tls_clienthello_vk_com.bin" ]] && link_blob tls_vk "$BLOBS/tls_clienthello_vk_com.bin"
[[ -f "$BLOBS/quic_initial_vk_com.bin" ]] && link_blob quic_vk "$BLOBS/quic_initial_vk_com.bin"
[[ -f "$CACHE/ACTIVE_DISCORD_UDP.bin" ]] && \
  [[ ! -f "$BLOBS/discord_udp.bin" || "$(stat -c%s "$BLOBS/discord_udp.bin")" -lt 100 ]] && \
  link_blob discord_udp "$CACHE/ACTIVE_DISCORD_UDP.bin"

echo "--- verify ---"
PYTHONPATH="$(cd "$(dirname "$0")/.." && pwd)/src" \
  python3 "$(dirname "$0")/verify_blobs.py" || true

ls -la "$BLOBS"/*.bin 2>/dev/null | wc -l | xargs echo "total blobs:"
