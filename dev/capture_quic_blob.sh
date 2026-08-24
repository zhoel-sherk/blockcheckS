#!/usr/bin/env bash
# capture_quic_blob.sh — capture a REAL QUIC v1 Initial sent by curl_cffi
# (chosen impersonate target) into an nfqws2 UDP fake blob.
#
# Why: TSPU classifies QUIC by the Initial packet (ClientHello-in-QUIC).
# Stock blobs are old Chrome builds; a blob captured from the CURRENT
# curl_cffi fingerprint ("Electron-like": Discord desktop == Chromium stack)
# keeps the UDP-side fake indistinguishable from live browser QUIC.
#
# NOTE (Fryazino/LLC Fiord): real QUIC egress is DROPPED by the ISP — curl
# reports http_version "3" but zero UDP:443 hits the wire (verified 2026-08-25).
# To capture a genuine Initial here, run this script ON the Selectel VPS
# (clean QUIC path) and copy the blob back:
#   ssh root@111.88.227.92 'apt/pip install curl_cffi' then run with target=chrome
#   scp root@111.88.227.92:blobs/quic_initial_chrome.bin blobs/
#
# Host-mode by design (no netns): high-level curl_cffi + impersonate need a
# working resolver, and in-netns UDP:53 is silent on some ISPs. The target
# host is pinned via a temporary /etc/hosts entry (reverted on exit).
#
# Usage:
#   sudo -E ./dev/capture_quic_blob.sh [target] [url] [out_blob] [ip]
#     target:   curl_cffi impersonate preset (default: chrome = latest)
#     url:      HTTPS origin triggering QUIC (default: https://discord.gg/)
#               Must be a domain where HTTP/3 passes your DPI (discord.gg /
#               discordcdn.com confirmed; forced QUIC-only drops on Fryazino,
#               so we rely on auto alt-svc negotiation).
#     out_blob: output path (default: blobs/quic_initial_<target>.bin)
#     ip:       optional explicit pin (default: known Cloudflare pins)

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TARGET="${1:-chrome}"
URL="${2:-https://discord.gg/}"
OUT="${3:-blobs/quic_initial_${TARGET}.bin}"
HOSTNAME_PART=$(echo "$URL" | sed -E 's#https?://([^/]+)/.*#\1#')

case "$HOSTNAME_PART" in
  discord.gg)     DEF_IP="162.159.135.234" ;;
  discordcdn.com) DEF_IP="162.159.138.233" ;;
  discord.com)    DEF_IP="162.159.128.233" ;;
  *)              DEF_IP="" ;;
esac
IP="${4:-$DEF_IP}"
if [ -z "$IP" ]; then
  IP=$(python3 -c "import socket;print(socket.gethostbyname('$HOSTNAME_PART'))")
fi

IF_OUT=$(ip -br link | awk '$2=="UP" && $1!~/^(lo|vh-|vn-|veth|br-|docker)/{print $1; exit}')
PCAP=$(mktemp /tmp/quic_cap_XXXX.pcap)
HOSTS_TMP=$(mktemp)

cleanup() {
  sudo cp "$HOSTS_TMP" /etc/hosts 2>/dev/null || true
  rm -f "$HOSTS_TMP" "$PCAP"
}
trap cleanup EXIT
sudo cp /etc/hosts "$HOSTS_TMP"

echo "=== pin $HOSTNAME_PART -> $IP (temporary /etc/hosts), iface=$IF_OUT"
echo "$IP $HOSTNAME_PART" | sudo tee -a /etc/hosts > /dev/null

echo "=== tcpdump udp:443 host $IP (max 14s)"
sudo timeout 14 tcpdump -i any -U -w "$PCAP" -c 16 \
  "udp port 443 and host $IP" > /tmp/quic_tcpdump.log 2>&1 &
TCPD=$!
sleep 0.5

echo "=== probe: curl_cffi impersonate=$TARGET -> $URL"
set +e
sudo -n -E env BLOCKCHECKS_IMPERSONATE="$TARGET" HOME="${HOME:-/home/zhoel}" \
  timeout 10 "$ROOT/.venv/bin/python" - << PYEOF
from curl_cffi import requests as r
try:
    resp = r.get("$URL", impersonate="$TARGET", timeout=6, allow_redirects=False)
    print("probe:", resp.status_code, getattr(resp, "http_version", "?"))
except Exception as e:
    # The outgoing Initial is already on the wire even if the flow is killed.
    print("probe err (Initial may be captured anyway):", str(e)[:90])
PYEOF
set -e
wait $TCPD 2>/dev/null || true
tail -3 /tmp/quic_tcpdump.log || true

echo "=== extract first QUIC v1 Initial -> $OUT"
sudo -E "$ROOT/.venv/bin/python" - "$PCAP" "$OUT" << 'PYEOF'
import struct, sys

def varint(buf, off):
    b = buf[off]; ln = 1 << (b >> 6)
    val = b & 0x3F
    for i in range(1, ln):
        val = (val << 8) | buf[off + i]
    return val, off + ln

pcap_path, out_path = sys.argv[1], sys.argv[2]
data = open(pcap_path, "rb").read()
endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
ts_len = 16
off = 24
found = False
while off + ts_len <= len(data):
    caplen = struct.unpack_from(endian + "I", data, off + 8)[0]
    pkt = data[off + ts_len : off + ts_len + caplen]
    off += ts_len + caplen
    eth = 14
    if len(pkt) < eth + 40:
        continue
    if pkt[12:14] == b"\x81\x00":
        eth = 18
    ip_off = eth
    if pkt[ip_off] >> 4 != 4:
        continue
    ihl = (pkt[ip_off] & 0x0F) * 4
    if pkt[ip_off + 9] != 17:
        continue
    payload = pkt[ip_off + ihl + 8 :]
    if len(payload) < 30:
        continue
    flags = payload[0]
    version = struct.unpack_from(">I", payload, 1)[0]
    if (flags & 0xC0) != 0xC0 or version != 1:
        continue
    p = 5
    dcil = payload[p]; p += 1 + dcil
    scil = payload[p]; p += 1 + scil
    token_len, p = varint(payload, p); p += token_len
    plen, p = varint(payload, p)
    if p + plen > len(payload):
        plen = len(payload) - p
    initial = payload[: p + plen]
    open(out_path, "wb").write(initial)
    print(f"saved {len(initial)}B Initial (flags=0x{flags:02x}) -> {out_path}")
    found = True
    break
if not found:
    sys.exit("ERROR: no QUIC v1 Initial in pcap — QUIC likely dropped for this URL/IP")
PYEOF

sudo chown "${SUDO_USER:-zhoel}":"${SUDO_USER:-zhoel}" "$OUT" 2>/dev/null || true
echo "=== done: $OUT ($(stat -c%s "$OUT") bytes)"
echo "Wire it up: copy blob + strategy line like:"
echo "  fake:blob=quic_initial_${TARGET}:repeats=1  (--udp, q201 side)"
