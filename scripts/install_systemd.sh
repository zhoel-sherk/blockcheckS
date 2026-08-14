#!/usr/bin/env bash
# Install blockcheckS systemd units (boot-resume series + optional on-the-fly
# probe service). Run with sudo. Safe to re-run (idempotent).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

SERVICE_SRC="$ROOT/systemd/blockcheck-series.service"
UNIT_DST="/etc/systemd/system/blockcheck-series.service"

if [ ! -f "$SERVICE_SRC" ]; then
  echo "missing $SERVICE_SRC" >&2
  exit 1
fi

# Render unit with actual ROOT/HOME (unit uses placeholders @ROOT@ / @HOME@).
# Prefer the invoking user's real home; when run via sudo $HOME is /root, so
# fall back to the sudoers user home if the file doesn't exist under $HOME.
_HOME="$HOME"
if [ "$HOME" = "/root" ] && [ -n "${SUDO_USER:-}" ]; then
  _HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
fi
sed -e "s|@ROOT@|$ROOT|g" -e "s|@HOME@|$_HOME|g" "$SERVICE_SRC" > "$UNIT_DST"
chmod 644 "$UNIT_DST"

systemctl daemon-reload
systemctl enable blockcheck-series.service 2>&1 | tail -2
echo "installed blockcheck-series.service (boot-resume on next boot if DB present)"
