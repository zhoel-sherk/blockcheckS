#!/usr/bin/env bash
# Install blockcheckS systemd units:
#   blockcheck-series.service — boot-resume of the long-term run series
#   blockcheck-serve.service  — resident on-the-fly probe server
# Run with sudo. Safe to re-run (idempotent).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Prefer the invoking user's real home; when run via sudo $HOME is /root.
_HOME="$HOME"
_USER="${USER:-root}"
if [ "$HOME" = "/root" ] && [ -n "${SUDO_USER:-}" ]; then
  _HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  _USER="$SUDO_USER"
fi

install_unit() {
  local src="$1" dst="$2"
  if [ ! -f "$src" ]; then
    echo "missing $src" >&2
    exit 1
  fi
  sed -e "s|@ROOT@|$ROOT|g" -e "s|@HOME@|$_HOME|g" -e "s|@USER@|$_USER|g" "$src" > "$dst"
  chmod 644 "$dst"
  echo "installed $(basename "$dst")"
}

install_unit "$ROOT/systemd/blockcheck-series.service" \
  /etc/systemd/system/blockcheck-series.service
install_unit "$ROOT/systemd/blockcheck-serve.service" \
  /etc/systemd/system/blockcheck-serve.service

systemctl daemon-reload
systemctl enable blockcheck-series.service 2>&1 | tail -1
systemctl enable blockcheck-serve.service 2>&1 | tail -1
echo "done"
