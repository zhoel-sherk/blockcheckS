#!/usr/bin/env bash
# Remove blockcheckS systemd units. Run with sudo.
set -euo pipefail

systemctl disable blockcheck-series.service 2>/dev/null || true
rm -f /etc/systemd/system/blockcheck-series.service
systemctl daemon-reload
echo "removed blockcheck-series.service"
