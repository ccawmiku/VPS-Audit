#!/usr/bin/env bash
set -euo pipefail

BIN_SRC="${1:-./vless-audit}"
UNIT_SRC="${2:-./vless-audit.service}"

if [[ ! -f "$BIN_SRC" ]]; then
  echo "Binary not found: $BIN_SRC" >&2
  exit 1
fi

if ! id -u vless-audit >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin vless-audit
fi

install -m 0755 "$BIN_SRC" /usr/local/bin/vless-audit
install -m 0644 "$UNIT_SRC" /etc/systemd/system/vless-audit.service

systemctl daemon-reload
systemctl enable --now vless-audit.service
systemctl status --no-pager vless-audit.service

sleep 1
curl -fsS http://127.0.0.1:18080/healthz && echo ""
echo "Installed and running on 127.0.0.1:18080"
