#!/usr/bin/env bash
set -euo pipefail

BIN_SRC="${1:-./vless-audit}"
UNIT_SRC="${2:-./vless-audit.service}"
LISTEN_ADDRESS="${3:-127.0.0.1:18080}"

if [[ ! -x "$BIN_SRC" || ! -f "$UNIT_SRC" ]]; then
  echo "An executable binary and a service unit are required: $BIN_SRC, $UNIT_SRC" >&2
  exit 1
fi

if ! id -u vless-audit >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin vless-audit
fi

install -m 0755 "$BIN_SRC" /usr/local/bin/vless-audit.new
mv -fT /usr/local/bin/vless-audit.new /usr/local/bin/vless-audit
install -m 0644 "$UNIT_SRC" /etc/systemd/system/vless-audit.service

systemctl daemon-reload
systemctl enable vless-audit.service
systemctl restart vless-audit.service

for _ in $(seq 1 30); do
  if curl -fsS --max-time 2 "http://$LISTEN_ADDRESS/healthz" >/dev/null 2>&1; then
    echo "Installed and running on $LISTEN_ADDRESS"
    exit 0
  fi
  sleep 0.2
done

systemctl status --no-pager vless-audit.service >&2
exit 1
