#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./dist/vless-audit}"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

DB="$TMP_DIR/audit.db"
PORT="18089"

"$BIN" --web-only --instance-name "Smoke Test" --db-path "$DB" --listen "127.0.0.1:$PORT" >"$TMP_DIR/out.log" 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; rm -rf "$TMP_DIR"' EXIT

for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

echo "healthz: $(curl -fsS "http://127.0.0.1:$PORT/healthz")"
curl -fsS "http://127.0.0.1:$PORT/" | grep -q "VLESS 旁路流量审计"
echo "index.html: OK"
status="$(curl -fsS "http://127.0.0.1:$PORT/api/status")"
grep -Fq '"instance_name":"Smoke Test"' <<< "$status"
echo "status: $status"
echo "overview: $(curl -fsS "http://127.0.0.1:$PORT/api/overview")"
echo "recent: $(curl -fsS "http://127.0.0.1:$PORT/api/recent")"
