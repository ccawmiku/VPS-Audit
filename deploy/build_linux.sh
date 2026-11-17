#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"
PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/vless-audit-target}"

cargo test
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-feature=+crt-static" \
  cargo build --release --target x86_64-unknown-linux-gnu

mkdir -p dist
cp "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/vless-audit" dist/vless-audit
chmod +x dist/vless-audit

file dist/vless-audit || true
ldd dist/vless-audit || true
ls -lh dist/vless-audit
sha256sum dist/vless-audit
