#!/usr/bin/env bash
# Run three local MPC signing nodes (Stage 1 stub — Stage 8 wires real
# mTLS clustering with attestation). Each node gets a distinct NODE_ID and
# PORT; the service is the same binary, configured via environment.
set -euo pipefail

cd "$(dirname "$0")/.."

FEATURES="${FEATURES:-in-house}"

for i in 1 2 3; do
  PORT=$((8090 + i - 1)) NODE_ID="node-$i" CUSTODY_PROVIDER="$FEATURES" \
    cargo run --release --no-default-features --features "$FEATURES" -- \
    &
  echo "started node-$i on port $PORT (pid $!)"
done

trap 'kill 0' INT TERM EXIT
wait