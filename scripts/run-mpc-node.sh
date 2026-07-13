#!/usr/bin/env bash
# Run one local MPC node. Reads NODE_ID / PORT / GRPC_PORT / THRESHOLD_T /
# TOTAL_N / CUSTODY_PROVIDER (and MTLS_* if present) from the environment.
#
# Each process runs an in-process t-of-n cluster (the local placeholder for a
# real multi-host deployment); NODE_ID / MTLS_* distinguish nodes when the
# threshold protocol is wired across hosts.
set -euo pipefail

: "${NODE_ID:=node1}"
: "${CUSTODY_PROVIDER:=in_house}"
: "${THRESHOLD_T:=2}"
: "${TOTAL_N:=3}"

export NODE_ID CUSTODY_PROVIDER THRESHOLD_T TOTAL_N

BIN="${MPC_BIN:-./target/release/mpc-signing-service}"
if [[ ! -x "$BIN" ]]; then
  echo "building release binary (set MPC_BIN to skip)…"
  cargo build --release
  BIN="./target/release/mpc-signing-service"
fi

echo "starting $NODE_ID (provider=$CUSTODY_PROVIDER t=$THRESHOLD_T n=$TOTAL_N)"
exec "$BIN"
