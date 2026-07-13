#!/usr/bin/env bash
# Generate an ephemeral internal PKI for the local mTLS cluster: a CA plus a
# cert/key per node (SAN localhost + the compose service name). DEV ONLY —
# production issues short-lived certs from the internal PKI, not this script.
set -euo pipefail

OUT="${1:-./certs}"
NODES="${NODES:-node1 node2 node3}"
DAYS="${DAYS:-3650}"

mkdir -p "$OUT"
cd "$OUT"

if [[ ! -f ca.key ]]; then
  echo "==> generating CA"
  openssl genrsa -out ca.key 4096 2>/dev/null
  openssl req -x509 -new -nodes -key ca.key -sha256 -days "$DAYS" \
    -subj "/CN=mpc-signing-internal-ca" -out ca.crt 2>/dev/null
fi

for node in $NODES; do
  echo "==> issuing cert for $node"
  openssl genrsa -out "$node.key" 2048 2>/dev/null
  openssl req -new -key "$node.key" -subj "/CN=$node" -out "$node.csr" 2>/dev/null
  cat > "$node.ext" <<EOF
subjectAltName = DNS:localhost, DNS:$node, DNS:mpc-signing-service, IP:127.0.0.1
extendedKeyUsage = serverAuth, clientAuth
EOF
  openssl x509 -req -in "$node.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$node.crt" -days "$DAYS" -sha256 -extfile "$node.ext" 2>/dev/null
  rm -f "$node.csr" "$node.ext"
done

echo "==> PKI written to $OUT (ca.crt + per-node .crt/.key)"
