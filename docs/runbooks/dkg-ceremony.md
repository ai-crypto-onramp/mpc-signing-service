# Runbook — DKG Ceremony

Generate a new threshold key across the cluster. DKG requires **full
membership** (all `n` nodes online and attested).

## Preconditions
- All `n` nodes healthy (`/healthz` 200) and attested at join.
- mTLS PKI current (`make mtls` for local; internal PKI in prod).
- Change ticket approved.

## Procedure
1. Confirm all nodes online:
   ```sh
   for p in 8091 8092 8093; do curl -sf localhost:$p/healthz; echo; done
   ```
2. Invoke DKG for the target chain (gRPC `Dkg`, e.g. via grpcurl over mTLS):
   ```sh
   grpcurl -cacert certs/ca.crt -cert certs/node1.crt -key certs/node1.key \
     -d '{"chain":"CHAIN_EVM","threshold":2,"parties":3}' \
     localhost:9091 mpc.v1.MpcSigningService/Dkg
   ```
3. Record the returned `key_id` and `public_key`.
4. Register the key with Wallet Management so the on-chain address is bound.
5. Verify: `GetKeyMetadata` returns the same public key on every node.

## Rollback
DKG produces a fresh `key_id`; abandon it (do not fund the address). No effect
on existing keys.

## Failure modes
- `QuorumNotMet` → a node is down/unattested; restore full membership first.
