# Runbook — Key Rotation (Proactive Share Refresh)

Refresh key shares without changing the public key / on-chain address (CMP20
refresh). Requires **full membership**.

## When
- Scheduled cadence (e.g. every 90 days).
- On suspicion that up to `t-1` shares may be exposed (rotate immediately).

## Procedure
1. Confirm all `n` nodes online and attested.
2. Invoke `RotateKey` for the `key_id` (gRPC over mTLS):
   ```sh
   grpcurl -cacert certs/ca.crt -cert certs/node1.crt -key certs/node1.key \
     -d '{"key_id":"<KEY_ID>"}' \
     localhost:9091 mpc.v1.MpcSigningService/RotateKey
   ```
3. Assert the response `public_key` is **unchanged** and `epoch` incremented.
4. Sign a canary payload and verify it against the (unchanged) public key.

## Rollback
Old shares are invalidated by the refresh. If a node missed the refresh it will
fail to contribute — re-run rotation with full membership; do not revert.

## Failure modes
- `QuorumNotMet` → restore full membership, then re-run.
- Public key changed → **stop, page on-call**: indicates a protocol fault.
