# Runbook — Node Restore

Recover a node whose key share was lost (disk failure, re-provision). Signing
continues on the remaining `>= t` nodes throughout.

## Procedure
1. Provision the replacement node; attest it at join (measurement + HSM identity
   bound to its new mTLS key).
2. Restore its share from the sealed backup, presenting a **quorum proof**:
   ```sh
   grpcurl -cacert certs/ca.crt -cert certs/nodeX.crt -key certs/nodeX.key \
     -d '{"key_id":"<KEY_ID>","node_id":"<NODE_ID>","quorum_proof":"<PROOF>"}' \
     localhost:909X mpc.v1.MpcSigningService/RestoreShare
   ```
3. Confirm the node reports the key via `GetKeyMetadata` with the correct epoch.
4. Run a canary sign that includes the restored node in the quorum.
5. Rotate keys (see key-rotation) so the restored node's share is refreshed.

## Notes
- Restore is refused without a valid quorum proof and is itself audited.
- If backup integrity fails, do not proceed — escalate to incident response.
