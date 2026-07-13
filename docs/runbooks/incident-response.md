# Runbook — Incident Response (Suspected Compromise)

## Trigger
Suspected compromise of a node, share, custody credential, or an anomalous
audit record (e.g. a signature with no matching approved policy decision).

## Immediate actions (first 15 minutes)
1. **Contain**: pause signing — remove the suspect node from the quorum
   (`set_online` false in dev; drain/cordon in prod) so it cannot contribute.
2. If a caller credential is suspect, revoke its policy-token issuing key at the
   Policy / Risk Engine (all in-flight tokens are single-use and short-lived).
3. Preserve evidence: snapshot audit records from the Audit / Event Log for the
   affected `key_id` / window. Records are node-signed and tamper-evident.

## Assess
- Cross-check every `SignTx` in the window against approved policy decisions.
- Verify each audit record's node signatures (`SigningAuditRecord::verify`).
- Determine how many nodes/shares are affected. Fewer than `t` compromised
  shares cannot have produced a signature alone.

## Recover
1. Rotate keys (proactive refresh) to invalidate all existing shares.
2. If `>= t` shares may be compromised, treat the key as exposed: migrate funds
   to a freshly DKG'd key and retire the old `key_id`.
3. Re-attest and restore any rebuilt nodes.

## Post-incident
- File a timeline and root cause; add detections.
- If the cause is a code/protocol flaw, open a Critical issue and block releases
  until remediated.
