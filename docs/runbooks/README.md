# Runbooks — MPC Signing Service

Operational procedures for the signing cluster. These are dev/staging drills
today; production versions gate on the HSM and cross-host threshold work
tracked in `PROJECT_PLAN.md`.

- [DKG ceremony](dkg-ceremony.md) — generate a new threshold key
- [Key rotation](key-rotation.md) — proactive share refresh
- [Node restore](node-restore.md) — recover a lost node's share
- [Incident response](incident-response.md) — suspected compromise
- Recovery drill cadence: run the node-restore drill on staging **quarterly**
  and after any node-hardware change.
