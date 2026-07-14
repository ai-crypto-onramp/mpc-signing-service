# MPC Signing Service

![CI](https://github.com/ai-crypto-onramp/mpc-signing-service/actions/workflows/ci.yml/badge.svg)
[![codecov](https://codecov.io/gh/ai-crypto-onramp/mpc-signing-service/branch/main/graph/badge.svg)](https://codecov.io/gh/ai-crypto-onramp/mpc-signing-service)

Threshold-signature (t-of-n) signing across distributed nodes — no single key, the most security-critical component of the crypto on-ramp.

## Overview / Responsibilities

The MPC Signing Service performs threshold signature generation in a distributed
manner such that no single node ever holds a complete private key. A compromise of
up to `t-1` nodes does not expose the key, and the service remains available as
long as at least `t` of `n` nodes participate.

Responsibilities:

- Threshold (t-of-n) signature generation for approved transactions
- Distributed Key Generation (DKG) ceremonies across peer nodes
- Key share rotation (proactive resharing) without changing the on-chain address
- Per-chain signing algorithms: ECDSA for EVM chains, EdDSA for Solana and others
- Policy-gated signing — only sign payloads carrying a valid `policy_decision_token`
  issued by the Policy / Risk Engine
- Signing audit trail — every signing session emits a signed audit record to the
  Audit / Event Log
- Multi-party node coordination via secure inter-node channels
- Key share backup / restore for disaster recovery (encrypted, HSM-bound)

This service is called by the **Transaction Orchestrator** (synchronous request on
the transaction path), calls **Wallet Management** to resolve address/key mappings,
and emits audit events asynchronously to the **Audit / Event Log**.

## Language & Tech Stack

- **Language:** Rust (memory safety is non-negotiable for funds-handling code)
- **MPC protocols:** GG20 / CGGMP / CMP20 (the CGGMP family is the current baseline;
  CMP20 for refreshable keys)
- **Key shares:** HSM-backed; shares are generated, stored, and used inside secure
  enclaves and never materialized in host process memory in cleartext
- **Secure enclaves:** AWS Nitro Enclaves / SGX / equivalent for share computation,
  with attestation at node join
- **Inter-node transport:** mutually-authenticated TLS (mTLS) between signing nodes;
  point-to-point encrypted channels for MPC protocol messages
- **Cryptographic primitives:** audited Rust crates (`curve25519-dalek`,
  `k256`/`ecdsa`, `rand`), HSM PKCS#11 interface, hardware RNG where available

## System Requirements

1. **Threshold t-of-n signature generation** — produce a valid ECDSA / EdDSA
   signature over a transaction payload when at least `t` of `n` nodes participate.
   The signature must be indistinguishable from one produced by a single key.

2. **Distributed Key Generation ceremony** — generate key material jointly across
   `n` nodes with no dealer and no single node ever holding the full key. Output is
   a public key (used to derive the on-chain address) and per-node private shares.

3. **Key share rotation** — proactively refresh shares (CMP20 refresh) on a schedule
   and on-demand, producing a new set of shares for the same public key, without a
   trusted dealer and without changing the on-chain address.

4. **Per-chain signing** — support the signing algorithms required by supported
   chains:
   - ECDSA over secp256k1 for EVM chains (Ethereum, Polygon, Arbitrum, Base, …)
   - EdDSA over Ed25519 for Solana, Aptos, Sui, …
   - Extensible signing-provider interface for additional curves / schemes.

5. **Policy-gated signing** — refuse to sign any transaction that does not carry a
   valid `policy_decision_token` from the Policy / Risk Engine. The token binds the
   signature to a specific `tx_payload`, `key_id`, and `chain`, and is single-use.

6. **Signing audit trail** — every signing session (successful or rejected) emits
   a signed, append-only audit record to the Audit / Event Log containing the
   request, participants, signature, and result.

7. **Multi-party node coordination** — orchestrate the MPC rounds (pre-signature,
   sign) across geographically and infrastructurally diverse nodes with reliable
   point-to-point messaging, timeouts, and quorum tracking.

8. **Key share backup / restore** — back up encrypted key shares to a sealed store
   (HSM-backed) to allow recovery of a failed node without re-running DKG;
   restoration requires quorum approval.

## Non-Functional Requirements

- **Sign latency:** p99 < 2s end-to-end (orchestrator request → signature returned),
  including MPC rounds and HSM operations.
- **No single point of compromise:** compromise of any `t-1` nodes must not reveal
   the private key or permit unauthorized signing.
- **Key share confinement:** key shares never leave the secure enclave in cleartext
  — not to logs, not to memory snapshots, not to backups (backups are encrypted with
  HSM-resident wrapping keys).
- **Availability:** 99.99% uptime with graceful degradation as long as `t` of `n`
  nodes are reachable. Loss of `n - t` nodes must not affect signing.
- **Side-channel resistance:** constant-time cryptographic operations, no
  data-dependent branching on secrets, enclave-mediated memory access, periodic
  share refresh to limit window of exposure.
- **Determinism & replay safety:** signatures are bound to a specific `tx_payload`
  via the policy token; replaying a stale request is rejected.
- **Auditability:** 100% of signing attempts (including denials) recorded with
  tamper-evident signatures.

## Technical Specifications

### API Surface

Internal **gRPC** service with **mTLS**. Not exposed to the public edge; reachable
only from the Transaction Orchestrator and other internal control-plane callers.
Node-to-node MPC traffic runs over a separate mTLS channel.

### Endpoints

| RPC | Request | Response |
|---|---|---|
| `SignTx` | `{ tx_payload: bytes, policy_decision_token: string, key_id: string, chain: enum }` | `{ signature: bytes, signing_session_id: string, participant_ids: repeated string, audit_record_hash: string }` |
| `DKG` | `{ participant_ids: repeated string, threshold: uint32 }` | `{ key_id: string, public_key: bytes, chain: enum, address: string }` |
| `RotateKey` | `{ key_id: string, participant_ids: repeated string }` | `{ rotation_id: string, completed_at: timestamp }` |
| `GetKeyMetadata` | `{ key_id: string }` | `{ public_key: bytes, chain: enum, address: string, threshold: uint32, total: uint32, last_rotated_at: timestamp, status: enum }` |
| `RestoreShare` | `{ key_id: string, node_id: string, quorum_proof: bytes }` | `{ restored: bool, attestation: bytes }` |

`SignTx` is the hot path; `DKG`, `RotateKey`, `RestoreShare` are control-plane
operations requiring elevated authz.

### Data Model

- `key_shares` — per-node encrypted key shares, wrapped by HSM-resident keys;
  stores `key_id`, `node_id`, `chain`, `wrapped_share`, `public_key`, `threshold`,
  `total`, `created_at`, `last_rotated_at`. Cleartext shares never persisted.
- `signing_sessions` — in-flight and completed MPC signing sessions; stores
  `signing_session_id`, `key_id`, `tx_payload_hash`, `policy_decision_token`,
  `participant_ids`, `status`, `started_at`, `completed_at`.
- `signing_audit_records` — tamper-evident record per signing attempt; stores
  `audit_record_id`, `signing_session_id`, `request`, `participants`, `result`,
  `signature` (or denial reason), `node_signatures` (record signed by each
  participant node), `created_at`. Streamed to the Audit / Event Log.

### Security

- **Enclave-bound shares:** key shares live only inside secure enclaves / HSMs;
  the host process sees only opaque ciphertext and signatures.
- **Policy token binding:** `SignTx` validates the `policy_decision_token`
  (signature, freshness, single-use, payload hash match) before initiating MPC
  rounds; mismatched or replayed tokens are rejected and audited.
- **Signed audit records:** each signing session produces a record signed by all
  participant nodes; records are streamed to Audit / Event Log and retained
  immutably.
- **mTLS:** all client and inter-node traffic uses mutually-verified TLS with
  short-lived certs issued by the internal PKI; no plaintext RPC.
- **Attestation:** nodes present hardware attestation (Nitro / SGX quote) at join
  time; the cluster rejects nodes whose attestation doc does not match the
  expected measurement and whose HSM is not on the approved list.

### Integrations

| Direction | Counterpart | Protocol | Purpose |
|---|---|---|---|
| Consumed by | Transaction Orchestrator | gRPC (sync) | `SignTx` on the transaction saga path |
| Calls | Wallet Management | gRPC (sync) | Resolve `key_id` → address / derivation path |
| Emits to | Audit / Event Log | Event bus (async) | Signed signing-audit records |
| Peers with | Other MPC Signing nodes | mTLS (sync) | MPC protocol rounds (DKG, sign, rotate) |

### v1 Integration Path

Per the architecture recommendation, **in-house MPC custody is ~$5–10M and
18–24 months**. For v1 we **integrate a custody provider** (Fireblocks / Dfns /
Turnkey) behind our own Wallet Management + Policy interfaces rather than building
threshold signing in-house.

- The MPC Signing Service exposes its standard gRPC surface to the Transaction
  Orchestrator and Wallet Management.
- Internally, when `CUSTODY_PROVIDER` is set, signing requests are routed through
  the configured provider's SDK / API (Fireblocks API, Dfns API, Turnkey API) under
  our own policy and audit wrappers.
- The custody-provider adapter implements the same internal trait as the in-house
  MPC engine, preserving a **clean boundary** so we can replace it with an
  in-house implementation later without changing callers.
- Policy gating, audit emission, and Wallet Mgmt integration are enforced by us
  regardless of whether signing is delegated to the custody provider or performed
  in-house.

## Dependencies

- **HSM / secure enclave** — PKCS#11 HSM and/or Nitro/SGX enclave for share storage
  and signing operations.
- **Secure inter-node communication** — mTLS-protected gRPC/HTTP2 channels between
  signing nodes, with mutual cert verification and certificate rotation.
- **Audit / Event Log** — append-only consumer of signing audit records.
- **Wallet Management** — source of truth for `key_id` ↔ address / derivation
  path mapping and wallet state.
- **Internal PKI** — issues short-lived mTLS certificates to nodes and clients.
- **Policy / Risk Engine** — issuer of `policy_decision_token`s consumed by
  `SignTx`.

## Configuration

All configuration is via environment variables (12-factor). Secrets are sourced
from the platform secret manager, not the environment, in production.

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | yes | — | gRPC listen port for the service |
| `NODE_ID` | yes | — | Unique identifier for this signing node |
| `PEER_NODES` | yes | — | Comma-separated `host:port` list of peer MPC nodes |
| `THRESHOLD_T` | yes | — | Minimum number of shares required to sign (`t`) |
| `TOTAL_N` | yes | — | Total number of key shares / nodes (`n`) |
| `KEY_SHARE_STORE_URL` | yes | — | URL of the sealed/encrypted key share backup store |
| `HSM_SLOT` | yes | — | PKCS#11 HSM slot label holding wrapping/signing keys |
| `HSM_PIN` | (secret) | — | HSM login PIN; sourced from secret manager in prod |
| `MTLS_CERT` | yes | — | Path to this node's mTLS certificate (PEM) |
| `MTLS_KEY` | yes | — | Path to this node's mTLS private key (PEM) |
| `MTLS_CA` | yes | — | Path to internal PKI CA bundle (PEM) for verifying peers/clients |
| `POLICY_ENGINE_URL` | yes | — | gRPC URL of the Policy / Risk Engine for token validation |
| `WALLET_MANAGEMENT_URL` | yes | — | gRPC URL of Wallet Management service |
| `AUDIT_EVENT_LOG_URL` | yes | — | gRPC / event bus URL for emitting audit records |
| `CUSTODY_PROVIDER` | no | `in_house` | v1 mode: `fireblocks` \| `dfns` \| `turnkey` \| `in_house` |
| `CUSTODY_API_URL` | if custody | — | Base API URL of the configured custody provider |
| `CUSTODY_API_KEY` | (secret) | — | API key / JWT signer key for the custody provider |
| `CUSTODY_WEBHOOK_SECRET` | (secret) | — | Secret for verifying inbound custody webhooks |
| `SIGN_TIMEOUT_MS` | no | `5000` | Per-MPC-round timeout; the p99 end-to-end target is < 2s |
| `ROTATION_INTERVAL_HOURS` | no | `168` | Proactive key share rotation cadence (default 1 week) |
| `ATTESTATION_REQUIRED` | no | `true` | Reject nodes that fail enclave/HSM attestation at join |
| `LOG_LEVEL` | no | `info` | `error` \| `warn` \| `info` \| `debug` |
| `RUST_LOG` | no | `info` | tracing-subscriber filter for crate-level log control |

## Implementation Status

Stages 1–6 of `PROJECT_PLAN.md` (the v1-shippable path) are implemented:

- **gRPC surface** (`proto/mpc_signing.proto`, tonic + prost): `SignTx`, `Dkg`,
  `RotateKey`, `GetKeyMetadata`, `RestoreShare`. HTTP serves `/healthz` and the
  HMAC-verified `/v1/custody/webhook`.
- **Policy gating** (Stage 3): `SignTx` refuses to sign without a valid
  `policy_decision_token` — an Ed25519-signed claims blob bound to
  `sha256(tx_payload)`, `key_id`, and `chain`, checked for freshness and single
  use. All five failure modes produce distinct audited denial reasons.
- **Wallet Management integration** (Stage 4): `wallet_id → key_id` binding is
  cross-checked before signing via wallet-management's JSON-codec gRPC
  (`/wallet.WalletService/ResolveKeyID`); the sign path fails closed on outage.
- **`SigningEngine` boundary** (Stage 5): all RPC handlers dispatch through the
  trait; `CUSTODY_PROVIDER` selects the backend with no handler changes.
- **Custody adapters** (Stage 6): Fireblocks / Dfns / Turnkey behind feature
  flags, sharing an HTTP core that locally verifies every provider-returned
  signature before trusting it (ECDSA secp256k1 + Ed25519 `verify_strict`).
- **Signed audit records** (Stage 9, partial): every signing attempt — signed,
  denied, or failed — emits a record signed by the node's Ed25519 identity key,
  delivered asynchronously with retries to `AUDIT_EVENT_LOG_URL`.

Stages 7–10 (the in-house engine and hardening) are also implemented:

- **Threshold engine** (Stage 7, feature `in-house`): dealer-less Feldman DKG,
  Shamir t-of-n over secp256k1 (ECDSA) and edwards25519 (EdDSA), threshold
  signing that verifies under the standard single-key verifier, proactive share
  refresh that preserves the public key/address, and an in-process transport
  with per-round timeout and quorum enforcement. A local 3-node (t=2, n=3)
  `mpc_rounds` test drives DKG → sign → verify and proves t-1 nodes cannot sign.
- **Enclave/HSM storage** (Stage 8): a `KeyShareStore` trait with a software
  `MockHsmStore` (wrap/unwrap/backup/restore, quorum-gated restore) and a
  join-time attestation verifier binding the node's mTLS key to the enclave
  measurement + HSM identity.
- **mTLS** (Stage 9): `MTLS_CERT`/`MTLS_KEY`/`MTLS_CA` enable mutual TLS on the
  gRPC port; a rogue-CA client is rejected (tested). `make mtls` generates a
  local PKI; `docker-compose.cluster.yml` runs a 3-node mTLS cluster.
- **Hardening** (Stage 10): coverage reporting in CI, chaos test, and
  `cargo-deny`/`cargo-audit` in CI; runbooks in `docs/runbooks/` and
  `SECURITY.md`.

Known deviations and pending work (see `PROJECT_PLAN.md` and `SECURITY.md`):

- **Threshold signing reconstructs the secret in the combiner** — a documented
  placeholder (`src/engine/threshold/cluster.rs`). A non-reconstructing
  protocol (GG20/CGGMP/CMP20) via an audited crate is required before the
  in-house engine signs production funds. DKG, refresh, quorum, and transport
  are real.
- Enclave/HSM storage and attestation are **software mocks** (no PKCS#11 / real
  Nitro-SGX); the inter-node channel is in-process; no external audit yet.
- `INSECURE_SKIP_POLICY` / `INSECURE_SKIP_WALLET_CHECK` are dev-only escape
  hatches; without them, an unconfigured policy key or wallet URL fails closed.
- Sessions and used tokens are in-memory stores behind traits; a durable store
  swaps in without touching handlers.

## Local Development

> **Security caveats:** Local development never uses real HSMs or production key
> material. The local backend uses a software mock enclave and ephemeral keys only.
> Never point a local node at production `PEER_NODES` or `KEY_SHARE_STORE_URL`.

### Build

```sh
# Build the service and all crates
cargo build --release

# Build with the in-house MPC backend (default)
cargo build --release --no-default-features --features in-house

# Build with a v1 custody provider backend
cargo build --release --no-default-features --features fireblocks
cargo build --release --no-default-features --features dfns
cargo build --release --no-default-features --features turnkey
```

### Test

```sh
# Unit + integration tests (software backend, no HSM required)
cargo test

# Run only the MPC round tests
cargo test --test mpc_rounds

# Run with the custody-provider adapter mocked
cargo test --features fireblocks -- --ignored
```

### Run a local 3-node cluster (t=2, n=3)

```sh
# Terminal 1
NODE_ID=node1 PORT=50051 PEER_NODES=localhost:50052,localhost:50053 \
  THRESHOLD_T=2 TOTAL_N=3 CUSTODY_PROVIDER=in_house ./target/run-mpc-node.sh

# Terminal 2
NODE_ID=node2 PORT=50052 PEER_NODES=localhost:50051,localhost:50053 \
  THRESHOLD_T=2 TOTAL_N=3 CUSTODY_PROVIDER=in_house ./target/run-mpc-node.sh

# Terminal 3
NODE_ID=node3 PORT=50053 PEER_NODES=localhost:50051,localhost:50052 \
  THRESHOLD_T=2 TOTAL_N=3 CUSTODY_PROVIDER=in_house ./target/run-mpc-node.sh
```

### v1 vs build-later strategy

- **v1:** Set `CUSTODY_PROVIDER` to `fireblocks`, `dfns`, or `turnkey`. The service
  delegates signing to the provider while enforcing policy gating, audit, and
  Wallet Mgmt integration through our wrappers. No MPC rounds run locally.
- **Later:** Set `CUSTODY_PROVIDER=in_house` (default) to use the in-house MPC
  engine. Existing callers (Orchestrator, Wallet Mgmt) are unchanged because they
  depend on the service's gRPC trait, not on the backend implementation.

## Security Considerations

### Threat model

- **Node compromise:** up to `t-1` nodes may be compromised without exposing the
  key or enabling unauthorized signing. Compromise of `t` nodes is catastrophic and
  mitigated by geographic/infra diversity, attestation, and rotation.
- **Insider / operator:** mitigated by quorum for control-plane ops (DKG,
  rotation, restore), separation of duties, and audit of all privileged actions.
- **Supply chain:** pinned, audited crates; reproducible builds; SBOM; HSM
  firmware attestation.
- **Network:** all RPC and inter-node traffic is mTLS; MPC messages are
  additionally protected by transport that resists replay and MITM via session
  binding.
- **Replay:** `policy_decision_token` is single-use and payload-bound; stale or
  duplicate `SignTx` requests are rejected.
- **Side channels:** constant-time crypto, no secret-dependent memory access
  patterns, enclave-mediated share use, scheduled rotation shrinks the exposure
  window.

### HSM requirements

- FIPS 140-2 Level 3 or higher (Level 4 preferred for the share store).
- PKCS#11 interface; supports wrapping keys resident in the HSM.
- Non-exportable wrapping keys; shares never appear in host memory in cleartext.
- Per-node HSM with independent PIN / admin quorum; no shared HSM across nodes.
- Audited firmware; vendor security disclosures monitored.

### Key ceremony

- DKG is run as a multi-party ceremony across `n` nodes; no dealer.
- Ceremony participants, threshold, and resulting public key / address are
  attested and recorded in the audit log.
- Share rotation (CMP20 refresh) is performed on a schedule and after any node
  incident, producing new shares for the same public key with no on-chain change.
- Backup shares are wrapped by HSM-resident keys; restore requires a quorum proof
  and is itself audited.
- Ceremony runbook, participants, and approvals are documented and stored
  alongside the audit record; recovery drills are exercised on a schedule.

### Attestation

- Every node presents a hardware attestation (Nitro Enclave attestation doc / SGX
  quote) at cluster join.
- The attestation doc binds the node's mTLS public key to the enclave measurement
  and HSM identity, preventing impersonation of a legit node by a rogue host.
- Nodes failing attestation are quarantined; cluster membership rejects them.
- Attestation freshness is checked on every control-plane and peer-join RPC.
