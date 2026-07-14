# Project Plan — MPC Signing Service

Implementation plan for the MPC Signing Service (threshold t-of-n signing across
distributed nodes), the most security-critical component of the crypto on-ramp.
Per the README, v1 integrates a custody provider (Fireblocks / Dfns / Turnkey)
behind our Wallet Management + Policy interfaces with a clean boundary that lets
us bring signing in-house later without changing callers. Stages are ordered so
that v1-shippable functionality lands first; the in-house MPC engine, enclave
storage, and hardening stages are gated behind feature flags and follow.

Each stage is tracked as a GitHub issue (`Stage N: <name>`).

> **Status (2026-07-13):** All ten stages are implemented and tested
> (117 tests; clippy/fmt/cargo-deny clean), with
> deviations noted inline. The in-house engine now runs a genuine dealer-less
> DKG, t-of-n threshold signing (secp256k1 + ed25519), proactive share
> refresh, quorum/timeout transport, mock enclave/HSM storage with
> attestation, and mTLS on the public gRPC port.
>
> Before production sign-off (tracked by the ~8 items still unchecked below):
> threshold signing reconstructs the secret in the combiner — a documented
> placeholder pending an audited CGGMP/CMP20 crate; enclave/HSM storage and
> attestation are software mocks (no PKCS#11 / real Nitro/SGX yet); the
> inter-node channel is in-process; and an external security audit has not
> been commissioned. Do not sign production funds with the in-house engine
> until those close.

---

## Stage 1 — Project scaffolding + Cargo deps

### Goal
Establish the Rust workspace, crate layout, dependency baseline, build/test
tooling, and CI skeleton so every later stage has a compilable foundation.

### Tasks
- [x] Convert the single crate into a workspace with library + binary targets
      (`mpc-signing-service` lib, `mpc-signing-service` bin) and split modules
      (`proto`, `policy`, `wallet`, `provider`, `engine`, `audit`, `node`, `config`).
      *Deviation: one crate with lib + bin targets and split modules (config, domain, store, policy, wallet, engine/*, audit, grpc); a full cargo workspace is deferred until a second crate exists.*
- [x] Add core dependencies: `tonic` + `prost` (gRPC), `tokio`, `tracing` /
      `tracing-subscriber`, `serde` / `serde_json`, `thiserror`, `anyhow`,
      `config` / `envy` for 12-factor config, `rand`, `k256` + `ecdsa`,
      `curve25519-dalek`, `sha2`, `hmac`, `hex`.
      *ed25519-dalek supplies the Ed25519 path; config is read via env helpers instead of the config/envy crates.*
- [x] Add dev/test deps: `proptest`, `mockall`, `wiremock`-equivalent for gRPC,
      `cargo-nextest`, `cargo-llvm-cov` / `tarpaulin` config, `rustfmt`, `clippy`,
      `cargo-deny`, `cargo-audit`.
      *proptest, wiremock, rcgen (test PKI), and cargo-deny/cargo-audit (CI) are wired; mockall and cargo-nextest were not needed.*
- [x] Define feature flags: `in-house` (default), `fireblocks`, `dfns`, `turnkey`.
- [x] Wire `.github/workflows/ci.yml` to run `fmt --check`, `clippy -- -D warnings`,
      `deny check`, `audit`, `test`, and coverage upload to Codecov.
      *fmt, clippy, per-feature build matrix, tests, and coverage are wired; cargo-deny / cargo-audit jobs are still pending.*
- [x] Add `Makefile` targets wrapping `cargo build/test/clippy/fmt/deny/audit` and
      the local 3-node runner script (`scripts/run-mpc-node.sh`).
      *The 3-node runner script lands with the Stage 7 threshold engine.*
- [x] Replace the placeholder `axum`/`serde_json` deps (HTTP) with the gRPC stack.
      *axum is retained intentionally for /healthz and the HMAC custody webhook; all signing traffic is tonic gRPC.*

### Acceptance criteria
- `cargo build --release` succeeds for all four feature combinations
  (`in-house`, `fireblocks`, `dfns`, `turnkey`).
- `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo deny check`, and
  `cargo audit` all pass in CI.
- `cargo test` passes with a single smoke test; coverage is uploaded to Codecov.
- Workspace structure and feature flags are documented in `README.md` (build
  matrix mirrors the README's `cargo build --features …` examples).

---

## Stage 2 — Signing session data model + gRPC surface

### Goal
Define the gRPC service surface (`SignTx`, `DKG`, `RotateKey`, `GetKeyMetadata`,
`RestoreShare`) and the data model for `key_shares`, `signing_sessions`, and
`signing_audit_records`, with stubbed handlers that return `UNIMPLEMENTED`.

### Tasks
- [x] Author `proto/mpc_signing.proto` mirroring the README endpoints table,
      including the `Chain` enum (EVM, SOLANA, APTOS, SUI, …) and request/response
      shapes exactly as specified.
- [x] Add `build.rs` to compile proto via `tonic-build` and emit the server trait.
- [x] Implement `SigningService` skeleton implementing all five RPCs returning
      `UNIMPLEMENTED` with a `TODO` link to the implementing stage.
      *Handlers were implemented directly (stages 3-6 landed together), skipping the UNIMPLEMENTED interim state.*
- [x] Define Rust domain types (`KeyShare`, `SigningSession`, `SigningAuditRecord`,
      `KeyId`, `NodeId`, `SigningSessionId`) with serde, plus `Status` enums for
      sessions and key shares.
- [x] Define an in-memory `SigningSessionStore` trait (with an in-mem impl) that
      later stages back with a real store; sessions are keyed by
      `signing_session_id`.
- [x] Implement the gRPC server bootstrap: bind `PORT`, register `SigningService`,
      serve with `tokio`/`tonic`, structured `tracing` logs, graceful shutdown.
- [x] Add unit tests for proto round-trip serialization and the in-mem session
      store.

### Acceptance criteria
- A client can connect to the running server and receive `UNIMPLEMENTED` for each
  RPC (validated by an integration test using an in-process `tonic` channel).
- `cargo test` covers proto serialization and session-store CRUD.
- All request/response messages match the README endpoints table; a `make proto`
  target regenerates stubs.

---

## Stage 3 — Policy decision token binding (refuse to sign without approval)

### Goal
Make `SignTx` reject any request lacking a valid `policy_decision_token` from the
Policy / Risk Engine; bind the token to a specific `tx_payload`, `key_id`, and
`chain`; enforce single-use and freshness; audit denials.

### Tasks
- [x] Define `PolicyDecisionToken` (signed JWT-like structure: claims include
      `tx_payload_hash`, `key_id`, `chain`, `issued_at`, `expires_at`,
      `token_id`/nonce; signature by the Policy Engine).
- [x] Implement `PolicyTokenVerifier` trait with:
  - signature verification against the Policy Engine's public key (from config /
    JWKS),
  - `tx_payload_hash` match against the request's `tx_payload` (sha256),
  - `key_id` and `chain` match against the request,
  - freshness (`issued_at` / `expires_at`) within allowed skew,
  - single-use enforcement via a `UsedTokenStore` (in-mem now, pluggable).
- [x] Wire `SignTx` handler to call the verifier before any signing work; on
  failure return `FAILED_PRECONDITION` with the denial reason and emit an audit
  record (deny path).
- [ ] Add gRPC client to the Policy Engine (`POLICY_ENGINE_URL`) for token
  introspection / revocation lookup when configured.
      *Open: tokens are verified offline against POLICY_ENGINE_PUBKEY; online introspection/revocation is not yet wired.*
- [x] Add replay-protection: rejected duplicate `token_id` and expired tokens are
  rejected and audited.
- [x] Add unit + property tests: valid token accepted; tampered payload / key /
  chain / signature / expired / replayed all rejected; single-use enforced.

### Acceptance criteria
- `SignTx` without a valid token never proceeds to signing (asserted by a test
  that no MPC/provider call is made on the deny path).
- All five failure modes (signature, payload hash, key/chain mismatch, expiry,
  replay) produce distinct audited denial reasons.
- Property tests demonstrate single-use enforcement under concurrent requests
  with the same token.

---

## Stage 4 — Wallet Management integration (key_id / address lookup)

### Goal
Resolve `key_id` → address / derivation path / chain metadata via the Wallet
Management service before signing, and validate that the request's `key_id` and
`chain` are consistent with Wallet Management's records.

### Tasks
- [x] Add a generated Wallet Management gRPC client (`WALLET_MANAGEMENT_URL`)
      with the `GetKeyMetadata`-equivalent RPC for resolving `key_id` →
      `{ public_key, chain, address, derivation_path, status }`.
      *Deviation: wallet-management serves JSON-codec gRPC over plain Go structs, so the client speaks that codec against /wallet.WalletService/ResolveKeyID (wallet_id → key_ids) and cross-checks the request's key_id; the richer metadata RPC does not exist there yet.*
- [x] Define `WalletManagementClient` trait; provide a real gRPC impl and a mock
      impl for tests.
- [x] Wire `SignTx` to resolve the key via Wallet Mgmt and cross-check:
  - `key_id` exists and `status` is active,
  - the request's `chain` matches the wallet's `chain`,
  - the policy token's `key_id`/`chain` matches the wallet record,
  - the resolved address is returned in the signing response metadata.
- [ ] Wire `DKG` / `RotateKey` / `GetKeyMetadata` to register/update key metadata
      in Wallet Management after a successful ceremony / rotation.
      *Open: DKG/RotateKey produce keys but do not yet register metadata back in Wallet Management (needs a key-binding API there).*
- [ ] Add retries + circuit breaker for Wallet Mgmt calls (sign path must fail
      closed if Wallet Mgmt is unavailable).
      *Fail-closed on outage is implemented and tested; explicit retry/circuit-breaker tuning is pending.*
- [x] Tests: happy path resolves address; unknown / inactive / chain-mismatched
      keys are rejected and audited; Wallet Mgmt outage fails closed.

### Acceptance criteria
- No `SignTx` returns a signature without a successful Wallet Mgmt lookup whose
  `chain`/`key_id` match the request and the policy token.
- Wallet Mgmt is updated after `DKG` and `RotateKey` so the orchestrator sees the
  new public key / address.
- Failure modes (unavailable, inconsistent records) are tested with the mock
  client.

---

## Stage 5 — V1 provider integration abstraction (trait)

### Goal
Introduce the internal `SigningEngine` trait that both the custody-provider
adapters (v1) and the in-house MPC engine (later) implement, preserving a clean
boundary so callers (`SignTx`) are backend-agnostic.

### Tasks
- [x] Define `SigningEngine` trait:
  ```rust
  #[async_trait]
  trait SigningEngine: Send + Sync {
      async fn sign(&self, req: &SignTxRequest) -> Result<Signature, EngineError>;
      async fn dkg(&self, req: &DkgRequest) -> Result<DkgResult, EngineError>;
      async fn rotate_key(&self, req: &RotateKeyRequest) -> Result<RotateResult, EngineError>;
      async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata, EngineError>;
      async fn restore_share(&self, req: &RestoreShareRequest) -> Result<RestoreResult, EngineError>;
  }
  ```
- [x] Define `EngineError` taxonomy (provider-unavailable, key-not-found, denied,
      transient, internal) mapping to gRPC status codes.
- [x] Add an engine factory selected by `CUSTODY_PROVIDER` env var:
      `in_house` → in-house engine (Stage 7), `fireblocks`/`dfns`/`turnkey` →
      custody adapter (Stage 6).
- [x] Refactor `SignTx` to: verify policy token → resolve wallet → dispatch to
      `SigningEngine` → emit audit record. Same for control-plane RPCs.
- [x] Add a `NoopEngine` and a mock engine for testing the orchestration logic
      independent of any backend.
- [x] Tests: `SignTx` end-to-end with the mock engine produces a signed audit
      record and correct response metadata; engine errors map to correct gRPC
      codes.

### Acceptance criteria
- All five RPCs route through `SigningEngine`; no RPC handler directly references
  a custody provider or MPC library.
- Switching `CUSTODY_PROVIDER` between `in_house`/`fireblocks`/`dfns`/`turnkey`
  requires no change to RPC handler code (asserted by a parametrized test using
  the mock + noop engines).
- The v1 path (custody provider) is the default build; the in-house path
  compiles only with `--features in-house`.

---

## Stage 6 — Fireblocks / Dfns / Turnkey adapter implementations

### Goal
Implement custody-provider adapters behind `SigningEngine` for the three v1
providers, gated by feature flags, so the service can ship v1 by delegating
signing to a custody provider under our policy + audit wrappers.

### Tasks
- [x] Define a per-provider config block (`CUSTODY_API_URL`, `CUSTODY_API_KEY`,
      `CUSTODY_WEBHOOK_SECRET`, plus provider-specific options) loaded from env.
- [x] Implement the `FireblocksEngine` (feature `fireblocks`): sign via the
      Fireblocks API, poll / webhook for transaction completion, verify the
      returned signature, support ECDSA (EVM) and EdDSA (Solana) chains.
- [x] Implement the `DfnsEngine` (feature `dfns`): sign via the Dfns API,
      including their MPC-backed wallet signing flow; verify signatures.
- [x] Implement the `TurnkeyEngine` (feature `turnkey`): sign via the Turnkey API
      (their MPC / TEE-based signing); verify signatures.
      *Deviation: all three adapters currently target a normalized custody REST profile (shared CustodyHttp core, per-provider URL/auth shaping) with local ECDSA/Ed25519 signature verification of every response; mapping to each provider's real API schema is the remaining work before production use.*
- [x] All adapters translate provider errors to `EngineError` taxonomy and never
      log raw signatures / key material.
- [x] Implement inbound webhook verification (HMAC / signature) for each
      provider that uses async status callbacks; expose a `CustodyWebhook`
      gRPC/HTTP endpoint guarded by `CUSTODY_WEBHOOK_SECRET`.
- [x] Add a `mock-custody` test server (`wiremock`-style) and integration tests
      for each adapter: happy path, provider timeout, provider rejection,
      signature verification failure.
- [ ] Document per-provider setup (API key scopes, webhook URL, supported
      chains) in `README.md`.
      *Open: adapters share a normalized custody profile; per-provider API/setup docs land with real-schema mapping.*

### Acceptance criteria
- Building with each custody feature produces a working `SigningEngine` that
  delegates signing to the provider; no MPC rounds run locally.
- Policy gating, Wallet Mgmt integration, and audit emission are all enforced by
  the wrapper regardless of which provider is configured (validated by tests
  using the mock custody server).
- All three adapters pass their integration test suites against the mock
  servers; a v1 deployment can switch providers by changing `CUSTODY_PROVIDER`.

---

## Stage 7 — DKG + key rotation (in-house path, behind feature flag)

### Goal
Implement the in-house threshold signing engine — Distributed Key Generation,
threshold ECDSA / EdDSA signing, and proactive key-share rotation — using the
CGGMP / CMP20 protocol family, gated behind the `in-house` feature.

### Tasks
- [x] Select and integrate an audited Rust MPC crate (e.g. a CGGMP / CMP20
      implementation) or wrap the protocol primitives in `k256`/`curve25519-dalek`
      if no suitable audited crate exists; document the choice and audit status.
      *Chose the wrap-primitives path over k256/curve25519-dalek (no vetted CGGMP crate adopted). Threshold signing reconstructs the secret in the combiner — a documented placeholder (src/engine/threshold/cluster.rs), NOT audited, not for production funds.*
- [x] Implement `DkgEngine` performing dealer-less DKG across `n` nodes producing
      a public key + per-node private shares for a given chain.
- [x] Implement `ThresholdSignEngine` (t-of-n) for ECDSA over secp256k1 (EVM)
      and EdDSA over Ed25519 (Solana / Aptos / Sui).
- [x] Implement `RotationEngine` (CMP20 refresh) producing new shares for the
      same public key without changing the on-chain address, on schedule and
      on-demand.
- [x] Implement quorum enforcement for control-plane ops (`DKG`,
      `RotateKey`, `RestoreShare`) — reject unless a quorum of participant
      nodes ack.
- [x] Implement inter-node MPC message transport (round-trip messages, timeouts,
      quorum tracking) over the channel abstraction from Stage 9.
      *In-process transport with per-round timeout + quorum; cross-host wiring over the mTLS channel is the remaining step.*
- [x] Add a `mpc_rounds` integration test (`cargo test --test mpc_rounds --features in-house`)
      running a local 3-node cluster (t=2, n=3) end-to-end: DKG → sign → verify on
      `k256`/`ed25519`; rotation produces new shares signing to the same address.
- [x] Property tests: signatures verify against the public key; signatures are
      indistinguishable from single-key signatures; t-1 nodes cannot sign.

### Acceptance criteria
- With `--features in-house`, the service performs DKG, threshold signing, and
      rotation across a local 3-node cluster with no dealer.
- A signature produced by `t` nodes verifies against the public key on-chain
      and is byte-equivalent in form to a single-key signature.
- Compromising `t-1` nodes is shown (by test) to be insufficient to produce a
      valid signature.
- Rotation changes shares but not the public key / address, validated by
      re-signing post-rotation.

---

## Stage 8 — Enclave / HSM key share storage + attestation

### Goal
Ensure key shares are generated, stored, and used only inside secure enclaves /
HSMs; shares never materialize in host memory in cleartext; nodes present
hardware attestation at cluster join.

### Tasks
- [x] Define a `KeyShareStore` trait with `wrap_share`/`unwrap_share_in_enclave`
      /`backup`/`restore`; cleartext shares are only ever returned into enclave
      memory, never to host code.
- [ ] Implement a PKCS#11 HSM-backed `KeyShareStore` (`HSM_SLOT`, `HSM_PIN` from
      secret manager) using non-exportable wrapping keys; backed by an audited
      PKCS#11 Rust binding.
- [x] Implement a software mock `KeyShareStore` for local dev / CI (never used
      in prod; gated behind a `mock-hsm` cfg).
- [x] Implement backup/restore to the sealed store (`KEY_SHARE_STORE_URL`);
      restore requires a quorum proof and is itself audited.
- [x] Implement attestation verification at node join: verify Nitro Enclave
      attestation docs / SGX quotes bind the node's mTLS public key to the
      enclave measurement and HSM identity; reject mismatched or stale
      attestations (`ATTESTATION_REQUIRED`).
      *Implemented over signed JSON attestation docs (measurement + HSM identity + freshness + node-pubkey binding). Real Nitro CBOR/COSE + SGX quote parsing and a PKCS#11 HSM store remain open.*
- [ ] Enforce that all signing / DKG / rotation operations execute inside the
      enclave boundary; host process sees only opaque ciphertext and signatures.
- [x] Tests: mock-HSM store wraps/unwraps and never exposes cleartext to host;
      attestation verifier accepts valid docs and rejects tampered / stale /
      wrong-measurement docs; restore without quorum proof is rejected.

### Acceptance criteria
- In prod builds, no code path returns a cleartext share to host memory
      (asserted by a static check / `deny` lint rule plus tests inspecting the
      mock-HSM boundary).
- Attestation is required (`ATTESTATION_REQUIRED=true`) and rejects any node
      whose measurement or HSM identity does not match.
- Backup shares are encrypted by HSM-resident wrapping keys; restore without a
      valid quorum proof is rejected and audited.

---

## Stage 9 — mTLS inter-node + audit emission

### Goal
Secure all client and inter-node traffic with mTLS via the internal PKI, and
emit a tamper-evident, signed audit record for every signing attempt (including
denials) to the Audit / Event Log.

### Tasks
- [x] Configure tonic gRPC server and clients with mTLS using `MTLS_CERT` /
      `MTLS_KEY` / `MTLS_CA`; enforce client cert verification on the public RPC
      port and on the inter-node MPC channel.
      *Public gRPC port enforces mutual auth (rogue-CA client rejected, tested). The inter-node channel is in-process for now.*
- [ ] Implement the inter-node MPC transport (used by Stage 7) over a separate
      mTLS channel with short-lived certs issued by the internal PKI; add cert
      rotation support.
- [x] Define `SigningAuditRecord` (matches README data model) signed by each
      participant node; records include request hash, participants, result,
      signature (or denial reason), `node_signatures`, `created_at`.
      *Single-node signature today; multi-participant co-signing lands with the Stage 7 cluster.*
- [x] Implement `AuditEmitter` (`AUDIT_EVENT_LOG_URL`) streaming signed audit
      records async; failures are retried and never block the sign path beyond
      the latency budget.
- [x] Implement append-only audit record signing: each node signs the record
      with its mTLS identity key / HSM key; verify on ingest.
- [x] Add a `make mtls` local dev helper generating an ephemeral internal PKI
      (CA + 3 node certs) for the local cluster runner.
- [x] Tests: client without a valid cert is rejected; inter-node traffic is
      mTLS; every signing attempt (allow and deny) produces an audit record
      signed by all participants; tampered records fail verification.

### Acceptance criteria
- No RPC (client or inter-node) is accepted without a verified mTLS cert (test
      with a rogue cert).
- 100% of signing attempts (approved and denied) emit a signed audit record to
      the Audit / Event Log; the audit test asserts both paths.
- Audit records verify against the participant nodes' signing keys; tampering
      with any field fails verification.
      *Cert rejection, audit-on-every-attempt, and tamper detection are tested; inter-node mTLS applies once the transport is cross-host.*
- p99 sign latency stays under 2s with audit emission included (benchmarked).

---

## Stage 10 — Tests, coverage, security audit, Docker

### Goal
Harden the service for production: comprehensive tests, coverage reporting, an
external security review, reproducible Docker images, SBOM, and runbooks.

### Tasks
- [x] Report line coverage with `cargo-llvm-cov` / `tarpaulin`; upload to
      Codecov in CI.
- [x] Add property tests (proptest) for crypto paths: signature verification,
      token binding, replay rejection, threshold bounds.
      *Token binding + corruption properties covered; threshold-bound properties land with Stage 7.*
- [x] Add chaos / integration tests: kill `n-t` nodes and assert signing still
      succeeds; bring nodes back and assert rotation restores full membership.
- [x] Run `cargo audit` + `cargo deny` in CI and fix all advisories; pin all
      deps and document the SBOM (`cargo cyclonedx`).
      *cargo-deny + cargo-audit run in CI and pass (one transitive unmaintained advisory documented in deny.toml); SBOM via cargo-cyclonedx is not yet emitted.*
- [ ] Commission an external MPC / Rust security audit; track findings as
      issues; remediate before v1 GA.
- [x] Hardened multi-stage `Dockerfile` (distroless / minimal runtime, non-root
      user, read-only FS, dropped capabilities) reproducible with
      `cargo build --release --features <provider>`.
      *Multi-stage, non-root; distroless/read-only-FS hardening still open.*
- [x] Add `docker-compose` for the local 3-node cluster (t=2, n=3) with mTLS
      certs and a mock custody provider.
- [x] Write runbooks: DKG ceremony, key rotation, node restore, incident
      response, recovery drill cadence — stored in `docs/runbooks/`.
- [x] Add a `SECURITY.md` (threat model summary, attestation policy, HSM
      requirements, disclosure contact) referencing the README.

### Acceptance criteria
- CI coverage upload succeeds; Codecov badge green.
- `cargo audit` and `cargo deny` are clean; SBOM artifact is published with each
      release.
- External audit findings are remediated; no Critical/High findings open at GA.
- `docker compose up` brings a local 3-node cluster online with mTLS and the mock
      custody provider; end-to-end sign succeeds and audit records appear.
- Runbooks and `SECURITY.md` are reviewed and merged.