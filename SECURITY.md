# Security Policy — MPC Signing Service

This service holds the signing authority for customer funds. It is the most
security-critical component of the on-ramp. This document summarizes the threat
model, the controls in place, and the disclosure process.

## Threat model (summary)

| Adversary | Goal | Primary control |
| --- | --- | --- |
| External attacker | Forge a signature / drain funds | Policy decision token required on every `SignTx`; mTLS on all RPC |
| Compromised caller | Sign an unapproved transaction | Token bound to `sha256(tx_payload)`, `key_id`, `chain`; single-use; Wallet Mgmt key-binding cross-check |
| Up to `t-1` compromised nodes | Reconstruct the key / sign alone | Threshold t-of-n: fewer than `t` shares cannot sign (enforced + tested) |
| Malicious custody provider | Return a bogus signature | Every provider signature is verified locally against the returned public key before use |
| Host / OS compromise | Read a key share from memory | Shares wrapped by a non-exportable HSM key; cleartext only inside the enclave boundary |
| Rogue node joining the cluster | Participate in signing | Attestation required at join: enclave measurement + HSM identity bound to the node's mTLS key |
| Replay of a captured token | Re-sign an old transaction | Single-use `token_id` + freshness window |
| Audit tampering | Hide an unauthorized signature | Every attempt (allow + deny) emits a node-signed, tamper-evident audit record |

## Attestation policy

Nodes must present a platform attestation document at cluster join binding
their mTLS public key to the expected enclave measurement (Nitro PCR /
SGX MRENCLAVE) and a trusted HSM identity. `ATTESTATION_REQUIRED=true` rejects
any node whose measurement or HSM identity does not match, or whose document is
stale or not authority-signed. See `src/enclave/attestation.rs`.

## HSM / key-share requirements

- Key shares are generated, stored, and used inside secure enclaves / HSMs and
  never materialize in host process memory in cleartext.
- The wrapping key is non-exportable (PKCS#11 in production). The software
  `MockHsmStore` is for local dev / CI only and must never run in production.
- Backups are encrypted by HSM-resident wrapping keys; restore requires a valid
  quorum proof and is itself audited.

## Implementation status vs. this policy

The controls above are implemented and tested for the v1 custody-delegation
path and the in-house engine's protocol structure, with these gaps tracked in
`PROJECT_PLAN.md` before production sign-off:

- **Threshold signing reconstructs the secret in the combiner** (documented in
  `src/engine/threshold/cluster.rs`). A non-reconstructing protocol
  (GG20 / CGGMP / CMP20) via an audited crate is required before the in-house
  engine signs production funds. DKG, refresh, quorum, and transport are real.
- **Enclave/HSM storage and attestation are software mocks.** PKCS#11 HSM
  integration and real Nitro/SGX attestation parsing are pending.
- **An external MPC / Rust security audit has not yet been commissioned.** No
  Critical/High findings may be open at v1 GA.

## Reporting a vulnerability

Email **security@blockchain.com** with details and reproduction steps. Do not
open a public issue for security reports. We aim to acknowledge within one
business day. Please allow coordinated disclosure before publishing.
