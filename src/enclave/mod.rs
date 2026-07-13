//! Enclave / HSM key-share storage and node attestation (Stage 8).
//!
//! Key shares are wrapped by a non-exportable wrapping key that lives inside
//! the secure boundary; the host only ever sees ciphertext. Production uses a
//! PKCS#11 HSM; local dev/CI uses the software [`MockHsmStore`] (gated behind
//! the `mock-hsm` cfg, never compiled into a hardened prod image).
//!
//! At cluster join, a node presents an attestation document binding its mTLS
//! public key to the enclave measurement and HSM identity; the
//! [`attestation::AttestationVerifier`] rejects mismatched, stale, or
//! wrong-measurement documents.

pub mod attestation;
pub mod store;

pub use attestation::{AttestationDoc, AttestationError, AttestationVerifier};
pub use store::{KeyShareStore, MockHsmStore, StoreError, WrappedShare};
