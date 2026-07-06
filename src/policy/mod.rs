//! Policy gating — refuse to sign without a valid `policy_decision_token`.
//!
//! Stub. The `PolicyTokenVerifier` trait and `UsedTokenStore` land in Stage 3.

#![allow(dead_code)]

use crate::Error;
use crate::Result;

/// Verifier for `policy_decision_token`s issued by the Policy / Risk Engine.
/// Stage 3 implements signature, freshness, payload-binding, and single-use
/// checks.
pub trait PolicyTokenVerifier: Send + Sync {
    /// Verify a token against a signing request's payload. Returns `Ok(())`
    /// when the token is valid and single-use-claimable, `Err` otherwise.
    fn verify(&self, token: &str, tx_payload_hash: &[u8], key_id: &str) -> Result<()> {
        let _ = (token, tx_payload_hash, key_id);
        Err(Error::Unimplemented(
            "PolicyTokenVerifier::verify (Stage 3)",
        ))
    }
}

/// In-mem (Stage 3) / pluggable store for consumed `policy_decision_token`
/// ids, enforcing single-use.
pub trait UsedTokenStore: Send + Sync {
    /// Record a token as used. Returns `Ok(())` if newly recorded, `Err` if
    /// already seen (replay).
    fn record(&self, token_id: &str) -> Result<()> {
        let _ = token_id;
        Err(Error::Unimplemented("UsedTokenStore::record (Stage 3)"))
    }
}
