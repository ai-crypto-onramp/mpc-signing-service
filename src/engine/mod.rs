//! In-house MPC signing engine (CGGMP / CMP20 family).
//!
//! Stub. The threshold-signing rounds (DKG, sign, refresh, restore) land in
//! Stage 5+, gated behind the `in-house` feature flag.

#![cfg(feature = "in-house")]

use crate::Error;
use crate::Result;

/// In-house threshold-signing engine placeholder. Stage 5 implements the
/// CGGMP/CMP20 rounds here.
#[derive(Debug, Default)]
pub struct Engine;

impl Engine {
    /// Create a new engine instance bound to this node.
    pub fn new() -> Self {
        Self
    }

    /// Run a threshold-sign round (stub).
    pub fn sign(&self, key_id: &str, tx_payload: &[u8]) -> Result<Vec<u8>> {
        let _ = (key_id, tx_payload);
        Err(Error::Unimplemented("Engine::sign (Stage 5)"))
    }
}
