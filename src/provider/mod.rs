//! Custody-provider adapters (Fireblocks / Dfns / Turnkey) behind a shared trait.
//!
//! Stub. The trait boundary is defined here so Stage 6+ can plug in provider
//! SDKs under the same interface as the in-house engine, letting v1 ship with a
//! custody provider and migrate later without changing callers.

#![allow(dead_code)]

use crate::Error;
use crate::Result;

/// Internal trait satisfied by both the in-house MPC engine and the custody
/// provider adapters. Callers (`SignTx` handler) talk only to this trait.
pub trait SigningProvider: Send + Sync {
    /// Threshold-sign a transaction payload, returning the resulting signature.
    fn sign(&self, key_id: &str, tx_payload: &[u8]) -> Result<Vec<u8>> {
        let _ = (key_id, tx_payload);
        Err(Error::Unimplemented("SigningProvider::sign (Stage 5/6)"))
    }
}

/// Marker for the active provider, selected at runtime via `CUSTODY_PROVIDER`.
/// The cargo feature flags (`in-house`, `fireblocks`, `dfns`, `turnkey`) gate
/// which provider SDK dependencies are compiled in; this enum names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// In-house CGGMP/CMP20 threshold signing.
    InHouse,
    /// Fireblocks custody API.
    Fireblocks,
    /// Dfns custody API.
    Dfns,
    /// Turnkey custody API.
    Turnkey,
}
