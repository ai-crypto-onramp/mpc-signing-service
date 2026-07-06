//! Wallet Management integration — resolve `key_id` → address / derivation path.
//!
//! Stub. Stage 4 implements the gRPC client to Wallet Management.

#![allow(dead_code)]

use crate::Error;
use crate::Result;

/// Client trait for Wallet Management lookups. Stage 4 wires the gRPC client.
pub trait WalletManagement: Send + Sync {
    /// Resolve a `key_id` to its on-chain address and derivation path.
    fn resolve(&self, key_id: &str) -> Result<String> {
        let _ = key_id;
        Err(Error::Unimplemented("WalletManagement::resolve (Stage 4)"))
    }
}
