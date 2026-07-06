//! Protocol definitions (gRPC service + messages).
//!
//! Stub — the `.proto` file and `tonic-build` wiring land in Stage 2. This
//! module exists so callers and other modules can reference `crate::proto`
//! from Stage 1 onward.

#![allow(dead_code)]

use crate::Error;
use crate::Result;

/// Placeholder for the gRPC server trait that Stage 2 generates from
/// `proto/mpc_signing.proto`. Defined here as a marker trait so the module
/// compiles and is addressable.
pub trait SigningService: Send + Sync + 'static {
    /// `SignTx` RPC — threshold-sign a transaction payload (Stage 5+).
    fn sign_tx(&self) -> Result<()> {
        Err(Error::Unimplemented("SigningService::sign_tx (Stage 5)"))
    }
}

/// Placeholder for the `Chain` enum that Stage 2 generates from the proto.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    /// EVM chains (Ethereum, Polygon, Arbitrum, Base, …) — ECDSA over secp256k1.
    Evm,
    /// Solana — EdDSA over Ed25519.
    Solana,
    /// Aptos — EdDSA over Ed25519.
    Aptos,
    /// Sui — EdDSA over Ed25519.
    Sui,
}
