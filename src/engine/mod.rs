//! `SigningEngine` boundary (Stage 5).
//!
//! Every RPC handler dispatches through this trait; no handler references a
//! custody provider or MPC library directly. v1 selects a custody adapter via
//! `CUSTODY_PROVIDER`; the in-house engine implements the same trait behind
//! the `in-house` feature.

pub mod custody;
pub mod noop;

#[cfg(feature = "dfns")]
pub mod dfns;
#[cfg(feature = "fireblocks")]
pub mod fireblocks;
#[cfg(feature = "in-house")]
pub mod local;
#[cfg(feature = "in-house")]
pub mod threshold;
#[cfg(feature = "turnkey")]
pub mod turnkey;

use std::sync::Arc;

use crate::config::{Config, CustodyProvider};
use crate::domain::{Chain, KeyId, KeyMetadata};

/// Backend-agnostic sign request (post policy/wallet checks).
#[derive(Debug, Clone)]
pub struct EngineSignRequest {
    pub key_id: KeyId,
    pub chain: Chain,
    pub payload: Vec<u8>,
}

/// A produced signature plus the public key it verifies against.
#[derive(Debug, Clone)]
pub struct EngineSignature {
    pub signature: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DkgParams {
    pub chain: Chain,
    pub threshold: u32,
    pub parties: u32,
}

#[derive(Debug, Clone)]
pub struct DkgOutcome {
    pub key_id: KeyId,
    pub public_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RotateOutcome {
    pub key_id: KeyId,
    pub public_key: Vec<u8>,
    pub epoch: u64,
}

#[derive(Debug, Clone)]
pub struct RestoreParams {
    pub key_id: KeyId,
    pub node_id: String,
    pub quorum_proof: Vec<u8>,
}

/// Engine error taxonomy; maps 1:1 to gRPC status codes.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("provider unavailable: {0}")]
    ProviderUnavailable(String),
    #[error("key not found: {0}")]
    KeyNotFound(String),
    #[error("denied: {0}")]
    Denied(String),
    #[error("transient: {0}")]
    Transient(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl EngineError {
    pub fn grpc_code(&self) -> tonic::Code {
        match self {
            EngineError::ProviderUnavailable(_) => tonic::Code::Unavailable,
            EngineError::KeyNotFound(_) => tonic::Code::NotFound,
            EngineError::Denied(_) => tonic::Code::PermissionDenied,
            EngineError::Transient(_) => tonic::Code::Aborted,
            EngineError::Unsupported(_) => tonic::Code::Unimplemented,
            EngineError::Internal(_) => tonic::Code::Internal,
        }
    }
}

impl From<EngineError> for tonic::Status {
    fn from(e: EngineError) -> Self {
        tonic::Status::new(e.grpc_code(), e.to_string())
    }
}

/// The signing backend boundary. Implemented by custody adapters (v1) and the
/// in-house threshold engine (feature `in-house`).
#[async_trait::async_trait]
pub trait SigningEngine: Send + Sync {
    async fn sign(&self, req: &EngineSignRequest) -> Result<EngineSignature, EngineError>;
    async fn dkg(&self, params: &DkgParams) -> Result<DkgOutcome, EngineError>;
    async fn rotate_key(&self, key_id: &KeyId) -> Result<RotateOutcome, EngineError>;
    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata, EngineError>;
    async fn restore_share(&self, params: &RestoreParams) -> Result<bool, EngineError>;
}

/// Selects the engine from `CUSTODY_PROVIDER`. Providers not compiled in
/// (missing feature) fail fast with a clear error.
pub fn build_engine(cfg: &Config) -> anyhow::Result<Arc<dyn SigningEngine>> {
    match cfg.custody_provider {
        CustodyProvider::InHouse => {
            #[cfg(feature = "in-house")]
            {
                Ok(Arc::new(threshold::ThresholdEngine::new(
                    cfg.threshold_t,
                    cfg.total_n,
                )?))
            }
            #[cfg(not(feature = "in-house"))]
            {
                anyhow::bail!(
                    "CUSTODY_PROVIDER=in_house but the in-house feature is not compiled in"
                )
            }
        }
        CustodyProvider::Fireblocks => {
            #[cfg(feature = "fireblocks")]
            {
                Ok(Arc::new(fireblocks::FireblocksEngine::from_config(cfg)?))
            }
            #[cfg(not(feature = "fireblocks"))]
            {
                anyhow::bail!(
                    "CUSTODY_PROVIDER=fireblocks but the fireblocks feature is not compiled in"
                )
            }
        }
        CustodyProvider::Dfns => {
            #[cfg(feature = "dfns")]
            {
                Ok(Arc::new(dfns::DfnsEngine::from_config(cfg)?))
            }
            #[cfg(not(feature = "dfns"))]
            {
                anyhow::bail!("CUSTODY_PROVIDER=dfns but the dfns feature is not compiled in")
            }
        }
        CustodyProvider::Turnkey => {
            #[cfg(feature = "turnkey")]
            {
                Ok(Arc::new(turnkey::TurnkeyEngine::from_config(cfg)?))
            }
            #[cfg(not(feature = "turnkey"))]
            {
                anyhow::bail!("CUSTODY_PROVIDER=turnkey but the turnkey feature is not compiled in")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_error_grpc_mapping() {
        assert_eq!(
            EngineError::ProviderUnavailable("x".into()).grpc_code(),
            tonic::Code::Unavailable
        );
        assert_eq!(
            EngineError::KeyNotFound("x".into()).grpc_code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            EngineError::Denied("x".into()).grpc_code(),
            tonic::Code::PermissionDenied
        );
        assert_eq!(
            EngineError::Transient("x".into()).grpc_code(),
            tonic::Code::Aborted
        );
        assert_eq!(
            EngineError::Unsupported("x".into()).grpc_code(),
            tonic::Code::Unimplemented
        );
        assert_eq!(
            EngineError::Internal("x".into()).grpc_code(),
            tonic::Code::Internal
        );
    }

    #[cfg(feature = "in-house")]
    #[test]
    fn factory_selects_in_house_by_default() {
        let cfg = Config::default();
        assert!(build_engine(&cfg).is_ok());
    }
}
