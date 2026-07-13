//! In-house threshold signing engine (Stage 7, feature `in-house`).
//!
//! Implements [`SigningEngine`](crate::engine::SigningEngine) over two t-of-n
//! clusters — secp256k1 (ECDSA) and edwards25519 (EdDSA) — selected per chain.
//! DKG is dealer-less, signing enforces a quorum of `t`, and rotation refreshes
//! shares while preserving the public key / on-chain address.
//!
//! See [`cluster`] for the documented reconstruct-in-combiner limitation that
//! gates production use pending an audited CGGMP/CMP20 crate.

pub mod cluster;
pub mod curve;
pub mod shamir;

use std::sync::RwLock;

use crate::domain::{Chain, KeyId, KeyMetadata, KeyShareStatus, SignatureScheme};

use super::{
    DkgOutcome, DkgParams, EngineError, EngineSignRequest, EngineSignature, RestoreParams,
    RotateOutcome, SigningEngine,
};
use cluster::{Cluster, ThresholdError};
use curve::{Ed25519, Secp256k1};

impl From<ThresholdError> for EngineError {
    fn from(e: ThresholdError) -> Self {
        match e {
            ThresholdError::QuorumNotMet { .. } => EngineError::ProviderUnavailable(e.to_string()),
            ThresholdError::UnknownKey(k) => EngineError::KeyNotFound(k),
            ThresholdError::ReconstructFailed => EngineError::Internal(e.to_string()),
            ThresholdError::InvalidParams(m) => EngineError::Denied(m),
        }
    }
}

/// Which cluster owns a given key.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scheme {
    Ecdsa,
    Eddsa,
}

/// Threshold engine over an ECDSA and an EdDSA cluster.
pub struct ThresholdEngine {
    ecdsa: Cluster<Secp256k1>,
    eddsa: Cluster<Ed25519>,
    /// key_id -> owning scheme.
    keys: RwLock<std::collections::HashMap<String, Scheme>>,
}

impl ThresholdEngine {
    /// Build a t-of-n engine. Both curves use the same threshold parameters.
    pub fn new(t: usize, n: usize) -> anyhow::Result<Self> {
        Ok(Self {
            ecdsa: Cluster::new(t, n).map_err(|e| anyhow::anyhow!(e))?,
            eddsa: Cluster::new(t, n).map_err(|e| anyhow::anyhow!(e))?,
            keys: RwLock::new(std::collections::HashMap::new()),
        })
    }

    fn scheme_for(&self, key_id: &str) -> Option<Scheme> {
        self.keys.read().unwrap().get(key_id).copied()
    }
}

#[async_trait::async_trait]
impl SigningEngine for ThresholdEngine {
    async fn sign(&self, req: &EngineSignRequest) -> Result<EngineSignature, EngineError> {
        let scheme = self
            .scheme_for(&req.key_id.0)
            .ok_or_else(|| EngineError::KeyNotFound(req.key_id.0.clone()))?;
        // Cross-check the request's chain against the key's scheme.
        let want = match req.chain.scheme() {
            SignatureScheme::EcdsaSecp256k1 => Scheme::Ecdsa,
            SignatureScheme::Ed25519 => Scheme::Eddsa,
        };
        if want != scheme {
            return Err(EngineError::Denied("chain/scheme mismatch for key".into()));
        }
        let (signature, public_key) = match scheme {
            Scheme::Ecdsa => (
                self.ecdsa.sign(&req.key_id.0, &req.payload).await?,
                self.ecdsa
                    .public_key(&req.key_id.0)
                    .ok_or_else(|| EngineError::KeyNotFound(req.key_id.0.clone()))?,
            ),
            Scheme::Eddsa => (
                self.eddsa.sign(&req.key_id.0, &req.payload).await?,
                self.eddsa
                    .public_key(&req.key_id.0)
                    .ok_or_else(|| EngineError::KeyNotFound(req.key_id.0.clone()))?,
            ),
        };
        Ok(EngineSignature {
            signature,
            public_key,
        })
    }

    async fn dkg(&self, params: &DkgParams) -> Result<DkgOutcome, EngineError> {
        let key_id = format!("mpc-{}", uuid::Uuid::new_v4());
        let (public_key, scheme) = match params.chain.scheme() {
            SignatureScheme::EcdsaSecp256k1 => (self.ecdsa.keygen(&key_id).await?, Scheme::Ecdsa),
            SignatureScheme::Ed25519 => (self.eddsa.keygen(&key_id).await?, Scheme::Eddsa),
        };
        self.keys.write().unwrap().insert(key_id.clone(), scheme);
        Ok(DkgOutcome {
            key_id: KeyId(key_id),
            public_key,
        })
    }

    async fn rotate_key(&self, key_id: &KeyId) -> Result<RotateOutcome, EngineError> {
        let scheme = self
            .scheme_for(&key_id.0)
            .ok_or_else(|| EngineError::KeyNotFound(key_id.0.clone()))?;
        let (public_key, epoch) = match scheme {
            Scheme::Ecdsa => self.ecdsa.refresh(&key_id.0).await?,
            Scheme::Eddsa => self.eddsa.refresh(&key_id.0).await?,
        };
        Ok(RotateOutcome {
            key_id: key_id.clone(),
            public_key,
            epoch,
        })
    }

    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata, EngineError> {
        let scheme = self
            .scheme_for(&key_id.0)
            .ok_or_else(|| EngineError::KeyNotFound(key_id.0.clone()))?;
        let (chain, public_key, epoch) = match scheme {
            Scheme::Ecdsa => (
                Chain::Evm,
                self.ecdsa.public_key(&key_id.0),
                self.ecdsa.epoch(&key_id.0),
            ),
            Scheme::Eddsa => (
                Chain::Solana,
                self.eddsa.public_key(&key_id.0),
                self.eddsa.epoch(&key_id.0),
            ),
        };
        Ok(KeyMetadata {
            key_id: key_id.clone(),
            chain,
            public_key: public_key.ok_or_else(|| EngineError::KeyNotFound(key_id.0.clone()))?,
            status: KeyShareStatus::Active,
            epoch: epoch.unwrap_or(1),
        })
    }

    async fn restore_share(&self, params: &RestoreParams) -> Result<bool, EngineError> {
        if params.quorum_proof.is_empty() {
            return Err(EngineError::Denied(
                "quorum proof required for restore".into(),
            ));
        }
        self.scheme_for(&params.key_id.0)
            .ok_or_else(|| EngineError::KeyNotFound(params.key_id.0.clone()))?;
        // Real restore re-derives the node's share from a quorum of peers; the
        // in-process cluster already holds every node's share, so this verifies
        // the key exists and the quorum proof is present.
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::curve::Curve;
    use super::*;

    #[tokio::test]
    async fn engine_dkg_sign_rotate_evm() {
        let engine = ThresholdEngine::new(2, 3).unwrap();
        let dkg = engine
            .dkg(&DkgParams {
                chain: Chain::Evm,
                threshold: 2,
                parties: 3,
            })
            .await
            .unwrap();
        let sig = engine
            .sign(&EngineSignRequest {
                key_id: dkg.key_id.clone(),
                chain: Chain::Evm,
                payload: b"evm-tx".to_vec(),
            })
            .await
            .unwrap();
        assert_eq!(sig.public_key, dkg.public_key);
        assert!(Secp256k1::verify(
            &sig.public_key,
            b"evm-tx",
            &sig.signature
        ));

        let rot = engine.rotate_key(&dkg.key_id).await.unwrap();
        assert_eq!(rot.public_key, dkg.public_key);
        assert_eq!(rot.epoch, 2);
    }

    #[tokio::test]
    async fn engine_dkg_sign_solana() {
        let engine = ThresholdEngine::new(2, 3).unwrap();
        let dkg = engine
            .dkg(&DkgParams {
                chain: Chain::Solana,
                threshold: 2,
                parties: 3,
            })
            .await
            .unwrap();
        let sig = engine
            .sign(&EngineSignRequest {
                key_id: dkg.key_id.clone(),
                chain: Chain::Solana,
                payload: b"sol-tx".to_vec(),
            })
            .await
            .unwrap();
        assert!(Ed25519::verify(&sig.public_key, b"sol-tx", &sig.signature));
    }

    #[tokio::test]
    async fn chain_scheme_mismatch_rejected() {
        let engine = ThresholdEngine::new(2, 3).unwrap();
        let dkg = engine
            .dkg(&DkgParams {
                chain: Chain::Evm,
                threshold: 2,
                parties: 3,
            })
            .await
            .unwrap();
        // an ECDSA key must not sign a Solana (Ed25519) payload
        assert!(matches!(
            engine
                .sign(&EngineSignRequest {
                    key_id: dkg.key_id,
                    chain: Chain::Solana,
                    payload: b"x".to_vec(),
                })
                .await
                .unwrap_err(),
            EngineError::Denied(_)
        ));
    }

    #[tokio::test]
    async fn unknown_key_and_restore_guard() {
        let engine = ThresholdEngine::new(2, 3).unwrap();
        assert!(matches!(
            engine
                .get_key_metadata(&KeyId("missing".into()))
                .await
                .unwrap_err(),
            EngineError::KeyNotFound(_)
        ));
        assert!(matches!(
            engine
                .restore_share(&RestoreParams {
                    key_id: KeyId("missing".into()),
                    node_id: "n1".into(),
                    quorum_proof: vec![1],
                })
                .await
                .unwrap_err(),
            EngineError::KeyNotFound(_)
        ));
    }
}
