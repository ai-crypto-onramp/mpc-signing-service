//! In-house signing engine (feature `in-house`, Stage 7 — partial).
//!
//! PLACEHOLDER STATUS: this engine performs real ECDSA (secp256k1) and
//! Ed25519 signing with locally generated keys, exercising the full
//! `SigningEngine` contract, but it is single-party. The threshold CGGMP /
//! CMP20 protocol (dealer-less DKG, t-of-n signing, proactive share refresh
//! across nodes) lands when an audited Rust MPC crate is selected — tracked
//! by the unchecked Stage 7 items in PROJECT_PLAN.md. Do not deploy this
//! engine as the production signer.

use std::collections::HashMap;
use std::sync::RwLock;

use k256::ecdsa::signature::Signer as _;
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey as EcdsaSigningKey};

use crate::domain::{Chain, KeyId, KeyMetadata, KeyShareStatus, SignatureScheme};

use super::{
    DkgOutcome, DkgParams, EngineError, EngineSignRequest, EngineSignature, RestoreParams,
    RotateOutcome, SigningEngine,
};

enum LocalSecret {
    Ecdsa(EcdsaSigningKey),
    Ed25519(ed25519_dalek::SigningKey),
}

struct LocalKey {
    chain: Chain,
    secret: LocalSecret,
    epoch: u64,
    status: KeyShareStatus,
}

impl LocalKey {
    fn public_key(&self) -> Vec<u8> {
        match &self.secret {
            LocalSecret::Ecdsa(k) => k.verifying_key().to_sec1_bytes().to_vec(),
            LocalSecret::Ed25519(k) => k.verifying_key().to_bytes().to_vec(),
        }
    }
}

/// Single-party local engine backing the `in-house` feature until the
/// threshold protocol is integrated.
#[derive(Default)]
pub struct LocalEngine {
    keys: RwLock<HashMap<String, LocalKey>>,
}

impl LocalEngine {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait::async_trait]
impl SigningEngine for LocalEngine {
    async fn sign(&self, req: &EngineSignRequest) -> Result<EngineSignature, EngineError> {
        let keys = self.keys.read().expect("keystore lock");
        let key = keys
            .get(&req.key_id.0)
            .ok_or_else(|| EngineError::KeyNotFound(req.key_id.0.clone()))?;
        if key.status != KeyShareStatus::Active {
            return Err(EngineError::Denied(format!(
                "key {} is not active",
                req.key_id.0
            )));
        }
        if key.chain.scheme() != req.chain.scheme() {
            return Err(EngineError::Denied("chain/scheme mismatch for key".into()));
        }
        let signature = match &key.secret {
            LocalSecret::Ecdsa(k) => {
                // ECDSA over SHA-256 of the payload (prehash handled by k256).
                let sig: EcdsaSignature = k.sign(&req.payload);
                sig.to_vec()
            }
            LocalSecret::Ed25519(k) => {
                use ed25519_dalek::Signer as _;
                k.sign(&req.payload).to_bytes().to_vec()
            }
        };
        Ok(EngineSignature {
            signature,
            public_key: key.public_key(),
        })
    }

    async fn dkg(&self, params: &DkgParams) -> Result<DkgOutcome, EngineError> {
        if params.threshold == 0 || params.parties == 0 || params.threshold > params.parties {
            return Err(EngineError::Denied(format!(
                "invalid threshold {}-of-{}",
                params.threshold, params.parties
            )));
        }
        let secret = match params.chain.scheme() {
            SignatureScheme::EcdsaSecp256k1 => {
                LocalSecret::Ecdsa(EcdsaSigningKey::random(&mut rand::rngs::OsRng))
            }
            SignatureScheme::Ed25519 => {
                LocalSecret::Ed25519(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng))
            }
        };
        let key = LocalKey {
            chain: params.chain,
            secret,
            epoch: 1,
            status: KeyShareStatus::Active,
        };
        let key_id = format!("local-{}", uuid::Uuid::new_v4());
        let public_key = key.public_key();
        self.keys
            .write()
            .expect("keystore lock")
            .insert(key_id.clone(), key);
        Ok(DkgOutcome {
            key_id: KeyId(key_id),
            public_key,
        })
    }

    async fn rotate_key(&self, key_id: &KeyId) -> Result<RotateOutcome, EngineError> {
        let mut keys = self.keys.write().expect("keystore lock");
        let key = keys
            .get_mut(&key_id.0)
            .ok_or_else(|| EngineError::KeyNotFound(key_id.0.clone()))?;
        // CMP20 share refresh replaces per-node shares while preserving the
        // public key; the single-party placeholder models that as an epoch
        // bump with the public key unchanged.
        key.epoch += 1;
        Ok(RotateOutcome {
            key_id: key_id.clone(),
            public_key: key.public_key(),
            epoch: key.epoch,
        })
    }

    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata, EngineError> {
        let keys = self.keys.read().expect("keystore lock");
        let key = keys
            .get(&key_id.0)
            .ok_or_else(|| EngineError::KeyNotFound(key_id.0.clone()))?;
        Ok(KeyMetadata {
            key_id: key_id.clone(),
            chain: key.chain,
            public_key: key.public_key(),
            status: key.status,
            epoch: key.epoch,
        })
    }

    async fn restore_share(&self, params: &RestoreParams) -> Result<bool, EngineError> {
        if params.quorum_proof.is_empty() {
            return Err(EngineError::Denied(
                "quorum proof required for restore".into(),
            ));
        }
        let keys = self.keys.read().expect("keystore lock");
        if !keys.contains_key(&params.key_id.0) {
            return Err(EngineError::KeyNotFound(params.key_id.0.clone()));
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::Verifier as _;

    fn engine() -> LocalEngine {
        LocalEngine::new()
    }

    #[tokio::test]
    async fn dkg_sign_verify_ecdsa() {
        let e = engine();
        let out = e
            .dkg(&DkgParams {
                chain: Chain::Evm,
                threshold: 2,
                parties: 3,
            })
            .await
            .unwrap();
        let sig = e
            .sign(&EngineSignRequest {
                key_id: out.key_id.clone(),
                chain: Chain::Evm,
                payload: b"evm-tx".to_vec(),
            })
            .await
            .unwrap();

        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&sig.public_key).unwrap();
        let parsed = EcdsaSignature::from_slice(&sig.signature).unwrap();
        vk.verify(b"evm-tx", &parsed).unwrap();
    }

    #[tokio::test]
    async fn dkg_sign_verify_ed25519() {
        let e = engine();
        let out = e
            .dkg(&DkgParams {
                chain: Chain::Solana,
                threshold: 2,
                parties: 3,
            })
            .await
            .unwrap();
        let sig = e
            .sign(&EngineSignRequest {
                key_id: out.key_id.clone(),
                chain: Chain::Solana,
                payload: b"sol-tx".to_vec(),
            })
            .await
            .unwrap();

        let pk_arr: [u8; 32] = sig.public_key.as_slice().try_into().unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr).unwrap();
        let sig_arr: [u8; 64] = sig.signature.as_slice().try_into().unwrap();
        use ed25519_dalek::Verifier as _;
        vk.verify(b"sol-tx", &ed25519_dalek::Signature::from_bytes(&sig_arr))
            .unwrap();
    }

    #[tokio::test]
    async fn rotation_preserves_public_key() {
        let e = engine();
        let out = e
            .dkg(&DkgParams {
                chain: Chain::Evm,
                threshold: 2,
                parties: 3,
            })
            .await
            .unwrap();
        let rot = e.rotate_key(&out.key_id).await.unwrap();
        assert_eq!(rot.public_key, out.public_key);
        assert_eq!(rot.epoch, 2);

        // post-rotation signing still verifies against the same public key
        let sig = e
            .sign(&EngineSignRequest {
                key_id: out.key_id.clone(),
                chain: Chain::Evm,
                payload: b"after-rotate".to_vec(),
            })
            .await
            .unwrap();
        assert_eq!(sig.public_key, out.public_key);
    }

    #[tokio::test]
    async fn unknown_key_and_bad_threshold_rejected() {
        let e = engine();
        assert!(matches!(
            e.sign(&EngineSignRequest {
                key_id: KeyId("missing".into()),
                chain: Chain::Evm,
                payload: vec![1],
            })
            .await
            .unwrap_err(),
            EngineError::KeyNotFound(_)
        ));
        assert!(e
            .dkg(&DkgParams {
                chain: Chain::Evm,
                threshold: 4,
                parties: 3
            })
            .await
            .is_err());
        assert!(e
            .dkg(&DkgParams {
                chain: Chain::Evm,
                threshold: 0,
                parties: 3
            })
            .await
            .is_err());
        assert!(e.rotate_key(&KeyId("missing".into())).await.is_err());
        assert!(e.get_key_metadata(&KeyId("missing".into())).await.is_err());
    }

    #[tokio::test]
    async fn chain_scheme_mismatch_rejected() {
        let e = engine();
        let out = e
            .dkg(&DkgParams {
                chain: Chain::Evm,
                threshold: 2,
                parties: 3,
            })
            .await
            .unwrap();
        // an EVM (ECDSA) key must not sign a Solana (Ed25519) payload
        assert!(matches!(
            e.sign(&EngineSignRequest {
                key_id: out.key_id,
                chain: Chain::Solana,
                payload: vec![1],
            })
            .await
            .unwrap_err(),
            EngineError::Denied(_)
        ));
    }

    #[tokio::test]
    async fn restore_requires_quorum_proof() {
        let e = engine();
        let out = e
            .dkg(&DkgParams {
                chain: Chain::Evm,
                threshold: 2,
                parties: 3,
            })
            .await
            .unwrap();
        assert!(matches!(
            e.restore_share(&RestoreParams {
                key_id: out.key_id.clone(),
                node_id: "n1".into(),
                quorum_proof: vec![],
            })
            .await
            .unwrap_err(),
            EngineError::Denied(_)
        ));
        assert!(e
            .restore_share(&RestoreParams {
                key_id: out.key_id,
                node_id: "n1".into(),
                quorum_proof: vec![1, 2, 3],
            })
            .await
            .unwrap());
    }
}
