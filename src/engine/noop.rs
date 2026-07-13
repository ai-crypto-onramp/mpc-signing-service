//! Test/dev engines: `NoopEngine` refuses everything; `MockEngine` records
//! calls and returns canned results so orchestration logic can be tested
//! independently of any backend.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use crate::domain::{Chain, KeyId, KeyMetadata, KeyShareStatus};

use super::{
    DkgOutcome, DkgParams, EngineError, EngineSignRequest, EngineSignature, RestoreParams,
    RotateOutcome, SigningEngine,
};

/// Engine that refuses all operations — a safe default when no backend is
/// configured.
#[derive(Default)]
pub struct NoopEngine;

#[async_trait::async_trait]
impl SigningEngine for NoopEngine {
    async fn sign(&self, _req: &EngineSignRequest) -> Result<EngineSignature, EngineError> {
        Err(EngineError::Unsupported("noop engine".into()))
    }
    async fn dkg(&self, _params: &DkgParams) -> Result<DkgOutcome, EngineError> {
        Err(EngineError::Unsupported("noop engine".into()))
    }
    async fn rotate_key(&self, _key_id: &KeyId) -> Result<RotateOutcome, EngineError> {
        Err(EngineError::Unsupported("noop engine".into()))
    }
    async fn get_key_metadata(&self, _key_id: &KeyId) -> Result<KeyMetadata, EngineError> {
        Err(EngineError::Unsupported("noop engine".into()))
    }
    async fn restore_share(&self, _params: &RestoreParams) -> Result<bool, EngineError> {
        Err(EngineError::Unsupported("noop engine".into()))
    }
}

/// Recording engine for orchestration tests.
pub struct MockEngine {
    pub sign_calls: AtomicUsize,
    /// When set, `sign` returns this error instead of a signature.
    pub fail_with: Mutex<Option<fn() -> EngineError>>,
}

impl Default for MockEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MockEngine {
    pub fn new() -> Self {
        Self {
            sign_calls: AtomicUsize::new(0),
            fail_with: Mutex::new(None),
        }
    }

    pub fn fail_next(&self, f: fn() -> EngineError) {
        *self.fail_with.lock().unwrap() = Some(f);
    }
}

#[async_trait::async_trait]
impl SigningEngine for MockEngine {
    async fn sign(&self, _req: &EngineSignRequest) -> Result<EngineSignature, EngineError> {
        self.sign_calls.fetch_add(1, Ordering::SeqCst);
        if let Some(f) = self.fail_with.lock().unwrap().take() {
            return Err(f());
        }
        Ok(EngineSignature {
            signature: vec![0xAA; 64],
            public_key: vec![0xBB; 33],
        })
    }
    async fn dkg(&self, params: &DkgParams) -> Result<DkgOutcome, EngineError> {
        Ok(DkgOutcome {
            key_id: KeyId(format!("mock-{}", params.chain.as_str())),
            public_key: vec![0xBB; 33],
        })
    }
    async fn rotate_key(&self, key_id: &KeyId) -> Result<RotateOutcome, EngineError> {
        Ok(RotateOutcome {
            key_id: key_id.clone(),
            public_key: vec![0xBB; 33],
            epoch: 2,
        })
    }
    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata, EngineError> {
        Ok(KeyMetadata {
            key_id: key_id.clone(),
            chain: Chain::Evm,
            public_key: vec![0xBB; 33],
            status: KeyShareStatus::Active,
            epoch: 1,
        })
    }
    async fn restore_share(&self, params: &RestoreParams) -> Result<bool, EngineError> {
        if params.quorum_proof.is_empty() {
            return Err(EngineError::Denied("quorum proof required".into()));
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_refuses_everything() {
        let e = NoopEngine;
        let req = EngineSignRequest {
            key_id: KeyId("k".into()),
            chain: Chain::Evm,
            payload: vec![1],
        };
        assert!(matches!(
            e.sign(&req).await.unwrap_err(),
            EngineError::Unsupported(_)
        ));
        assert!(e
            .dkg(&DkgParams {
                chain: Chain::Evm,
                threshold: 2,
                parties: 3
            })
            .await
            .is_err());
        assert!(e.rotate_key(&KeyId("k".into())).await.is_err());
        assert!(e.get_key_metadata(&KeyId("k".into())).await.is_err());
        assert!(e
            .restore_share(&RestoreParams {
                key_id: KeyId("k".into()),
                node_id: "n".into(),
                quorum_proof: vec![],
            })
            .await
            .is_err());
    }

    #[tokio::test]
    async fn mock_counts_calls_and_can_fail() {
        let e = MockEngine::new();
        let req = EngineSignRequest {
            key_id: KeyId("k".into()),
            chain: Chain::Evm,
            payload: vec![1],
        };
        e.sign(&req).await.unwrap();
        assert_eq!(e.sign_calls.load(Ordering::SeqCst), 1);
        e.fail_next(|| EngineError::ProviderUnavailable("down".into()));
        assert!(e.sign(&req).await.is_err());
        assert_eq!(e.sign_calls.load(Ordering::SeqCst), 2);
    }
}
