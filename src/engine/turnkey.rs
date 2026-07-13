//! Turnkey custody adapter (feature `turnkey`).

use crate::config::Config;
use crate::domain::{Chain, KeyId, KeyMetadata};

use super::custody::{CustodyHttp, ProviderProfile};
use super::{
    DkgOutcome, DkgParams, EngineError, EngineSignRequest, EngineSignature, RestoreParams,
    RotateOutcome, SigningEngine,
};

pub struct TurnkeyEngine {
    http: CustodyHttp,
}

impl TurnkeyEngine {
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let url = cfg
            .custody_api_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("CUSTODY_API_URL required for turnkey"))?;
        let key = cfg
            .custody_api_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("CUSTODY_API_KEY required for turnkey"))?;
        Ok(Self {
            http: CustodyHttp::new(
                ProviderProfile {
                    name: "turnkey",
                    auth_header: "X-API-Key",
                    auth_prefix: "",
                },
                url,
                key,
            ),
        })
    }
}

#[async_trait::async_trait]
impl SigningEngine for TurnkeyEngine {
    async fn sign(&self, req: &EngineSignRequest) -> Result<EngineSignature, EngineError> {
        self.http.sign(req).await
    }
    async fn dkg(&self, params: &DkgParams) -> Result<DkgOutcome, EngineError> {
        self.http.dkg(params).await
    }
    async fn rotate_key(&self, key_id: &KeyId) -> Result<RotateOutcome, EngineError> {
        self.http.rotate(key_id).await
    }
    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata, EngineError> {
        self.http.key_metadata(key_id, Chain::Evm).await
    }
    async fn restore_share(&self, params: &RestoreParams) -> Result<bool, EngineError> {
        self.http.restore(params).await
    }
}
