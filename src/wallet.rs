//! Wallet Management integration (Stage 4).
//!
//! Resolves `wallet_id` → active `key_id`s before signing and cross-checks
//! the request's `key_id` against Wallet Management's records. The sign path
//! fails closed when Wallet Management is unavailable.
//!
//! Wire note: wallet-management serves gRPC with a JSON codec
//! (`grpc.ForceServerCodec(jsonCodec{})` on plain Go structs), so this client
//! sends JSON-encoded gRPC frames to `/wallet.WalletService/ResolveKeyID`
//! rather than protobuf.

use serde::{Deserialize, Serialize};

/// Active key material bound to a wallet, per Wallet Management.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WalletKeyRecord {
    /// All key ids currently resolvable (current + cooling during rotation).
    #[serde(default)]
    pub key_ids: Vec<String>,
    /// The `current` key id.
    #[serde(default)]
    pub current_key_id: String,
}

/// Errors from wallet resolution. The sign path treats every variant as a
/// hard stop (fail closed).
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("wallet management unavailable: {0}")]
    Unavailable(String),
    #[error("wallet not found or has no bound key")]
    NotFound,
    #[error("key_id is not bound to the wallet")]
    KeyMismatch,
}

/// Client boundary for Wallet Management.
#[async_trait::async_trait]
pub trait WalletManagementClient: Send + Sync {
    /// Resolve the active key record for `wallet_id`.
    async fn resolve_keys(&self, wallet_id: &str) -> Result<WalletKeyRecord, WalletError>;

    /// Resolve and cross-check that `key_id` is bound to `wallet_id`.
    async fn check_key_binding(
        &self,
        wallet_id: &str,
        key_id: &str,
    ) -> Result<WalletKeyRecord, WalletError> {
        let rec = self.resolve_keys(wallet_id).await?;
        if rec.key_ids.is_empty() && rec.current_key_id.is_empty() {
            return Err(WalletError::NotFound);
        }
        if rec.current_key_id != key_id && !rec.key_ids.iter().any(|k| k == key_id) {
            return Err(WalletError::KeyMismatch);
        }
        Ok(rec)
    }
}

/// JSON-codec gRPC request to wallet-management.
#[derive(Debug, Serialize)]
struct ResolveKeyIdRequest {
    wallet_id: String,
}

/// gRPC client speaking wallet-management's JSON codec.
pub struct GrpcWalletClient {
    channel: tonic::transport::Channel,
}

impl GrpcWalletClient {
    /// `url` like `http://wallet-management:9090`.
    pub async fn connect(url: &str) -> Result<Self, WalletError> {
        let channel = tonic::transport::Channel::from_shared(url.to_string())
            .map_err(|e| WalletError::Unavailable(e.to_string()))?
            .connect_timeout(std::time::Duration::from_secs(3))
            .timeout(std::time::Duration::from_secs(5))
            .connect_lazy();
        Ok(Self { channel })
    }
}

#[async_trait::async_trait]
impl WalletManagementClient for GrpcWalletClient {
    async fn resolve_keys(&self, wallet_id: &str) -> Result<WalletKeyRecord, WalletError> {
        let mut grpc = tonic::client::Grpc::new(self.channel.clone());
        grpc.ready()
            .await
            .map_err(|e| WalletError::Unavailable(e.to_string()))?;
        let path = http::uri::PathAndQuery::from_static("/wallet.WalletService/ResolveKeyID");
        let req = tonic::Request::new(ResolveKeyIdRequest {
            wallet_id: wallet_id.to_string(),
        });
        let resp: tonic::Response<WalletKeyRecord> = grpc
            .unary(req, path, crate::grpc::json_codec::JsonCodec::default())
            .await
            .map_err(|status| match status.code() {
                tonic::Code::NotFound => WalletError::NotFound,
                _ => WalletError::Unavailable(status.to_string()),
            })?;
        Ok(resp.into_inner())
    }
}

/// In-memory mock for tests: maps wallet_id → record, or errors.
#[derive(Default)]
pub struct MockWalletClient {
    records: std::sync::RwLock<std::collections::HashMap<String, WalletKeyRecord>>,
    outage: std::sync::atomic::AtomicBool,
}

impl MockWalletClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind(&self, wallet_id: &str, key_ids: &[&str], current: &str) {
        self.records.write().unwrap().insert(
            wallet_id.to_string(),
            WalletKeyRecord {
                key_ids: key_ids.iter().map(|s| s.to_string()).collect(),
                current_key_id: current.to_string(),
            },
        );
    }

    pub fn set_outage(&self, down: bool) {
        self.outage.store(down, std::sync::atomic::Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl WalletManagementClient for MockWalletClient {
    async fn resolve_keys(&self, wallet_id: &str) -> Result<WalletKeyRecord, WalletError> {
        if self.outage.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(WalletError::Unavailable("mock outage".into()));
        }
        self.records
            .read()
            .unwrap()
            .get(wallet_id)
            .cloned()
            .ok_or(WalletError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binding_check_accepts_current_key() {
        let mock = MockWalletClient::new();
        mock.bind("w1", &["k1"], "k1");
        let rec = mock.check_key_binding("w1", "k1").await.unwrap();
        assert_eq!(rec.current_key_id, "k1");
    }

    #[tokio::test]
    async fn binding_check_accepts_cooling_key() {
        let mock = MockWalletClient::new();
        mock.bind("w1", &["k-old", "k-new"], "k-new");
        // during rotation cooling both keys resolve
        mock.check_key_binding("w1", "k-old").await.unwrap();
        mock.check_key_binding("w1", "k-new").await.unwrap();
    }

    #[tokio::test]
    async fn binding_check_rejects_unbound_key() {
        let mock = MockWalletClient::new();
        mock.bind("w1", &["k1"], "k1");
        assert!(matches!(
            mock.check_key_binding("w1", "other").await.unwrap_err(),
            WalletError::KeyMismatch
        ));
    }

    #[tokio::test]
    async fn unknown_wallet_rejected() {
        let mock = MockWalletClient::new();
        assert!(matches!(
            mock.check_key_binding("nope", "k1").await.unwrap_err(),
            WalletError::NotFound
        ));
    }

    #[tokio::test]
    async fn outage_fails_closed() {
        let mock = MockWalletClient::new();
        mock.bind("w1", &["k1"], "k1");
        mock.set_outage(true);
        assert!(matches!(
            mock.check_key_binding("w1", "k1").await.unwrap_err(),
            WalletError::Unavailable(_)
        ));
    }

    #[tokio::test]
    async fn empty_record_treated_as_not_found() {
        let mock = MockWalletClient::new();
        mock.bind("w1", &[], "");
        assert!(matches!(
            mock.check_key_binding("w1", "k1").await.unwrap_err(),
            WalletError::NotFound
        ));
    }
}
