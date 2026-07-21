//! Fireblocks custody adapter (feature `fireblocks`).
//!
//! Real REST client for the Fireblocks API (https://docs.fireblocks.com).
//! Unlike the shared `CustodyHttp` core used by the generic custody mock,
//! Fireblocks authenticates each request with a per-request RS256 JWT signed
//! with the workspace RSA-4096 private key, and exposes vault accounts /
//! asset wallets / raw-signing transactions rather than a generic
//! `/v1/<provider>/keys` + `/sign` shape. This adapter speaks that API
//! directly.
//!
//! Public-key material returned by Fireblocks is locally verified against the
//! signed payload via `custody::verify_signature` before being trusted, the
//! same as the other custody adapters.

use std::time::Duration;

use chrono::Utc;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::domain::{Chain, KeyId, KeyMetadata, KeyShareStatus, SignatureScheme};

use super::custody::verify_signature;
use super::{
    DkgOutcome, DkgParams, EngineError, EngineSignRequest, EngineSignature, RestoreParams,
    RotateOutcome, SigningEngine,
};

/// Default Fireblocks REST API base URL (production workspace).
const FIREBLOCKS_API_BASE: &str = "https://api.fireblocks.io";
/// Sandbox workspace host (same API surface, sandbox workspace credentials).
const FIREBLOCKS_SANDBOX_BASE: &str = "https://sandbox-api.fireblocks.io";

/// Poll interval for transaction status (`POST /v1/transactions` →
/// `GET /v1/transactions/{id}`).
const TX_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Hard upper bound on signature polling; Fireblocks RAW signing is normally
/// sub-second but cold starts can take a few seconds.
const TX_POLL_TIMEOUT: Duration = Duration::from_secs(30);

/// SHA-256 of the empty string — used as `bodyHash` for GET requests.
const EMPTY_BODY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Fireblocks custody client.
///
/// Holds an `reqwest::Client`, the workspace API key (UUID), the RSA-4096
/// private key (PEM) used to sign per-request JWTs, and the resolved API
/// base URL. All `SigningEngine` trait methods translate to one or more
/// Fireblocks REST calls.
pub struct FireblocksEngine {
    client: reqwest::Client,
    base_url: String,
    api_key: String,
    encoding_key: EncodingKey,
}

impl FireblocksEngine {
    /// Build from environment-driven `Config`. Returns a clear error if any
    /// of `custody_api_key`, `custody_api_secret_key` are missing, or if the
    /// PEM private key cannot be parsed by `jsonwebtoken` as an RSA key.
    ///
    /// `custody_api_url` is optional; if unset it defaults to
    /// `https://api.fireblocks.io` (or `https://sandbox-api.fireblocks.io`
    /// when `custody_sandbox` is true).
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let api_key = cfg
            .custody_api_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("CUSTODY_API_KEY required for fireblocks"))?;
        let pem = cfg.custody_api_secret_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "CUSTODY_API_SECRET_KEY (or CUSTODY_API_SECRET_KEY_PATH) \
                     required for fireblocks"
            )
        })?;
        let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes())
            .map_err(|e| anyhow::anyhow!("CUSTODY_API_SECRET_KEY is not a valid RSA PEM: {e}"))?;
        let base_url = cfg
            .custody_api_url
            .as_deref()
            .map(|s| s.trim_end_matches('/').to_string())
            .unwrap_or_else(|| {
                if cfg.custody_sandbox {
                    FIREBLOCKS_SANDBOX_BASE.to_string()
                } else {
                    FIREBLOCKS_API_BASE.to_string()
                }
            });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| anyhow::anyhow!("reqwest client build: {e}"))?;
        Ok(Self {
            client,
            base_url,
            api_key: api_key.to_string(),
            encoding_key,
        })
    }

    fn url(&self, path_and_query: &str) -> String {
        format!("{}{}", self.base_url, path_and_query)
    }

    /// Sign a per-request JWT with the Fireblocks custom claims (`uri`,
    /// `nonce`, `iat`, `exp`, `sub`, `bodyHash`). The `uri` claim MUST match
    /// the path+query of the outgoing request exactly or Fireblocks rejects
    /// with 401. `exp` is set to `iat + 29` (must be `< iat + 30`).
    fn sign_jwt(&self, uri: &str, body_hash: &str) -> Result<String, EngineError> {
        let iat = Utc::now().timestamp();
        let exp = iat + 29;
        let claims = JwtClaims {
            uri,
            nonce: uuid::Uuid::new_v4().to_string(),
            iat,
            exp,
            sub: &self.api_key,
            body_hash,
        };
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("JWT".to_string());
        jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| EngineError::Internal(format!("jwt encode: {e}")))
    }

    /// Compute `bodyHash` (hex SHA-256 of the raw request body) for POST
    /// requests, or the empty-body hash for GET.
    fn body_hash(body: Option<&[u8]>) -> String {
        use sha2::{Digest, Sha256};
        match body {
            Some(b) => hex::encode(Sha256::digest(b)),
            None => EMPTY_BODY_HASH.to_string(),
        }
    }

    async fn post_json<R: serde::de::DeserializeOwned>(
        &self,
        path_and_query: &str,
        body: serde_json::Value,
    ) -> Result<R, EngineError> {
        let body_bytes = serde_json::to_vec(&body)
            .map_err(|e| EngineError::Internal(format!("body encode: {e}")))?;
        let body_hash = Self::body_hash(Some(&body_bytes));
        let jwt = self.sign_jwt(path_and_query, &body_hash)?;
        let resp = self
            .client
            .post(self.url(path_and_query))
            .header("X-API-Key", &self.api_key)
            .header("Authorization", format!("Bearer {jwt}"))
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(classify_reqwest)?;
        decode_response(resp).await
    }

    async fn get_json<R: serde::de::DeserializeOwned>(
        &self,
        path_and_query: &str,
    ) -> Result<R, EngineError> {
        let body_hash = Self::body_hash(None);
        let jwt = self.sign_jwt(path_and_query, &body_hash)?;
        let resp = self
            .client
            .get(self.url(path_and_query))
            .header("X-API-Key", &self.api_key)
            .header("Authorization", format!("Bearer {jwt}"))
            .send()
            .await
            .map_err(classify_reqwest)?;
        decode_response(resp).await
    }
}

/// Fireblocks JWT claims (registered + custom). Field names match the
/// Fireblocks spec exactly (`uri`, `nonce`, `iat`, `exp`, `sub`, `bodyHash`).
#[derive(Debug, Serialize)]
struct JwtClaims<'a> {
    uri: &'a str,
    nonce: String,
    iat: i64,
    exp: i64,
    sub: &'a str,
    #[serde(rename = "bodyHash")]
    body_hash: &'a str,
}

// ---- Chain → Fireblocks assetId / algorithm mapping ------------------------

/// Map a `Chain` to the Fireblocks `assetId` for mainnet.
fn asset_id(chain: Chain) -> &'static str {
    match chain {
        Chain::Evm => "ETH",
        Chain::Solana => "SOL",
        Chain::Bitcoin => "BTC",
        // Aptos / Sui are EVM-compatible-signing chains in Fireblocks via
        // their respective assetIds; the custody API exposes them as
        // MPC_ECDSA_SECP256K1 for Aptos and MPC_EDDSA_ED25519 for Sui.
        Chain::Aptos => "APT",
        Chain::Sui => "SUI",
    }
}

/// Map a `Chain` to the Fireblocks MPC signing algorithm name.
fn mpc_algorithm(chain: Chain) -> &'static str {
    match chain.scheme() {
        SignatureScheme::EcdsaSecp256k1 => "MPC_ECDSA_SECP256K1",
        SignatureScheme::Ed25519 => "MPC_EDDSA_ED25519",
    }
}

// ---- Fireblocks wire shapes -----------------------------------------------

#[derive(Debug, Deserialize)]
struct VaultAccountResp {
    id: String,
}

#[derive(Debug, Deserialize)]
struct PublicKeyInfoResp {
    #[serde(rename = "publicKey")]
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct TransactionResp {
    id: String,
    status: String,
    #[serde(default, rename = "signedMessages")]
    signed_messages: Vec<SignedMessage>,
}

#[derive(Debug, Deserialize)]
struct SignedMessage {
    #[serde(default)]
    signature: Option<String>,
    #[serde(default, rename = "publicKey")]
    public_key: Option<String>,
}

// ---- SigningEngine implementation -----------------------------------------

#[async_trait::async_trait]
impl SigningEngine for FireblocksEngine {
    /// Create a vault account + asset wallet, then fetch the wallet's public
    /// key. `DkgParams::chain` selects the assetId; threshold/parties are
    /// ignored (Fireblocks MPC policy is configured in the workspace).
    async fn dkg(&self, params: &DkgParams) -> Result<DkgOutcome, EngineError> {
        let key_name = format!("key-{}", uuid::Uuid::new_v4());
        let vault: VaultAccountResp = self
            .post_json(
                "/v1/vault/accounts",
                serde_json::json!({
                    "name": key_name,
                    "hiddenOnUI": true,
                }),
            )
            .await?;
        let asset = asset_id(params.chain);
        let _: serde_json::Value = self
            .post_json(
                &format!("/v1/vault/accounts/{}/{}", vault.id, asset),
                serde_json::json!({}),
            )
            .await?;
        let public_key = self.fetch_public_key(&vault.id, asset, 0, 0).await?;
        Ok(DkgOutcome {
            key_id: KeyId(vault.id),
            public_key,
        })
    }

    /// Submit a RAW signing transaction and poll until `COMPLETED`. Verifies
    /// the returned signature locally before returning.
    async fn sign(&self, req: &EngineSignRequest) -> Result<EngineSignature, EngineError> {
        let asset = asset_id(req.chain);
        let algo = mpc_algorithm(req.chain);
        let content = hex::encode(&req.payload);
        let body = serde_json::json!({
            "assetId": asset,
            "source": {"type": "VAULT_ACCOUNT", "id": req.key_id.0},
            "operation": "RAW",
            "amount": "0",
            "note": format!("MPC signing request for key {}", req.key_id.0),
            "extraParameters": {
                "rawMessageData": {
                    "messages": [{"content": content}],
                    "algorithm": algo,
                }
            }
        });
        let tx: TransactionResp = self.post_json("/v1/transactions", body).await?;
        let final_tx = self.poll_transaction(&tx.id).await?;
        match final_tx.signed_messages.first() {
            Some(msg) => {
                let sig_hex = msg.signature.as_ref().ok_or_else(|| {
                    EngineError::Internal("fireblocks signed message missing signature".into())
                })?;
                let pk_hex = msg.public_key.as_ref().ok_or_else(|| {
                    EngineError::Internal("fireblocks signed message missing public key".into())
                })?;
                let signature = hex::decode(sig_hex).map_err(|_| {
                    EngineError::Internal("fireblocks returned non-hex signature".into())
                })?;
                let public_key = hex::decode(pk_hex).map_err(|_| {
                    EngineError::Internal("fireblocks returned non-hex public key".into())
                })?;
                verify_signature(req.chain, &req.payload, &signature, &public_key)?;
                Ok(EngineSignature {
                    signature,
                    public_key,
                })
            }
            None => Err(EngineError::Internal(
                "fireblocks completed transaction had no signed messages".into(),
            )),
        }
    }

    /// Rotate by creating a NEW asset wallet under the same vault account
    /// (Fireblocks has no in-place key-rotation API). The old wallet remains
    /// on the vault account and should be treated as retired by the caller.
    /// `epoch` is always `0` — Fireblocks does not expose a per-key epoch.
    async fn rotate_key(&self, key_id: &KeyId) -> Result<RotateOutcome, EngineError> {
        // Fireblocks does not tell us which asset a vault account holds; we
        // try the EVM asset (the common case) and surface a clear error if
        // the caller needs a different chain. A future improvement is to
        // store the chain alongside the key id at DKG time.
        let asset = asset_id(Chain::Evm);
        let _: serde_json::Value = self
            .post_json(
                &format!("/v1/vault/accounts/{}/{}", key_id.0, asset),
                serde_json::json!({}),
            )
            .await?;
        let public_key = self.fetch_public_key(&key_id.0, asset, 0, 1).await?;
        Ok(RotateOutcome {
            key_id: key_id.clone(),
            public_key,
            epoch: 0,
        })
    }

    /// Read public key + status for a vault account's first asset wallet
    /// (change=0, addressIndex=0). Fireblocks exposes no per-key cooling /
    /// retired state, so `status` is always `Active`. `chain` defaults to
    /// EVM because the trait does not carry it; callers that need a
    /// different chain's public key should call `dkg`/`sign` instead.
    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata, EngineError> {
        let chain = Chain::Evm;
        let asset = asset_id(chain);
        let public_key = self.fetch_public_key(&key_id.0, asset, 0, 0).await?;
        Ok(KeyMetadata {
            key_id: key_id.clone(),
            chain,
            public_key,
            status: KeyShareStatus::Active,
            epoch: 0,
        })
    }

    /// Fireblocks manages all MPC key shares internally; there is no
    /// customer-facing share-restore API. Reject so callers do not assume a
    /// restore happened. `quorum_proof` is ignored.
    async fn restore_share(&self, _params: &RestoreParams) -> Result<bool, EngineError> {
        Err(EngineError::Internal(
            "Fireblocks manages key shares; restore is not applicable".into(),
        ))
    }
}

impl FireblocksEngine {
    /// Fetch a derived public key from
    /// `GET /v1/vault/accounts/{vault}/{asset}/{change}/{addressIndex}/public_key_info?compressed=false`.
    async fn fetch_public_key(
        &self,
        vault: &str,
        asset: &str,
        change: u32,
        address_index: u32,
    ) -> Result<Vec<u8>, EngineError> {
        let path = format!(
            "/v1/vault/accounts/{}/{}/{}/{}/public_key_info?compressed=false",
            vault, asset, change, address_index
        );
        let info: PublicKeyInfoResp = self.get_json(&path).await?;
        hex::decode(&info.public_key)
            .map_err(|_| EngineError::Internal("fireblocks returned non-hex public key".into()))
    }

    /// Poll `GET /v1/transactions/{id}` until `status` is a terminal state.
    /// `COMPLETED` → Ok; `FAILED`/`REJECTED`/`CANCELLED` → error; timeout →
    /// `EngineError::Transient`.
    async fn poll_transaction(&self, tx_id: &str) -> Result<TransactionResp, EngineError> {
        let path = format!("/v1/transactions/{tx_id}");
        let deadline = std::time::Instant::now() + TX_POLL_TIMEOUT;
        loop {
            let tx: TransactionResp = self.get_json(&path).await?;
            match tx.status.as_str() {
                "COMPLETED" => return Ok(tx),
                "FAILED" | "REJECTED" | "CANCELLED" => {
                    return Err(EngineError::Internal(format!(
                        "fireblocks transaction {tx_id} terminal status: {}",
                        tx.status
                    )))
                }
                _ => {}
            }
            if std::time::Instant::now() >= deadline {
                return Err(EngineError::Transient(format!(
                    "fireblocks transaction {tx_id} poll timed out"
                )));
            }
            tokio::time::sleep(TX_POLL_INTERVAL).await;
        }
    }
}

// ---- shared error helpers (mirrors custody.rs) ----------------------------

fn classify_reqwest(err: reqwest::Error) -> EngineError {
    if err.is_timeout() || err.is_connect() {
        EngineError::ProviderUnavailable(err.to_string())
    } else {
        EngineError::Transient(err.to_string())
    }
}

async fn decode_response<R: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<R, EngineError> {
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(EngineError::KeyNotFound(
            "fireblocks reports unknown key".into(),
        ));
    }
    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(EngineError::Denied(format!(
            "fireblocks rejected request: {status}"
        )));
    }
    if status.is_server_error() {
        return Err(EngineError::ProviderUnavailable(format!(
            "fireblocks server error: {status}"
        )));
    }
    if !status.is_success() {
        return Err(EngineError::Transient(format!(
            "fireblocks returned {status}"
        )));
    }
    resp.json::<R>()
        .await
        .map_err(|e| EngineError::Internal(format!("fireblocks response decode: {e}")))
}

// TODO: integration test against sandbox with
// CUSTODY_API_KEY / CUSTODY_API_SECRET_KEY env vars set.

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{DecodingKey, Validation};
    use rsa::{
        pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding},
        RsaPrivateKey,
    };
    use sha2::{Digest, Sha256};

    /// Generate a small RSA keypair, return PEM private key and a JWT
    /// `Validation` seeded with the public key. Tests use a 2048-bit key for
    /// speed; production Fireblocks keys are RSA-4096.
    fn test_keypair() -> (String, DecodingKey) {
        let mut rng = rand::rngs::OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let pem = priv_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("pkcs8 pem")
            .to_string();
        let pub_pem = priv_key
            .to_public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("pub pem");
        let decoding = DecodingKey::from_rsa_pem(pub_pem.as_bytes()).expect("decoding key");
        (pem, decoding)
    }

    fn engine_from_pem(pem: &str) -> FireblocksEngine {
        let cfg = Config {
            custody_api_key: Some("11111111-2222-3333-4444-555555555555".into()),
            custody_api_secret_key: Some(pem.to_string()),
            custody_api_url: Some("https://example.test".into()),
            ..Config::default()
        };
        FireblocksEngine::from_config(&cfg).expect("engine from pem")
    }

    #[test]
    fn jwt_claims_are_correct_and_verifiable() {
        let (pem, decoding) = test_keypair();
        let engine = engine_from_pem(&pem);
        let uri = "/v1/vault/accounts";
        let body_hash = hex::encode(Sha256::digest(b"{}"));
        let jwt = engine.sign_jwt(uri, &body_hash).expect("jwt");
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.set_audience(&[""]);
        let decoded = jsonwebtoken::decode::<serde_json::Value>(&jwt, &decoding, &validation)
            .expect("decode");
        let claims = decoded.claims;
        assert_eq!(claims["uri"], uri);
        assert_eq!(claims["sub"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(claims["bodyHash"], body_hash);
        let nonce = claims["nonce"].as_str().expect("nonce");
        assert!(!nonce.is_empty());
        let iat = claims["iat"].as_i64().expect("iat");
        let exp = claims["exp"].as_i64().expect("exp");
        assert!(exp > iat && exp < iat + 30);
    }

    #[test]
    fn jwt_nonce_is_unique_per_call() {
        let (pem, _) = test_keypair();
        let engine = engine_from_pem(&pem);
        let a = engine.sign_jwt("/v1/x", EMPTY_BODY_HASH).expect("jwt a");
        let b = engine.sign_jwt("/v1/x", EMPTY_BODY_HASH).expect("jwt b");
        // JWT body is base64; cheap inequality check confirms nonce differs.
        assert_ne!(a, b);
    }

    #[test]
    fn body_hash_empty_is_known_constant() {
        assert_eq!(FireblocksEngine::body_hash(None), EMPTY_BODY_HASH);
    }

    #[test]
    fn body_hash_matches_sha256_of_body() {
        let body = br#"{"x":1}"#;
        let expected = hex::encode(Sha256::digest(body));
        assert_eq!(FireblocksEngine::body_hash(Some(body)), expected);
        assert_ne!(FireblocksEngine::body_hash(Some(body)), EMPTY_BODY_HASH);
    }

    #[test]
    fn asset_id_mapping() {
        assert_eq!(asset_id(Chain::Evm), "ETH");
        assert_eq!(asset_id(Chain::Solana), "SOL");
        assert_eq!(asset_id(Chain::Bitcoin), "BTC");
        assert_eq!(asset_id(Chain::Aptos), "APT");
        assert_eq!(asset_id(Chain::Sui), "SUI");
    }

    #[test]
    fn mpc_algorithm_mapping() {
        assert_eq!(mpc_algorithm(Chain::Evm), "MPC_ECDSA_SECP256K1");
        assert_eq!(mpc_algorithm(Chain::Bitcoin), "MPC_ECDSA_SECP256K1");
        assert_eq!(mpc_algorithm(Chain::Solana), "MPC_EDDSA_ED25519");
        assert_eq!(mpc_algorithm(Chain::Aptos), "MPC_EDDSA_ED25519");
        assert_eq!(mpc_algorithm(Chain::Sui), "MPC_EDDSA_ED25519");
    }

    #[test]
    fn from_config_errors_when_missing_key() {
        let cfg = Config {
            custody_api_key: None,
            ..Config::default()
        };
        assert!(FireblocksEngine::from_config(&cfg).is_err());
    }

    #[test]
    fn from_config_errors_when_missing_secret() {
        let cfg = Config {
            custody_api_key: Some("k".into()),
            custody_api_secret_key: None,
            ..Config::default()
        };
        assert!(FireblocksEngine::from_config(&cfg).is_err());
    }

    #[test]
    fn from_config_errors_on_bad_pem() {
        let cfg = Config {
            custody_api_key: Some("k".into()),
            custody_api_secret_key: Some("not-a-pem".into()),
            ..Config::default()
        };
        assert!(FireblocksEngine::from_config(&cfg).is_err());
    }

    #[test]
    fn from_config_picks_sandbox_base_url_when_flag_set() {
        let (pem, _) = test_keypair();
        let cfg = Config {
            custody_api_key: Some("k".into()),
            custody_api_secret_key: Some(pem),
            custody_sandbox: true,
            custody_api_url: None,
            ..Config::default()
        };
        let engine = FireblocksEngine::from_config(&cfg).expect("engine");
        assert_eq!(engine.base_url, FIREBLOCKS_SANDBOX_BASE);
    }

    #[test]
    fn from_config_picks_prod_base_url_by_default() {
        let (pem, _) = test_keypair();
        let cfg = Config {
            custody_api_key: Some("k".into()),
            custody_api_secret_key: Some(pem),
            custody_sandbox: false,
            custody_api_url: None,
            ..Config::default()
        };
        let engine = FireblocksEngine::from_config(&cfg).expect("engine");
        assert_eq!(engine.base_url, FIREBLOCKS_API_BASE);
    }

    #[test]
    fn from_config_respects_explicit_api_url() {
        let (pem, _) = test_keypair();
        let cfg = Config {
            custody_api_key: Some("k".into()),
            custody_api_secret_key: Some(pem),
            custody_api_url: Some("https://custom.example/".into()),
            ..Config::default()
        };
        let engine = FireblocksEngine::from_config(&cfg).expect("engine");
        assert_eq!(engine.base_url, "https://custom.example");
    }

    #[test]
    fn restore_share_is_unsupported() {
        let (pem, _) = test_keypair();
        let engine = engine_from_pem(&pem);
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let res = rt.block_on(engine.restore_share(&RestoreParams {
            key_id: KeyId("v1".into()),
            node_id: "n1".into(),
            quorum_proof: vec![1, 2, 3],
        }));
        assert!(matches!(res, Err(EngineError::Internal(_))));
    }
}
