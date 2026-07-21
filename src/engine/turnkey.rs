//! Turnkey custody adapter (feature `turnkey`).
//!
//! Implements the `SigningEngine` trait against Turnkey's POST-only RPC API.
//! Authentication uses stamp-based request signing (secp256k1 over SHA-256 of
//! the JSON body), sent in the `X-Stamp` header as base64url-encoded JSON.
//! See https://docs.turnkey.com/api-reference/overview/stamps.
//!
//! Wallets map 1:1 to our `KeyId`; Turnkey has no key-rotation primitive, so
//! `rotate_key` creates a fresh wallet with a `-rotated` name suffix.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::warn;

use crate::config::Config;
use crate::domain::{Chain, KeyId, KeyMetadata, KeyShareStatus, SignatureScheme};

use super::custody::verify_signature;
use super::{
    DkgOutcome, DkgParams, EngineError, EngineSignRequest, EngineSignature, RestoreParams,
    RotateOutcome, SigningEngine,
};

const DEFAULT_API_BASE: &str = "https://api.turnkey.com";
const COMPLETED: &str = "ACTIVITY_STATUS_COMPLETED";
const FAILED: &str = "ACTIVITY_STATUS_FAILED";

/// Turnkey custody engine.
pub struct TurnkeyEngine {
    base_url: String,
    organization_id: String,
    sub_organization_id: Option<String>,
    api_public_key: String,
    api_private_key: k256::ecdsa::SigningKey,
    client: reqwest::Client,
}

impl TurnkeyEngine {
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let base_url = cfg
            .custody_api_url
            .as_deref()
            .map(str::to_string)
            .unwrap_or_else(|| DEFAULT_API_BASE.to_string());
        let organization_id = cfg
            .custody_organization_id
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("CUSTODY_ORGANIZATION_ID required for turnkey"))?;
        let api_public_key = cfg
            .custody_api_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("CUSTODY_API_KEY required for turnkey"))?;
        let api_private_key_hex = cfg
            .custody_api_private_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("CUSTODY_API_PRIVATE_KEY required for turnkey"))?;
        let api_private_key = parse_secp256k1_signing_key(api_private_key_hex)
            .map_err(|e| anyhow::anyhow!("invalid CUSTODY_API_PRIVATE_KEY: {e}"))?;
        let derived_pub = hex::encode(api_private_key.verifying_key().to_sec1_bytes());
        if !derived_pub.eq_ignore_ascii_case(api_public_key) {
            anyhow::bail!(
                "CUSTODY_API_KEY does not match the public key derived from CUSTODY_API_PRIVATE_KEY"
            );
        }
        Ok(Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            organization_id: organization_id.to_string(),
            sub_organization_id: cfg.custody_sub_organization_id.clone(),
            api_public_key: api_public_key.to_string(),
            api_private_key,
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .expect("reqwest client"),
        })
    }

    fn effective_org(&self) -> &str {
        self.sub_organization_id
            .as_deref()
            .unwrap_or(&self.organization_id)
    }

    async fn rpc<B: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        prefix: &str,
        endpoint: &str,
        body: &B,
    ) -> Result<R, EngineError> {
        let raw = serde_json::to_vec(body)
            .map_err(|e| EngineError::Internal(format!("body encode: {e}")))?;
        let stamp = stamp_request(&self.api_private_key, &self.api_public_key, &raw)?;
        let url = format!("{base}/public/v1/{prefix}/{endpoint}", base = self.base_url);
        let resp = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .header("X-Stamp", stamp)
            .body(raw)
            .send()
            .await
            .map_err(classify_reqwest)?;
        decode_response(resp).await
    }

    /// Submit an activity and, if the optimistic-sync response is not yet
    /// COMPLETED, poll `get_activity` until it is.
    async fn submit_and_wait<B: Serialize>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> Result<ActivityEnvelope, EngineError> {
        let env = self
            .rpc::<_, ActivityEnvelope>("submit", endpoint, body)
            .await?;
        if env.activity.status == COMPLETED {
            Ok(env)
        } else {
            self.poll_activity(&env.activity.id).await
        }
    }

    async fn query<B: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        body: &B,
    ) -> Result<R, EngineError> {
        self.rpc("query", endpoint, body).await
    }

    async fn poll_activity(&self, activity_id: &str) -> Result<ActivityEnvelope, EngineError> {
        let body = GetActivityBody {
            organization_id: self.effective_org().to_string(),
            activity_id: activity_id.to_string(),
        };
        for _ in 0..60 {
            let env: ActivityEnvelope = self.query("get_activity", &body).await?;
            match env.activity.status.as_str() {
                COMPLETED => return Ok(env),
                FAILED => {
                    return Err(EngineError::Internal(format!(
                        "turnkey activity {activity_id} failed"
                    )))
                }
                _ => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
        Err(EngineError::ProviderUnavailable(format!(
            "turnkey activity {activity_id} timed out"
        )))
    }

    fn chain_params(&self, chain: Chain) -> Result<(&'static str, &'static str), EngineError> {
        match chain.scheme() {
            SignatureScheme::EcdsaSecp256k1 => Ok(("CURVE_SECP256K1", "m/44'/60'/0'/0/0")),
            SignatureScheme::Ed25519 => Ok(("CURVE_ED25519", "m/44'/501'/0'/0'")),
        }
    }
}

fn parse_secp256k1_signing_key(
    hex_or_pem: &str,
) -> Result<k256::ecdsa::SigningKey, Box<dyn std::error::Error>> {
    let trimmed = hex_or_pem.trim();
    if trimmed.starts_with("-----BEGIN") {
        return Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "PEM-encoded secp256k1 keys are not supported; provide raw hex",
        )));
    }
    let bytes = hex::decode(trimmed).map_err(|e| format!("non-hex private key: {e}"))?;
    let sk = k256::ecdsa::SigningKey::from_slice(&bytes)
        .map_err(|e| format!("invalid secp256k1 private key: {e}"))?;
    Ok(sk)
}

/// Sign the SHA-256 hash of `body` with the API key and return the base64url-
/// encoded stamp envelope suitable for the `X-Stamp` header.
fn stamp_request(
    signing_key: &k256::ecdsa::SigningKey,
    public_key_hex: &str,
    body: &[u8],
) -> Result<String, EngineError> {
    use k256::ecdsa::signature::DigestSigner;
    let mut hasher = Sha256::new();
    hasher.update(body);
    let sig: k256::ecdsa::Signature = DigestSigner::sign_digest(signing_key, hasher);
    let der = sig.to_der().to_bytes();
    let envelope = StampEnvelope {
        public_key: public_key_hex.to_string(),
        signature: hex::encode(der),
        scheme: "SIGNATURE_SCHEME_TK_API_SECP256K1".to_string(),
    };
    let json = serde_json::to_vec(&envelope)
        .map_err(|e| EngineError::Internal(format!("stamp encode: {e}")))?;
    Ok(BASE64_URL.encode(json))
}

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
            "turnkey reports unknown key".into(),
        ));
    }
    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(EngineError::Denied(format!(
            "turnkey rejected request: {status}"
        )));
    }
    if status.is_server_error() {
        return Err(EngineError::ProviderUnavailable(format!(
            "turnkey error: {status}"
        )));
    }
    if !status.is_success() {
        return Err(EngineError::Transient(format!("turnkey returned {status}")));
    }
    resp.json::<R>()
        .await
        .map_err(|e| EngineError::Internal(format!("turnkey response decode: {e}")))
}

#[derive(Debug, Serialize)]
struct StampEnvelope {
    #[serde(rename = "publicKey")]
    public_key: String,
    signature: String,
    scheme: String,
}

#[derive(Debug, Deserialize)]
struct ActivityEnvelope {
    activity: Activity,
}

#[derive(Debug, Deserialize)]
struct Activity {
    id: String,
    status: String,
    #[serde(default)]
    result: Option<Value>,
}

#[derive(Debug, Serialize)]
struct CreateWalletBody {
    #[serde(rename = "type")]
    activity_type: String,
    #[serde(rename = "timestampMs")]
    timestamp_ms: String,
    #[serde(rename = "organizationId")]
    organization_id: String,
    parameters: CreateWalletParams,
}

#[derive(Debug, Serialize)]
struct CreateWalletParams {
    #[serde(rename = "walletName")]
    wallet_name: String,
    accounts: Vec<WalletAccountParams>,
}

#[derive(Debug, Serialize)]
struct WalletAccountParams {
    curve: &'static str,
    #[serde(rename = "pathFormat")]
    path_format: &'static str,
    path: &'static str,
    #[serde(rename = "addressFormat")]
    address_format: &'static str,
}

#[derive(Debug, Serialize)]
struct GetActivityBody {
    #[serde(rename = "organizationId")]
    organization_id: String,
    #[serde(rename = "activityId")]
    activity_id: String,
}

#[derive(Debug, Serialize)]
struct SignRawPayloadBody {
    #[serde(rename = "type")]
    activity_type: String,
    #[serde(rename = "timestampMs")]
    timestamp_ms: String,
    #[serde(rename = "organizationId")]
    organization_id: String,
    parameters: SignRawPayloadParams,
}

#[derive(Debug, Serialize)]
struct SignRawPayloadParams {
    #[serde(rename = "signWith")]
    sign_with: String,
    payload: String,
    encoding: &'static str,
    #[serde(rename = "hashFunction")]
    hash_function: &'static str,
}

#[derive(Debug, Serialize)]
struct GetWalletAccountBody {
    #[serde(rename = "organizationId")]
    organization_id: String,
    #[serde(rename = "walletId")]
    wallet_id: String,
}

#[derive(Debug, Deserialize)]
struct GetWalletAccountResp {
    account: WalletAccount,
}

#[derive(Debug, Deserialize)]
struct WalletAccount {
    address: String,
    #[serde(default, rename = "publicKey")]
    public_key: Option<String>,
    curve: String,
    #[allow(dead_code)]
    path: String,
}

#[async_trait::async_trait]
impl SigningEngine for TurnkeyEngine {
    async fn sign(&self, req: &EngineSignRequest) -> Result<EngineSignature, EngineError> {
        let account = self.fetch_wallet_account(&req.key_id).await?;
        let sign_with = account.address;
        let public_key = hex::decode(
            account
                .public_key
                .as_deref()
                .ok_or_else(|| EngineError::Internal("turnkey returned no public key".into()))?,
        )
        .map_err(|_| EngineError::Internal("turnkey returned non-hex public key".into()))?;

        let (encoding, hash_function) = match req.chain.scheme() {
            SignatureScheme::EcdsaSecp256k1 => {
                ("PAYLOAD_ENCODING_HEXADECIMAL", "HASH_FUNCTION_NO_OP")
            }
            SignatureScheme::Ed25519 => (
                "PAYLOAD_ENCODING_HEXADECIMAL",
                "HASH_FUNCTION_NOT_APPLICABLE",
            ),
        };
        let body = SignRawPayloadBody {
            activity_type: "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2".to_string(),
            timestamp_ms: timestamp_ms(),
            organization_id: self.effective_org().to_string(),
            parameters: SignRawPayloadParams {
                sign_with,
                payload: hex::encode(&req.payload),
                encoding,
                hash_function,
            },
        };
        let env = self.submit_and_wait("sign_raw_payload", &body).await?;
        let result = env;
        let r_s = extract_sign_raw_payload_result(&result)
            .ok_or_else(|| EngineError::Internal("turnkey missing signRawPayloadResult".into()))?;

        let signature = match req.chain.scheme() {
            SignatureScheme::EcdsaSecp256k1 => {
                let mut sig = Vec::with_capacity(64);
                sig.extend_from_slice(&r_s.r);
                sig.extend_from_slice(&r_s.s);
                sig
            }
            SignatureScheme::Ed25519 => {
                // Turnkey returns the raw 64-byte Ed25519 signature as the `r`
                // component (s is empty/unused). Concatenate defensively.
                let mut sig = Vec::with_capacity(64);
                sig.extend_from_slice(&r_s.r);
                if !r_s.s.is_empty() {
                    sig.extend_from_slice(&r_s.s);
                }
                sig
            }
        };

        verify_signature(req.chain, &req.payload, &signature, &public_key)?;
        Ok(EngineSignature {
            signature,
            public_key,
        })
    }

    async fn dkg(&self, params: &DkgParams) -> Result<DkgOutcome, EngineError> {
        let (curve, path) = self.chain_params(params.chain)?;
        let address_format = match params.chain.scheme() {
            SignatureScheme::EcdsaSecp256k1 => "ADDRESS_FORMAT_ETHEREUM",
            SignatureScheme::Ed25519 => "ADDRESS_FORMAT_SOLANA",
        };
        let body = CreateWalletBody {
            activity_type: "ACTIVITY_TYPE_CREATE_WALLET".to_string(),
            timestamp_ms: timestamp_ms(),
            organization_id: self.effective_org().to_string(),
            parameters: CreateWalletParams {
                wallet_name: format!("key-{}", uuid::Uuid::new_v4()),
                accounts: vec![WalletAccountParams {
                    curve,
                    path_format: "PATH_FORMAT_BIP32",
                    path,
                    address_format,
                }],
            },
        };
        let env = self.submit_and_wait("create_wallet", &body).await?;
        let result = env;
        let (wallet_id, address) = extract_create_wallet_result(&result)
            .ok_or_else(|| EngineError::Internal("turnkey missing createWalletResult".into()))?;

        let public_key = self.fetch_public_key(&wallet_id, &address).await?;
        Ok(DkgOutcome {
            key_id: KeyId(wallet_id),
            public_key,
        })
    }

    async fn rotate_key(&self, _key_id: &KeyId) -> Result<RotateOutcome, EngineError> {
        // Turnkey exposes no key-rotation primitive; create a fresh wallet
        // with a `-rotated` name suffix and return its key id.
        warn!("turnkey rotate_key creates a new wallet (no native rotation)");
        let chain = Chain::Evm;
        let (curve, path) = self.chain_params(chain)?;
        let body = CreateWalletBody {
            activity_type: "ACTIVITY_TYPE_CREATE_WALLET".to_string(),
            timestamp_ms: timestamp_ms(),
            organization_id: self.effective_org().to_string(),
            parameters: CreateWalletParams {
                wallet_name: format!("key-{}-rotated", uuid::Uuid::new_v4()),
                accounts: vec![WalletAccountParams {
                    curve,
                    path_format: "PATH_FORMAT_BIP32",
                    path,
                    address_format: "ADDRESS_FORMAT_ETHEREUM",
                }],
            },
        };
        let env = self.submit_and_wait("create_wallet", &body).await?;
        let result = env;
        let (wallet_id, address) = extract_create_wallet_result(&result)
            .ok_or_else(|| EngineError::Internal("turnkey missing createWalletResult".into()))?;
        let public_key = self.fetch_public_key(&wallet_id, &address).await?;
        Ok(RotateOutcome {
            key_id: KeyId(wallet_id),
            public_key,
            epoch: 0,
        })
    }

    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata, EngineError> {
        let account = self.fetch_wallet_account(key_id).await?;
        let public_key = hex::decode(
            account
                .public_key
                .as_deref()
                .ok_or_else(|| EngineError::Internal("turnkey returned no public key".into()))?,
        )
        .map_err(|_| EngineError::Internal("turnkey returned non-hex public key".into()))?;
        let chain = match account.curve.as_str() {
            "CURVE_SECP256K1" => Chain::Evm,
            "CURVE_ED25519" => Chain::Solana,
            other => {
                return Err(EngineError::Unsupported(format!(
                    "turnkey curve {other} not mapped"
                )))
            }
        };
        Ok(KeyMetadata {
            key_id: key_id.clone(),
            chain,
            public_key,
            status: KeyShareStatus::Active,
            epoch: 0,
        })
    }

    async fn restore_share(&self, _params: &RestoreParams) -> Result<bool, EngineError> {
        Err(EngineError::Unsupported(
            "Turnkey manages key shares in enclaves; restore is not applicable".into(),
        ))
    }
}

impl TurnkeyEngine {
    async fn fetch_wallet_account(&self, key_id: &KeyId) -> Result<WalletAccount, EngineError> {
        let body = GetWalletAccountBody {
            organization_id: self.effective_org().to_string(),
            wallet_id: key_id.0.clone(),
        };
        let resp: GetWalletAccountResp = self.query("get_wallet_account", &body).await?;
        Ok(resp.account)
    }

    async fn fetch_public_key(
        &self,
        wallet_id: &str,
        _address: &str,
    ) -> Result<Vec<u8>, EngineError> {
        let body = GetWalletAccountBody {
            organization_id: self.effective_org().to_string(),
            wallet_id: wallet_id.to_string(),
        };
        let resp: GetWalletAccountResp = self.query("get_wallet_account", &body).await?;
        let pk = resp
            .account
            .public_key
            .as_deref()
            .ok_or_else(|| EngineError::Internal("turnkey returned no public key".into()))?;
        hex::decode(pk)
            .map_err(|_| EngineError::Internal("turnkey returned non-hex public key".into()))
    }
}

fn timestamp_ms() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    millis.to_string()
}

#[derive(Debug)]
struct RawSignature {
    r: Vec<u8>,
    s: Vec<u8>,
}

fn extract_sign_raw_payload_result(env: &ActivityEnvelope) -> Option<RawSignature> {
    let result = env.activity.result.as_ref()?;
    let rp = result.get("signRawPayloadResult")?;
    let r_hex = rp.get("r")?.as_str()?;
    let s_hex = rp.get("s")?.as_str()?;
    Some(RawSignature {
        r: hex::decode(r_hex).ok()?,
        s: hex::decode(s_hex).ok()?,
    })
}

fn extract_create_wallet_result(env: &ActivityEnvelope) -> Option<(String, String)> {
    let result = env.activity.result.as_ref()?;
    let cw = result.get("createWalletResult")?;
    let wallet_id = cw.get("walletId")?.as_str()?.to_string();
    let addresses = cw.get("addresses")?.as_array()?;
    let address = addresses.first()?.as_str()?.to_string();
    Some((wallet_id, address))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_envelope_shape() {
        use k256::ecdsa::signature::DigestSigner as _;
        let sk = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let pub_hex = hex::encode(sk.verifying_key().to_sec1_bytes());
        let body = br#"{"type":"ACTIVITY_TYPE_CREATE_WALLET"}"#;
        let stamp_b64 = stamp_request(&sk, &pub_hex, body).unwrap();
        let json = BASE64_URL
            .decode(stamp_b64.as_bytes())
            .expect("base64url decode");
        let v: serde_json::Value = serde_json::from_slice(&json).expect("json decode");
        assert_eq!(v["publicKey"], pub_hex);
        assert!(v["signature"].is_string());
        assert_eq!(v["scheme"], "SIGNATURE_SCHEME_TK_API_SECP256K1");
        // signature should be hex of a DER-encoded ECDSA sig over SHA-256(body)
        let sig_hex = v["signature"].as_str().unwrap();
        let der = hex::decode(sig_hex).unwrap();
        assert!(der.len() >= 8);
        let _ = k256::ecdsa::Signature::from_der(&der).expect("valid der");
        // Also verify the signature is correct for this body.
        let mut hasher = Sha256::new();
        hasher.update(body);
        let sig: k256::ecdsa::Signature = sk.sign_digest(hasher);
        assert_eq!(hex::encode(sig.to_der().to_bytes()), sig_hex);
    }

    #[test]
    fn timestamp_ms_is_numeric_string() {
        let ts = timestamp_ms();
        assert!(ts.chars().all(|c| c.is_ascii_digit()));
        assert!(ts.parse::<u128>().is_ok());
    }

    #[test]
    fn chain_params_curve_and_path() {
        let cfg = Config::default();
        // Build a minimal engine by constructing fields directly.
        let sk = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let pk = hex::encode(sk.verifying_key().to_sec1_bytes());
        let eng = TurnkeyEngine {
            base_url: DEFAULT_API_BASE.to_string(),
            organization_id: "org".to_string(),
            sub_organization_id: None,
            api_public_key: pk,
            api_private_key: sk,
            client: reqwest::Client::new(),
        };
        let (c, p) = eng.chain_params(Chain::Evm).unwrap();
        assert_eq!(c, "CURVE_SECP256K1");
        assert_eq!(p, "m/44'/60'/0'/0/0");
        let (c, p) = eng.chain_params(Chain::Solana).unwrap();
        assert_eq!(c, "CURVE_ED25519");
        assert_eq!(p, "m/44'/501'/0'/0'");
        let _ = cfg;
    }

    #[test]
    fn parse_secp256k1_signing_key_round_trip() {
        use k256::ecdsa::signature::DigestSigner as _;
        let sk = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let sk_hex = hex::encode(sk.to_bytes());
        let sk2 = parse_secp256k1_signing_key(&sk_hex).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"msg");
        let _sig: k256::ecdsa::Signature = sk2.sign_digest(hasher);
    }

    #[test]
    fn from_config_missing_org_errors() {
        let cfg = Config::default();
        assert!(TurnkeyEngine::from_config(&cfg).is_err());
    }

    #[test]
    fn from_config_pubkey_mismatch_errors() {
        let sk = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let sk_hex = hex::encode(sk.to_bytes());
        let wrong_pub = hex::encode([0u8; 33]);
        let cfg = Config {
            custody_provider: CustodyProvider::Turnkey,
            custody_api_url: Some("https://api.turnkey.com".into()),
            custody_api_key: Some(wrong_pub),
            custody_api_private_key: Some(sk_hex),
            custody_organization_id: Some("org".into()),
            ..Config::default()
        };
        assert!(TurnkeyEngine::from_config(&cfg).is_err());
    }

    // TODO: integration test against sandbox
    use crate::config::CustodyProvider;

    #[test]
    fn extract_create_wallet_result_parses_shape() {
        let raw = serde_json::json!({
            "activity": {
                "id": "a1",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "result": {
                    "createWalletResult": {
                        "walletId": "w-123",
                        "addresses": ["0xabc"]
                    }
                }
            }
        });
        let env: ActivityEnvelope = serde_json::from_value(raw).unwrap();
        let (wid, addr) = extract_create_wallet_result(&env).unwrap();
        assert_eq!(wid, "w-123");
        assert_eq!(addr, "0xabc");
    }

    #[test]
    fn extract_sign_raw_payload_result_parses_shape() {
        let raw = serde_json::json!({
            "activity": {
                "id": "a2",
                "status": "ACTIVITY_STATUS_COMPLETED",
                "result": {
                    "signRawPayloadResult": {
                        "r": "0011",
                        "s": "2233",
                        "v": "27"
                    }
                }
            }
        });
        let env: ActivityEnvelope = serde_json::from_value(raw).unwrap();
        let rs = extract_sign_raw_payload_result(&env).unwrap();
        assert_eq!(rs.r, vec![0x00, 0x11]);
        assert_eq!(rs.s, vec![0x22, 0x33]);
    }
}
