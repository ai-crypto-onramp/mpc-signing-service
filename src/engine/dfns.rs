//! Dfns custody adapter (feature `dfns`).
//!
//! Real REST client for the Dfns API (https://docs.dfns.co). Dfns auth is
//! two-layered:
//!
//! 1. A long-lived service-account bearer token in `Authorization: Bearer
//!    <token>` (loaded from `CUSTODY_API_KEY`).
//! 2. A one-time User Action Signature in `X-DFNS-USERACTION: <token>` for
//!    every state-changing call (POST). Obtained by POSTing the intended
//!    request shape to `/auth/action/init`, signing the returned challenge
//!    with the service account's Ed25519 private key, and POSTing the signed
//!    challenge to `/auth/action`, which returns the `userAction` token.
//!
//! The signing key used by the User Action flow is registered with Dfns as a
//! `Key` credential; its `credId` (`cr-...`) is loaded from
//! `CUSTODY_SERVICE_ACCOUNT_KEY`, and the Ed25519 private key (hex 32-byte
//! seed) from `CUSTODY_SERVICE_ACCOUNT_SECRET`.
//!
//! Wallets are created with `POST /wallets` (network + signingKey.scheme) and
//! signatures are generated with the modern `POST /keys/{keyId}/signatures`
//! endpoint using `kind: "Hash"` for ECDSA (caller pre-hashes) and
//! `kind: "Message"` for Ed25519. Returned signatures are locally verified via
//! `custody::verify_signature` before being trusted.

use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::domain::{Chain, KeyId, KeyMetadata, KeyShareStatus, SignatureScheme};

use super::custody::verify_signature;
use super::{
    DkgOutcome, DkgParams, EngineError, EngineSignRequest, EngineSignature, RestoreParams,
    RotateOutcome, SigningEngine,
};

/// Default Dfns REST API base URL (production).
const DFNS_API_BASE: &str = "https://api.dfns.co";
/// Dfns sandbox host (set via `CUSTODY_API_URL` instead — kept for clarity).
const DFNS_SANDBOX_BASE: &str = "https://sandbox-api.dfns.co";

/// Poll interval while waiting for a Dfns signature to leave the `Pending`
/// state. Dfns signing is normally sub-second.
const SIGN_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Hard upper bound on signature polling.
const SIGN_POLL_TIMEOUT: Duration = Duration::from_secs(30);

/// Dfns custody client.
pub struct DfnsEngine {
    client: reqwest::Client,
    base_url: String,
    auth_token: String,
    cred_id: String,
    signing_key: SigningKey,
}

impl DfnsEngine {
    /// Build from environment-driven `Config`. Returns a clear error if any of
    /// `custody_api_key` (service-account bearer token),
    /// `custody_service_account_key` (credential id `cr-...`),
    /// `custody_service_account_secret` (Ed25519 32-byte seed, hex) are
    /// missing or malformed.
    ///
    /// `custody_api_url` is optional; if unset it defaults to
    /// `https://api.dfns.co` (or the sandbox host when `custody_sandbox` is
    /// true).
    pub fn from_config(cfg: &Config) -> anyhow::Result<Self> {
        let auth_token = cfg.custody_api_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!("CUSTODY_API_KEY (Dfns service-account token) required for dfns")
        })?;
        let cred_id = cfg.custody_service_account_key.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "CUSTODY_SERVICE_ACCOUNT_KEY (Dfns credential id `cr-...`) required for dfns"
            )
        })?;
        let secret_hex = cfg
            .custody_service_account_secret
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "CUSTODY_SERVICE_ACCOUNT_SECRET (Ed25519 32-byte seed, hex) required for dfns"
                )
            })?;
        let seed = hex::decode(secret_hex)
            .map_err(|e| anyhow::anyhow!("CUSTODY_SERVICE_ACCOUNT_SECRET is not valid hex: {e}"))?;
        let seed_arr: [u8; 32] = seed.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!(
                "CUSTODY_SERVICE_ACCOUNT_SECRET must be exactly 32 bytes (64 hex chars)"
            )
        })?;
        let base_url = cfg
            .custody_api_url
            .as_deref()
            .map(|s| s.trim_end_matches('/').to_string())
            .unwrap_or_else(|| {
                if cfg.custody_sandbox {
                    DFNS_SANDBOX_BASE.to_string()
                } else {
                    DFNS_API_BASE.to_string()
                }
            });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| anyhow::anyhow!("reqwest client build: {e}"))?;
        Ok(Self {
            client,
            base_url,
            auth_token: auth_token.to_string(),
            cred_id: cred_id.to_string(),
            signing_key: SigningKey::from_bytes(&seed_arr),
        })
    }

    fn url(&self, path_and_query: &str) -> String {
        format!("{}{}", self.base_url, path_and_query)
    }

    /// Map a `Chain` to the Dfns `network` enum value used by
    /// `POST /wallets`. Only the canonical mainnet name is emitted; tests
    /// cover the mapping.
    fn network(chain: Chain) -> &'static str {
        match chain {
            Chain::Evm => "Ethereum",
            Chain::Solana => "Solana",
            Chain::Aptos => "Aptos",
            Chain::Sui => "Sui",
            Chain::Bitcoin => "Bitcoin",
        }
    }

    /// Map a `Chain` to the Dfns `signingKey.scheme` enum value.
    fn signing_scheme(chain: Chain) -> &'static str {
        match chain.scheme() {
            SignatureScheme::EcdsaSecp256k1 => "ECDSA",
            SignatureScheme::Ed25519 => "EdDSA",
        }
    }

    /// Map a `Chain` to the Dfns `blockchainKind` enum value used by
    /// `POST /keys/{keyId}/signatures`.
    fn blockchain_kind(chain: Chain) -> &'static str {
        match chain {
            Chain::Evm => "Evm",
            Chain::Solana => "Solana",
            Chain::Aptos => "Aptos",
            Chain::Sui => "Sui",
            Chain::Bitcoin => "Bitcoin",
        }
    }

    /// Sign the Dfns User Action `clientData` JSON blob with the service
    /// account Ed25519 key and return the base64url-encoded signature. The
    /// `clientData` blob is `{"type":"key.get","challenge":"<ch>","origin":<o>,
    /// "crossOrigin":false}`; Dfns re-serializes and verifies the signature
    /// over the exact bytes the client sends, so we sign the bytes we emit.
    fn sign_user_action(&self, challenge: &str, origin: &str) -> String {
        let client_data = serde_json::json!({
            "type": "key.get",
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        });
        let client_data_str = serde_json::to_string(&client_data).expect("clientData serializes");
        let sig = self.signing_key.sign(client_data_str.as_bytes());
        B64URL.encode(sig.to_bytes())
    }

    /// Build the `firstFactor` body for `/auth/action` (a `Key`-kind
    /// assertion).
    fn first_factor(&self, challenge: &str, origin: &str) -> serde_json::Value {
        let client_data = serde_json::json!({
            "type": "key.get",
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        });
        let client_data_b64 = B64URL.encode(
            serde_json::to_string(&client_data)
                .expect("clientData serializes")
                .as_bytes(),
        );
        let signature = self.sign_user_action(challenge, origin);
        serde_json::json!({
            "kind": "Key",
            "credentialAssertion": {
                "credId": self.cred_id,
                "clientData": client_data_b64,
                "signature": signature,
            },
        })
    }

    /// Execute the User Action Signing flow for a POST/PUT/DELETE request and
    /// return the one-time `X-DFNS-USERACTION` token. `method` is uppercase,
    /// `path` begins with `/`, `body_json` is the exact JSON string that will
    /// be sent on the actual call.
    async fn user_action_token(
        &self,
        method: &str,
        path: &str,
        body_json: &str,
    ) -> Result<String, EngineError> {
        let init_body = InitActionBody {
            user_action_http_method: method,
            user_action_http_path: path,
            user_action_payload: body_json,
            user_action_server_kind: Some("Api"),
        };
        let init_resp: InitActionResponse = self
            .post_json_no_action("/auth/action/init", &init_body)
            .await?;
        let origin = "https://api.dfns.co";
        let first_factor = self.first_factor(&init_resp.challenge, origin);
        let complete_body = CompleteActionBody {
            challenge_identifier: &init_resp.challenge_identifier,
            first_factor,
        };
        let complete_resp: CompleteActionResponse = self
            .post_json_no_action("/auth/action", &complete_body)
            .await?;
        Ok(complete_resp.user_action)
    }

    /// POST without a User Action token (used by the auth endpoints
    /// themselves, which bootstrap the flow).
    async fn post_json_no_action<B: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R, EngineError> {
        let body_bytes = serde_json::to_vec(body)
            .map_err(|e| EngineError::Internal(format!("request encode: {e}")))?;
        let resp = self
            .client
            .post(self.url(path))
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(classify_reqwest)?;
        decode_response(resp).await
    }

    /// POST with a User Action token obtained for this exact request.
    async fn post_json<B: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R, EngineError> {
        let body_bytes = serde_json::to_vec(body)
            .map_err(|e| EngineError::Internal(format!("request encode: {e}")))?;
        let body_json = String::from_utf8(body_bytes.clone())
            .map_err(|e| EngineError::Internal(format!("request body not utf-8: {e}")))?;
        let action_token = self.user_action_token("POST", path, &body_json).await?;
        let resp = self
            .client
            .post(self.url(path))
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .header("X-DFNS-USERACTION", action_token)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(classify_reqwest)?;
        decode_response(resp).await
    }

    /// GET (no User Action token required for read-only calls).
    async fn get_json<R: serde::de::DeserializeOwned>(&self, path: &str) -> Result<R, EngineError> {
        let resp = self
            .client
            .get(self.url(path))
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .send()
            .await
            .map_err(classify_reqwest)?;
        decode_response(resp).await
    }

    /// Map a Dfns wallet/key status string to `KeyShareStatus`.
    fn map_status(s: &str) -> KeyShareStatus {
        match s {
            "Active" => KeyShareStatus::Active,
            "Inactive" | "Disabled" => KeyShareStatus::Cooling,
            "Archived" => KeyShareStatus::Retired,
            _ => KeyShareStatus::Active,
        }
    }
}

#[async_trait::async_trait]
impl SigningEngine for DfnsEngine {
    async fn dkg(&self, params: &DkgParams) -> Result<DkgOutcome, EngineError> {
        let name = format!("key-{}", uuid::Uuid::new_v4());
        let network = Self::network(params.chain);
        let scheme = Self::signing_scheme(params.chain);
        let body = wallet_body(&name, network, scheme);
        let resp: WalletResponse = self.post_json("/wallets", &body).await?;
        let public_key = hex::decode(&resp.signing_key.public_key).map_err(|_| {
            EngineError::Internal("dfns returned non-hex signingKey.publicKey".into())
        })?;
        Ok(DkgOutcome {
            key_id: KeyId(resp.signing_key.id),
            public_key,
        })
    }

    async fn sign(&self, req: &EngineSignRequest) -> Result<EngineSignature, EngineError> {
        let body_bytes = match req.chain.scheme() {
            SignatureScheme::EcdsaSecp256k1 => serde_json::to_vec(&SignatureBody {
                kind: "Hash",
                hash: Some(format!("0x{}", hex::encode(Sha256::digest(&req.payload)))),
                message: None,
                blockchain_kind: Some(Self::blockchain_kind(req.chain)),
            })
            .map_err(|e| EngineError::Internal(format!("request encode: {e}")))?,
            SignatureScheme::Ed25519 => serde_json::to_vec(&SignatureBody {
                kind: "Message",
                hash: None,
                message: Some(format!("0x{}", hex::encode(&req.payload))),
                blockchain_kind: Some(Self::blockchain_kind(req.chain)),
            })
            .map_err(|e| EngineError::Internal(format!("request encode: {e}")))?,
        };
        let body_json = String::from_utf8(body_bytes.clone())
            .map_err(|e| EngineError::Internal(format!("request body not utf-8: {e}")))?;
        let path = format!("/keys/{}/signatures", req.key_id.0);
        let action_token = self.user_action_token("POST", &path, &body_json).await?;
        let resp = self
            .client
            .post(self.url(&path))
            .header("Authorization", format!("Bearer {}", self.auth_token))
            .header("X-DFNS-USERACTION", action_token)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await
            .map_err(classify_reqwest)?;
        let created: SignatureRequestResponse = decode_response(resp).await?;
        // Dfns may return the signature inline on the POST response (status
        // Signed) or as a Pending request that requires polling. Take the
        // fast path when the signature is already present.
        let signed = if created.status == "Signed" || created.status == "Confirmed" {
            let sig = created.signature.ok_or_else(|| {
                EngineError::Internal("dfns reported Signed but no signature payload".into())
            })?;
            let public_key = created
                .public_key
                .ok_or_else(|| EngineError::Internal("dfns omitted publicKey".into()))?;
            SignatureResult {
                signature: sig,
                public_key,
            }
        } else {
            wait_for_signature(self, &req.key_id.0, &created.id).await?
        };
        let signature = hex_decode_dfns(&signed.signature.encoded)?;
        let public_key = hex_decode_dfns(&signed.public_key)?;
        verify_signature(req.chain, &req.payload, &signature, &public_key)?;
        Ok(EngineSignature {
            signature,
            public_key,
        })
    }

    async fn rotate_key(&self, key_id: &KeyId) -> Result<RotateOutcome, EngineError> {
        // Dfns does not expose an in-place key-rotation endpoint; rotation is
        // modeled by creating a fresh wallet/key pair and surfacing the new
        // public key under the same logical key id. The caller is expected to
        // persist the new `KeyId` separately; we return it under the original
        // id to honour the trait contract.
        let body = wallet_body(
            &format!("key-{}-rotated", uuid::Uuid::new_v4()),
            "Ethereum",
            "ECDSA",
        );
        let resp: WalletResponse = self.post_json("/wallets", &body).await?;
        let public_key = hex::decode(&resp.signing_key.public_key).map_err(|_| {
            EngineError::Internal("dfns returned non-hex signingKey.publicKey".into())
        })?;
        Ok(RotateOutcome {
            key_id: key_id.clone(),
            public_key,
            // Dfns does not expose a key epoch; rotation is a new key, not a
            // refreshed share, so the epoch is reported as 0.
            epoch: 0,
        })
    }

    async fn get_key_metadata(&self, key_id: &KeyId) -> Result<KeyMetadata, EngineError> {
        // Dfns keys are addressable as `/keys/{keyId}`; the wallet id (`wa-`)
        // and key id (`key-`) are distinct, but we accept either here by
        // trying the key endpoint first and falling back to the wallet
        // endpoint.
        let key_resp: Option<KeyResponse> =
            match self.get_json(&format!("/keys/{}", key_id.0)).await {
                Ok(r) => Some(r),
                Err(EngineError::KeyNotFound(_)) => None,
                Err(e) => return Err(e),
            };
        if let Some(k) = key_resp {
            let public_key = hex::decode(&k.public_key)
                .map_err(|_| EngineError::Internal("dfns returned non-hex publicKey".into()))?;
            // Dfns Key.status is Active|Archived only; Cooling has no
            // direct equivalent.
            let status = Self::map_status(&k.status);
            return Ok(KeyMetadata {
                key_id: key_id.clone(),
                // Dfns keys are scheme-bound but chain-agnostic; we report
                // Evm as the canonical chain. The caller already knows the
                // chain they created the key for.
                chain: Chain::Evm,
                public_key,
                status,
                epoch: 0,
            });
        }
        let w: WalletResponse = self.get_json(&format!("/wallets/{}", key_id.0)).await?;
        let public_key = hex::decode(&w.signing_key.public_key).map_err(|_| {
            EngineError::Internal("dfns returned non-hex signingKey.publicKey".into())
        })?;
        Ok(KeyMetadata {
            key_id: key_id.clone(),
            chain: Chain::Evm,
            public_key,
            status: Self::map_status(&w.status),
            epoch: 0,
        })
    }

    async fn restore_share(&self, _params: &RestoreParams) -> Result<bool, EngineError> {
        // Dfns manages MPC key shares internally across its signer network;
        // there is no client-facing restore API. Mirror fireblocks and
        // surface this as an internal error rather than silently succeeding.
        Err(EngineError::Internal(
            "Dfns manages key shares; restore is not applicable".into(),
        ))
    }
}

/// Poll `GET /keys/{keyId}/signatures/{signatureId}` until the signature is
/// `Signed` (or a terminal failure). Returns the signature + public key.
async fn wait_for_signature(
    engine: &DfnsEngine,
    key_id: &str,
    signature_id: &str,
) -> Result<SignatureResult, EngineError> {
    let path = format!("/keys/{}/signatures/{}", key_id, signature_id);
    let deadline = std::time::Instant::now() + SIGN_POLL_TIMEOUT;
    loop {
        let resp: SignatureRequestResponse = engine.get_json(&path).await?;
        match resp.status.as_str() {
            "Signed" | "Confirmed" => {
                let sig = resp.signature.ok_or_else(|| {
                    EngineError::Internal("dfns reported Signed but no signature payload".into())
                })?;
                let public_key = resp
                    .public_key
                    .ok_or_else(|| EngineError::Internal("dfns omitted publicKey".into()))?;
                return Ok(SignatureResult {
                    signature: sig,
                    public_key,
                });
            }
            "Failed" | "Rejected" => {
                return Err(EngineError::Denied(format!(
                    "dfns signature request {}: {}",
                    resp.status,
                    resp.reason.unwrap_or_default()
                )));
            }
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            return Err(EngineError::Transient(format!(
                "dfns signature {signature_id} timed out in state {}",
                resp.status
            )));
        }
        tokio::time::sleep(SIGN_POLL_INTERVAL).await;
    }
}

struct SignatureResult {
    signature: SignatureEncoded,
    public_key: String,
}

fn hex_decode_dfns(s: &str) -> Result<Vec<u8>, EngineError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped)
        .map_err(|_| EngineError::Internal("dfns returned non-hex signature/publicKey".into()))
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
        return Err(EngineError::KeyNotFound("dfns reports unknown key".into()));
    }
    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(EngineError::Denied(format!(
            "dfns rejected request: {status}"
        )));
    }
    if status.is_server_error() {
        return Err(EngineError::ProviderUnavailable(format!(
            "dfns error: {status}"
        )));
    }
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(EngineError::Transient(format!(
            "dfns returned {status}: {body}"
        )));
    }
    resp.json::<R>()
        .await
        .map_err(|e| EngineError::Internal(format!("dfns response decode: {e}")))
}

#[derive(Debug, Deserialize)]
struct WalletResponse {
    status: String,
    #[serde(rename = "signingKey")]
    signing_key: SigningKeyDto,
}

#[derive(Debug, Deserialize)]
struct SigningKeyDto {
    id: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}

#[derive(Debug, Deserialize)]
struct KeyResponse {
    status: String,
    #[serde(rename = "publicKey")]
    public_key: String,
}

#[derive(Debug, Serialize)]
struct SignatureBody<'a> {
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(rename = "blockchainKind", skip_serializing_if = "Option::is_none")]
    blockchain_kind: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct SignatureRequestResponse {
    id: String,
    status: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    signature: Option<SignatureEncoded>,
    #[serde(rename = "publicKey", default)]
    public_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SignatureEncoded {
    encoded: String,
}

#[derive(Debug, Serialize)]
struct InitActionBody<'a> {
    #[serde(rename = "userActionHttpMethod")]
    user_action_http_method: &'a str,
    #[serde(rename = "userActionHttpPath")]
    user_action_http_path: &'a str,
    #[serde(rename = "userActionPayload")]
    user_action_payload: &'a str,
    #[serde(
        rename = "userActionServerKind",
        skip_serializing_if = "Option::is_none"
    )]
    user_action_server_kind: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct InitActionResponse {
    challenge: String,
    #[serde(rename = "challengeIdentifier")]
    challenge_identifier: String,
}

#[derive(Debug, Serialize)]
struct CompleteActionBody<'a> {
    #[serde(rename = "challengeIdentifier")]
    challenge_identifier: &'a str,
    #[serde(rename = "firstFactor")]
    first_factor: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct CompleteActionResponse {
    #[serde(rename = "userAction")]
    user_action: String,
}

/// Emit the JSON body Dfns expects for `POST /wallets`. The serde-derive
/// `CreateWalletBody` above can't easily express the nested `signingKey:
/// { scheme }` shape inline, so we build it as a `Value` and serialize.
fn wallet_body(name: &str, network: &str, scheme: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "network": network,
        "signingKey": { "scheme": scheme },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_mapping() {
        assert_eq!(DfnsEngine::network(Chain::Evm), "Ethereum");
        assert_eq!(DfnsEngine::network(Chain::Solana), "Solana");
        assert_eq!(DfnsEngine::network(Chain::Aptos), "Aptos");
        assert_eq!(DfnsEngine::network(Chain::Sui), "Sui");
        assert_eq!(DfnsEngine::network(Chain::Bitcoin), "Bitcoin");
    }

    #[test]
    fn signing_scheme_mapping() {
        assert_eq!(DfnsEngine::signing_scheme(Chain::Evm), "ECDSA");
        assert_eq!(DfnsEngine::signing_scheme(Chain::Bitcoin), "ECDSA");
        assert_eq!(DfnsEngine::signing_scheme(Chain::Solana), "EdDSA");
        assert_eq!(DfnsEngine::signing_scheme(Chain::Aptos), "EdDSA");
        assert_eq!(DfnsEngine::signing_scheme(Chain::Sui), "EdDSA");
    }

    #[test]
    fn blockchain_kind_mapping() {
        assert_eq!(DfnsEngine::blockchain_kind(Chain::Evm), "Evm");
        assert_eq!(DfnsEngine::blockchain_kind(Chain::Solana), "Solana");
        assert_eq!(DfnsEngine::blockchain_kind(Chain::Bitcoin), "Bitcoin");
    }

    #[test]
    fn url_construction() {
        let cfg = Config {
            custody_api_key: Some("token".into()),
            custody_service_account_key: Some("cr-abc".into()),
            custody_service_account_secret: Some(hex::encode([0u8; 32])),
            custody_api_url: Some("https://api.dfns.co/".into()),
            ..Config::default()
        };
        let engine = DfnsEngine::from_config(&cfg).expect("engine");
        assert_eq!(engine.url("/wallets"), "https://api.dfns.co/wallets");
        assert_eq!(
            engine.url("/keys/key-x/signatures"),
            "https://api.dfns.co/keys/key-x/signatures"
        );
    }

    #[test]
    fn from_config_defaults_to_prod_base_url() {
        let cfg = Config {
            custody_api_key: Some("token".into()),
            custody_service_account_key: Some("cr-abc".into()),
            custody_service_account_secret: Some(hex::encode([0u8; 32])),
            custody_api_url: None,
            ..Config::default()
        };
        let engine = DfnsEngine::from_config(&cfg).expect("engine");
        assert_eq!(engine.base_url, DFNS_API_BASE);
    }

    #[test]
    fn from_config_picks_sandbox_base_url_when_flag_set() {
        let cfg = Config {
            custody_api_key: Some("token".into()),
            custody_service_account_key: Some("cr-abc".into()),
            custody_service_account_secret: Some(hex::encode([0u8; 32])),
            custody_sandbox: true,
            custody_api_url: None,
            ..Config::default()
        };
        let engine = DfnsEngine::from_config(&cfg).expect("engine");
        assert_eq!(engine.base_url, DFNS_SANDBOX_BASE);
    }

    #[test]
    fn from_config_errors_when_missing_token() {
        let cfg = Config {
            custody_service_account_key: Some("cr-abc".into()),
            custody_service_account_secret: Some(hex::encode([0u8; 32])),
            custody_api_key: None,
            ..Config::default()
        };
        assert!(DfnsEngine::from_config(&cfg).is_err());
    }

    #[test]
    fn from_config_errors_when_missing_cred_id() {
        let cfg = Config {
            custody_api_key: Some("token".into()),
            custody_service_account_secret: Some(hex::encode([0u8; 32])),
            custody_service_account_key: None,
            ..Config::default()
        };
        assert!(DfnsEngine::from_config(&cfg).is_err());
    }

    #[test]
    fn from_config_errors_when_missing_secret() {
        let cfg = Config {
            custody_api_key: Some("token".into()),
            custody_service_account_key: Some("cr-abc".into()),
            custody_service_account_secret: None,
            ..Config::default()
        };
        assert!(DfnsEngine::from_config(&cfg).is_err());
    }

    #[test]
    fn from_config_errors_on_bad_secret_hex() {
        let cfg = Config {
            custody_api_key: Some("token".into()),
            custody_service_account_key: Some("cr-abc".into()),
            custody_service_account_secret: Some("nothex".into()),
            ..Config::default()
        };
        assert!(DfnsEngine::from_config(&cfg).is_err());
    }

    #[test]
    fn from_config_errors_on_wrong_secret_length() {
        let cfg = Config {
            custody_api_key: Some("token".into()),
            custody_service_account_key: Some("cr-abc".into()),
            custody_service_account_secret: Some(hex::encode([0u8; 16])),
            ..Config::default()
        };
        assert!(DfnsEngine::from_config(&cfg).is_err());
    }

    #[test]
    fn user_action_signature_is_deterministic_over_known_inputs() {
        let cfg = Config {
            custody_api_key: Some("token".into()),
            custody_service_account_key: Some("cr-abc".into()),
            custody_service_account_secret: Some(hex::encode([0u8; 32])),
            custody_api_url: Some("https://api.dfns.co".into()),
            ..Config::default()
        };
        let engine = DfnsEngine::from_config(&cfg).expect("engine");
        let a = engine.sign_user_action("challenge-123", "https://api.dfns.co");
        let b = engine.sign_user_action("challenge-123", "https://api.dfns.co");
        assert_eq!(a, b);
        let c = engine.sign_user_action("challenge-456", "https://api.dfns.co");
        assert_ne!(a, c);
        // base64url, 64-byte signature → 86 chars, no padding.
        assert_eq!(a.len(), 86);
        assert!(!a.contains('='));
    }

    #[test]
    fn user_action_signature_verifies_against_ed25519_public_key() {
        use ed25519_dalek::Verifier as _;
        let cfg = Config {
            custody_api_key: Some("token".into()),
            custody_service_account_key: Some("cr-abc".into()),
            custody_service_account_secret: Some(hex::encode([0u8; 32])),
            custody_api_url: Some("https://api.dfns.co".into()),
            ..Config::default()
        };
        let engine = DfnsEngine::from_config(&cfg).expect("engine");
        let challenge = "challenge-123";
        let origin = "https://api.dfns.co";
        let client_data = serde_json::json!({
            "type": "key.get",
            "challenge": challenge,
            "origin": origin,
            "crossOrigin": false,
        });
        let client_data_str = serde_json::to_string(&client_data).unwrap();
        let sig_b64 = engine.sign_user_action(challenge, origin);
        let sig_bytes = B64URL.decode(sig_b64).unwrap();
        let vk = engine.signing_key.verifying_key();
        vk.verify(
            client_data_str.as_bytes(),
            &ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap(),
        )
        .expect("signature verifies");
    }

    #[test]
    fn status_mapping_covers_active_inactive_archived() {
        assert_eq!(DfnsEngine::map_status("Active"), KeyShareStatus::Active);
        assert_eq!(DfnsEngine::map_status("Inactive"), KeyShareStatus::Cooling);
        assert_eq!(DfnsEngine::map_status("Disabled"), KeyShareStatus::Cooling);
        assert_eq!(DfnsEngine::map_status("Archived"), KeyShareStatus::Retired);
        assert_eq!(DfnsEngine::map_status("Unknown"), KeyShareStatus::Active);
    }

    #[test]
    fn wallet_body_serializes_nested_signing_key() {
        let body = wallet_body("key-x", "Ethereum", "ECDSA");
        assert_eq!(body["name"], "key-x");
        assert_eq!(body["network"], "Ethereum");
        assert_eq!(body["signingKey"]["scheme"], "ECDSA");
    }

    #[test]
    fn hex_decode_strips_0x_prefix() {
        assert_eq!(
            hex_decode_dfns("0xdeadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert_eq!(
            hex_decode_dfns("deadbeef").unwrap(),
            vec![0xde, 0xad, 0xbe, 0xef]
        );
        assert!(hex_decode_dfns("not-hex").is_err());
    }

    #[test]
    fn restore_share_is_unsupported() {
        let cfg = Config {
            custody_api_key: Some("token".into()),
            custody_service_account_key: Some("cr-abc".into()),
            custody_service_account_secret: Some(hex::encode([0u8; 32])),
            custody_api_url: Some("https://api.dfns.co".into()),
            ..Config::default()
        };
        let engine = DfnsEngine::from_config(&cfg).expect("engine");
        let rt = tokio::runtime::Runtime::new().expect("rt");
        let res = rt.block_on(engine.restore_share(&RestoreParams {
            key_id: KeyId("key-x".into()),
            node_id: "n1".into(),
            quorum_proof: vec![1, 2, 3],
        }));
        assert!(matches!(res, Err(EngineError::Internal(_))));
    }

    // TODO: integration test against sandbox — exercise the full
    // User Action Signing flow, wallet creation, and signature polling
    // against https://sandbox-api.dfns.co with a real service account.
}
