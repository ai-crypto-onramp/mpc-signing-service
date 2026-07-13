//! Shared custody-provider HTTP core (Stage 6).
//!
//! The three v1 adapters (Fireblocks / Dfns / Turnkey) differ in URL layout,
//! auth header, and payload naming, but share the same lifecycle: submit a
//! sign request, receive (or poll for) the signature, then LOCALLY VERIFY the
//! returned signature against the returned public key before handing it to
//! the caller. Raw signatures and key material are never logged.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::domain::{Chain, KeyId, KeyMetadata, KeyShareStatus, SignatureScheme};

use super::{
    DkgOutcome, DkgParams, EngineError, EngineSignRequest, EngineSignature, RestoreParams,
    RotateOutcome,
};

/// Provider-specific request shaping.
pub struct ProviderProfile {
    /// Name used in URLs and diagnostics (`fireblocks`, `dfns`, `turnkey`).
    pub name: &'static str,
    /// Auth header name (e.g. `Authorization` or `X-DFNS-APIKEY`).
    pub auth_header: &'static str,
    /// Prefix applied to the API key value (e.g. `Bearer `).
    pub auth_prefix: &'static str,
}

/// Wire shapes for the custody REST API (mirrored by the mock custody server
/// in tests and docker-compose).
#[derive(Debug, Serialize)]
pub struct SignRequestBody {
    pub key_id: String,
    pub chain: String,
    pub payload_hex: String,
}

#[derive(Debug, Deserialize)]
pub struct SignResponseBody {
    pub signature_hex: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub status: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateKeyBody {
    pub chain: String,
    pub threshold: u32,
    pub parties: u32,
}

#[derive(Debug, Deserialize)]
pub struct KeyResponseBody {
    pub key_id: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub status: Option<String>,
}

/// HTTP client core shared by all custody adapters.
pub struct CustodyHttp {
    profile: ProviderProfile,
    base_url: String,
    api_key: String,
    client: reqwest::Client,
}

impl CustodyHttp {
    pub fn new(profile: ProviderProfile, base_url: &str, api_key: &str) -> Self {
        Self {
            profile,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.to_string(),
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client"),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{}{}", self.base_url, self.profile.name, path)
    }

    fn auth_value(&self) -> String {
        format!("{}{}", self.profile.auth_prefix, self.api_key)
    }

    async fn post_json<B: Serialize, R: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<R, EngineError> {
        let resp = self
            .client
            .post(self.url(path))
            .header(self.profile.auth_header, self.auth_value())
            .json(body)
            .send()
            .await
            .map_err(classify_reqwest)?;
        decode_response(resp).await
    }

    async fn get_json<R: serde::de::DeserializeOwned>(&self, path: &str) -> Result<R, EngineError> {
        let resp = self
            .client
            .get(self.url(path))
            .header(self.profile.auth_header, self.auth_value())
            .send()
            .await
            .map_err(classify_reqwest)?;
        decode_response(resp).await
    }

    /// Submit a sign request and verify the returned signature locally.
    pub async fn sign(&self, req: &EngineSignRequest) -> Result<EngineSignature, EngineError> {
        let body = SignRequestBody {
            key_id: req.key_id.0.clone(),
            chain: req.chain.as_str().to_string(),
            payload_hex: hex::encode(&req.payload),
        };
        let resp: SignResponseBody = self.post_json("/sign", &body).await?;
        let signature = hex::decode(&resp.signature_hex)
            .map_err(|_| EngineError::Internal("provider returned non-hex signature".into()))?;
        let public_key = hex::decode(&resp.public_key_hex)
            .map_err(|_| EngineError::Internal("provider returned non-hex public key".into()))?;

        verify_signature(req.chain, &req.payload, &signature, &public_key)?;
        Ok(EngineSignature {
            signature,
            public_key,
        })
    }

    pub async fn dkg(&self, params: &DkgParams) -> Result<DkgOutcome, EngineError> {
        let body = CreateKeyBody {
            chain: params.chain.as_str().to_string(),
            threshold: params.threshold,
            parties: params.parties,
        };
        let resp: KeyResponseBody = self.post_json("/keys", &body).await?;
        Ok(DkgOutcome {
            key_id: KeyId(resp.key_id),
            public_key: hex::decode(&resp.public_key_hex).map_err(|_| {
                EngineError::Internal("provider returned non-hex public key".into())
            })?,
        })
    }

    pub async fn rotate(&self, key_id: &KeyId) -> Result<RotateOutcome, EngineError> {
        let resp: KeyResponseBody = self
            .post_json(
                &format!("/keys/{}/rotate", key_id.0),
                &serde_json::json!({}),
            )
            .await?;
        Ok(RotateOutcome {
            key_id: key_id.clone(),
            public_key: hex::decode(&resp.public_key_hex).map_err(|_| {
                EngineError::Internal("provider returned non-hex public key".into())
            })?,
            epoch: resp.epoch,
        })
    }

    pub async fn key_metadata(
        &self,
        key_id: &KeyId,
        chain: Chain,
    ) -> Result<KeyMetadata, EngineError> {
        let resp: KeyResponseBody = self.get_json(&format!("/keys/{}", key_id.0)).await?;
        Ok(KeyMetadata {
            key_id: KeyId(resp.key_id),
            chain,
            public_key: hex::decode(&resp.public_key_hex).map_err(|_| {
                EngineError::Internal("provider returned non-hex public key".into())
            })?,
            status: match resp.status.as_deref() {
                Some("cooling") => KeyShareStatus::Cooling,
                Some("retired") => KeyShareStatus::Retired,
                _ => KeyShareStatus::Active,
            },
            epoch: resp.epoch,
        })
    }

    pub async fn restore(&self, params: &RestoreParams) -> Result<bool, EngineError> {
        if params.quorum_proof.is_empty() {
            return Err(EngineError::Denied(
                "quorum proof required for restore".into(),
            ));
        }
        let body = serde_json::json!({
            "node_id": params.node_id,
            "quorum_proof_hex": hex::encode(&params.quorum_proof),
        });
        let _: serde_json::Value = self
            .post_json(&format!("/keys/{}/restore", params.key_id.0), &body)
            .await?;
        Ok(true)
    }
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
            "provider reports unknown key".into(),
        ));
    }
    if status == reqwest::StatusCode::FORBIDDEN || status == reqwest::StatusCode::UNAUTHORIZED {
        return Err(EngineError::Denied(format!(
            "provider rejected request: {status}"
        )));
    }
    if status.is_server_error() {
        return Err(EngineError::ProviderUnavailable(format!(
            "provider error: {status}"
        )));
    }
    if !status.is_success() {
        return Err(EngineError::Transient(format!(
            "provider returned {status}"
        )));
    }
    resp.json::<R>()
        .await
        .map_err(|e| EngineError::Internal(format!("provider response decode: {e}")))
}

/// Verify a provider-returned signature against the provider-returned public
/// key before trusting it. ECDSA signatures are 64-byte r||s over SHA-256 of
/// the payload; Ed25519 signatures are over the raw payload.
pub fn verify_signature(
    chain: Chain,
    payload: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), EngineError> {
    let fail = |what: &str| {
        EngineError::Internal(format!("provider signature verification failed: {what}"))
    };
    match chain.scheme() {
        SignatureScheme::EcdsaSecp256k1 => {
            use k256::ecdsa::signature::Verifier as _;
            let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                .map_err(|_| fail("bad public key"))?;
            let sig = k256::ecdsa::Signature::from_slice(signature)
                .map_err(|_| fail("bad signature encoding"))?;
            vk.verify(payload, &sig).map_err(|_| fail("mismatch"))
        }
        SignatureScheme::Ed25519 => {
            let pk_arr: [u8; 32] = public_key.try_into().map_err(|_| fail("bad public key"))?;
            let sig_arr: [u8; 64] = signature
                .try_into()
                .map_err(|_| fail("bad signature encoding"))?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
                .map_err(|_| fail("bad public key"))?;
            // verify_strict rejects small-order/weak keys a malicious provider
            // could use to make garbage "verify".
            vk.verify_strict(payload, &ed25519_dalek::Signature::from_bytes(&sig_arr))
                .map_err(|_| fail("mismatch"))
        }
    }
}

/// Verify an inbound custody webhook: HMAC-SHA256 over the raw body, hex in
/// the `X-Custody-Signature` header, keyed by `CUSTODY_WEBHOOK_SECRET`.
pub fn verify_webhook(secret: &str, body: &[u8], signature_hex: &str) -> bool {
    let Ok(sig) = hex::decode(signature_hex) else {
        return false;
    };
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(body);
    mac.verify_slice(&sig).is_ok()
}

/// Compute the webhook signature (used by tests and the mock provider).
pub fn webhook_signature(secret: &str, body: &[u8]) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webhook_round_trip() {
        let sig = webhook_signature("secret", b"payload");
        assert!(verify_webhook("secret", b"payload", &sig));
        assert!(!verify_webhook("secret", b"tampered", &sig));
        assert!(!verify_webhook("wrong", b"payload", &sig));
        assert!(!verify_webhook("secret", b"payload", "not-hex!"));
    }

    #[test]
    fn signature_verification_rejects_garbage() {
        assert!(verify_signature(Chain::Evm, b"x", &[0u8; 64], &[0u8; 33]).is_err());
        assert!(verify_signature(Chain::Solana, b"x", &[0u8; 64], &[0u8; 32]).is_err());
        assert!(verify_signature(Chain::Solana, b"x", &[0u8; 10], &[0u8; 32]).is_err());
    }

    #[test]
    fn signature_verification_accepts_valid_ecdsa() {
        use k256::ecdsa::signature::Signer as _;
        let sk = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let sig: k256::ecdsa::Signature = sk.sign(b"msg");
        verify_signature(
            Chain::Evm,
            b"msg",
            &sig.to_vec(),
            &sk.verifying_key().to_sec1_bytes(),
        )
        .unwrap();
    }

    #[test]
    fn signature_verification_accepts_valid_ed25519() {
        use ed25519_dalek::Signer as _;
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let sig = sk.sign(b"msg");
        verify_signature(
            Chain::Solana,
            b"msg",
            &sig.to_bytes(),
            &sk.verifying_key().to_bytes(),
        )
        .unwrap();
    }
}
