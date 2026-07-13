//! Policy decision token verification (Stage 3).
//!
//! `SignTx` refuses to sign unless the request carries a token issued by the
//! Policy / Risk Engine that is (1) signature-valid, (2) bound to this exact
//! `tx_payload`, `key_id`, and `chain`, (3) fresh, and (4) unused.
//!
//! Token wire format: `base64url(claims_json) + "." + base64url(signature)`
//! where the signature is Ed25519 over the exact claims-JSON bytes, made with
//! the Policy Engine's key (`POLICY_ENGINE_PUBKEY`).

use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::domain::{sha256_hex, unix_now, Chain};
use crate::store::UsedTokenStore;

/// Claims carried by a policy decision token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyClaims {
    /// Unique token id (nonce) enforcing single use.
    pub token_id: String,
    /// Hex SHA-256 of the tx payload this approval covers.
    pub tx_payload_hash: String,
    pub key_id: String,
    pub chain: Chain,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Distinct, audited reasons a token is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DenyReason {
    #[error("token_malformed")]
    Malformed,
    #[error("token_signature_invalid")]
    BadSignature,
    #[error("tx_payload_hash_mismatch")]
    PayloadMismatch,
    #[error("key_id_mismatch")]
    KeyMismatch,
    #[error("chain_mismatch")]
    ChainMismatch,
    #[error("token_expired_or_not_yet_valid")]
    Expired,
    #[error("token_replayed")]
    Replayed,
}

/// Verifies policy decision tokens before any signing work happens.
pub trait PolicyTokenVerifier: Send + Sync {
    /// Returns the verified claims, or the (audited) denial reason.
    fn verify(
        &self,
        token: &str,
        tx_payload: &[u8],
        key_id: &str,
        chain: Chain,
    ) -> Result<PolicyClaims, DenyReason>;
}

/// Ed25519-based verifier with freshness + single-use enforcement.
pub struct Ed25519TokenVerifier {
    policy_pubkey: VerifyingKey,
    max_skew_secs: u64,
    used: Arc<dyn UsedTokenStore>,
}

impl Ed25519TokenVerifier {
    /// `pubkey_hex` is the Policy Engine's 32-byte Ed25519 public key in hex.
    pub fn new(
        pubkey_hex: &str,
        max_skew_secs: u64,
        used: Arc<dyn UsedTokenStore>,
    ) -> anyhow::Result<Self> {
        let bytes = hex::decode(pubkey_hex)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("policy pubkey must be 32 bytes"))?;
        Ok(Self {
            policy_pubkey: VerifyingKey::from_bytes(&arr)?,
            max_skew_secs,
            used,
        })
    }
}

impl PolicyTokenVerifier for Ed25519TokenVerifier {
    fn verify(
        &self,
        token: &str,
        tx_payload: &[u8],
        key_id: &str,
        chain: Chain,
    ) -> Result<PolicyClaims, DenyReason> {
        let (claims_b64, sig_b64) = token.split_once('.').ok_or(DenyReason::Malformed)?;
        let claims_bytes = B64.decode(claims_b64).map_err(|_| DenyReason::Malformed)?;
        let sig_bytes = B64.decode(sig_b64).map_err(|_| DenyReason::Malformed)?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| DenyReason::Malformed)?;

        // 1. Signature over the exact claims bytes.
        let signature = Signature::from_bytes(&sig_arr);
        self.policy_pubkey
            .verify(&claims_bytes, &signature)
            .map_err(|_| DenyReason::BadSignature)?;

        let claims: PolicyClaims =
            serde_json::from_slice(&claims_bytes).map_err(|_| DenyReason::Malformed)?;

        // 2. Payload binding.
        if claims.tx_payload_hash != sha256_hex(tx_payload) {
            return Err(DenyReason::PayloadMismatch);
        }
        // 3. Key and chain binding.
        if claims.key_id != key_id {
            return Err(DenyReason::KeyMismatch);
        }
        if claims.chain != chain {
            return Err(DenyReason::ChainMismatch);
        }
        // 4. Freshness within skew.
        let now = unix_now();
        if claims.issued_at > now + self.max_skew_secs
            || claims.expires_at + self.max_skew_secs < now
        {
            return Err(DenyReason::Expired);
        }
        // 5. Single use — the atomic try_use is the replay gate.
        if !self.used.try_use(&claims.token_id, claims.expires_at) {
            return Err(DenyReason::Replayed);
        }
        Ok(claims)
    }
}

/// Test/dev helper: mint tokens the verifier accepts.
pub mod mint {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// Signs `claims` with `key`, producing the wire-format token.
    pub fn mint_token(key: &SigningKey, claims: &PolicyClaims) -> String {
        let claims_bytes = serde_json::to_vec(claims).expect("claims serialize");
        let sig = key.sign(&claims_bytes);
        format!(
            "{}.{}",
            B64.encode(&claims_bytes),
            B64.encode(sig.to_bytes())
        )
    }

    /// Standard claims for a payload/key/chain valid for `ttl_secs`.
    pub fn claims_for(payload: &[u8], key_id: &str, chain: Chain, ttl_secs: u64) -> PolicyClaims {
        let now = unix_now();
        PolicyClaims {
            token_id: uuid::Uuid::new_v4().to_string(),
            tx_payload_hash: sha256_hex(payload),
            key_id: key_id.to_string(),
            chain,
            issued_at: now,
            expires_at: now + ttl_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mint::{claims_for, mint_token};
    use super::*;
    use crate::store::InMemUsedTokenStore;
    use ed25519_dalek::SigningKey;

    fn setup() -> (SigningKey, Ed25519TokenVerifier) {
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifier = Ed25519TokenVerifier::new(
            &hex::encode(key.verifying_key().to_bytes()),
            30,
            Arc::new(InMemUsedTokenStore::new()),
        )
        .unwrap();
        (key, verifier)
    }

    #[test]
    fn valid_token_accepted() {
        let (key, v) = setup();
        let payload = b"tx-bytes";
        let token = mint_token(&key, &claims_for(payload, "k1", Chain::Evm, 60));
        let claims = v.verify(&token, payload, "k1", Chain::Evm).unwrap();
        assert_eq!(claims.key_id, "k1");
    }

    #[test]
    fn tampered_payload_rejected() {
        let (key, v) = setup();
        let token = mint_token(&key, &claims_for(b"tx-bytes", "k1", Chain::Evm, 60));
        let err = v
            .verify(&token, b"other-bytes", "k1", Chain::Evm)
            .unwrap_err();
        assert_eq!(err, DenyReason::PayloadMismatch);
    }

    #[test]
    fn key_mismatch_rejected() {
        let (key, v) = setup();
        let token = mint_token(&key, &claims_for(b"tx", "k1", Chain::Evm, 60));
        assert_eq!(
            v.verify(&token, b"tx", "other-key", Chain::Evm)
                .unwrap_err(),
            DenyReason::KeyMismatch
        );
    }

    #[test]
    fn chain_mismatch_rejected() {
        let (key, v) = setup();
        let token = mint_token(&key, &claims_for(b"tx", "k1", Chain::Evm, 60));
        assert_eq!(
            v.verify(&token, b"tx", "k1", Chain::Solana).unwrap_err(),
            DenyReason::ChainMismatch
        );
    }

    #[test]
    fn wrong_signer_rejected() {
        let (_, v) = setup();
        let rogue = SigningKey::generate(&mut rand::rngs::OsRng);
        let token = mint_token(&rogue, &claims_for(b"tx", "k1", Chain::Evm, 60));
        assert_eq!(
            v.verify(&token, b"tx", "k1", Chain::Evm).unwrap_err(),
            DenyReason::BadSignature
        );
    }

    #[test]
    fn expired_token_rejected() {
        let (key, v) = setup();
        let mut claims = claims_for(b"tx", "k1", Chain::Evm, 60);
        claims.issued_at = unix_now() - 3600;
        claims.expires_at = unix_now() - 1800; // expired beyond skew
        let token = mint_token(&key, &claims);
        assert_eq!(
            v.verify(&token, b"tx", "k1", Chain::Evm).unwrap_err(),
            DenyReason::Expired
        );
    }

    #[test]
    fn future_token_rejected() {
        let (key, v) = setup();
        let mut claims = claims_for(b"tx", "k1", Chain::Evm, 60);
        claims.issued_at = unix_now() + 3600; // issued in the future beyond skew
        claims.expires_at = unix_now() + 7200;
        let token = mint_token(&key, &claims);
        assert_eq!(
            v.verify(&token, b"tx", "k1", Chain::Evm).unwrap_err(),
            DenyReason::Expired
        );
    }

    #[test]
    fn replay_rejected() {
        let (key, v) = setup();
        let token = mint_token(&key, &claims_for(b"tx", "k1", Chain::Evm, 60));
        v.verify(&token, b"tx", "k1", Chain::Evm).unwrap();
        assert_eq!(
            v.verify(&token, b"tx", "k1", Chain::Evm).unwrap_err(),
            DenyReason::Replayed
        );
    }

    #[test]
    fn malformed_tokens_rejected() {
        let (_, v) = setup();
        for bad in ["", "notdotted", "a.b", "!!!.???"] {
            assert_eq!(
                v.verify(bad, b"tx", "k1", Chain::Evm).unwrap_err(),
                DenyReason::Malformed,
                "input: {bad:?}"
            );
        }
    }

    proptest::proptest! {
        // Property: a token minted for one payload never verifies any other
        // payload (token binding holds for arbitrary byte strings).
        #[test]
        fn token_bound_to_exact_payload(
            payload in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..256),
            other in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..256),
        ) {
            let (key, v) = setup();
            let token = mint_token(&key, &claims_for(&payload, "k1", Chain::Evm, 60));
            if payload == other {
                proptest::prop_assert!(v.verify(&token, &other, "k1", Chain::Evm).is_ok());
            } else {
                proptest::prop_assert_eq!(
                    v.verify(&token, &other, "k1", Chain::Evm).unwrap_err(),
                    DenyReason::PayloadMismatch
                );
            }
        }

        // Property: any corruption of the token string fails verification with
        // a deny reason — never a panic and never acceptance.
        #[test]
        fn corrupted_tokens_never_verify(flip_at in 0usize..64, xor in 1u8..255) {
            let (key, v) = setup();
            let payload = b"stable-payload";
            let token = mint_token(&key, &claims_for(payload, "k1", Chain::Evm, 60));
            let mut bytes = token.into_bytes();
            let idx = flip_at % bytes.len();
            bytes[idx] ^= xor;
            let corrupted = String::from_utf8_lossy(&bytes).to_string();
            proptest::prop_assert!(
                v.verify(&corrupted, payload, "k1", Chain::Evm).is_err()
            );
        }
    }

    #[test]
    fn concurrent_replay_single_winner() {
        let (key, _) = setup();
        let used: Arc<dyn UsedTokenStore> = Arc::new(InMemUsedTokenStore::new());
        let v = Arc::new(
            Ed25519TokenVerifier::new(&hex::encode(key.verifying_key().to_bytes()), 30, used)
                .unwrap(),
        );
        let token = mint_token(&key, &claims_for(b"tx", "k1", Chain::Evm, 60));
        let wins = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let v = v.clone();
            let token = token.clone();
            let wins = wins.clone();
            handles.push(std::thread::spawn(move || {
                if v.verify(&token, b"tx", "k1", Chain::Evm).is_ok() {
                    wins.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(wins.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
