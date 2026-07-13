//! Node attestation at cluster join.
//!
//! A joining node presents an attestation document that binds its mTLS public
//! key to the enclave measurement (PCR / MRENCLAVE) and HSM identity, signed
//! by the platform attestation authority (Nitro / SGX quoting enclave). The
//! verifier accepts only documents that are (1) authority-signed, (2) carry an
//! expected measurement, (3) name a trusted HSM identity, and (4) are fresh.
//!
//! Production parses real CBOR/COSE Nitro documents or SGX quotes; this models
//! the same trust checks over a signed JSON document so the join-time policy
//! and its failure modes are testable without enclave hardware.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::domain::unix_now;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AttestationError {
    #[error("attestation_malformed")]
    Malformed,
    #[error("attestation_signature_invalid")]
    BadSignature,
    #[error("attestation_measurement_mismatch")]
    MeasurementMismatch,
    #[error("attestation_untrusted_hsm")]
    UntrustedHsm,
    #[error("attestation_stale")]
    Stale,
    #[error("attestation_pubkey_mismatch")]
    PublicKeyMismatch,
}

/// Claims in an attestation document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDoc {
    /// Hex of the node's mTLS public key this document vouches for.
    pub node_public_key: String,
    /// Enclave measurement (e.g. Nitro PCR0 / SGX MRENCLAVE), hex.
    pub measurement: String,
    /// HSM identity that holds the node's wrapping key.
    pub hsm_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
}

/// Verifies attestation documents against the platform authority key and the
/// expected enclave measurement / trusted HSM set.
pub struct AttestationVerifier {
    authority: VerifyingKey,
    expected_measurement: String,
    trusted_hsms: Vec<String>,
    max_age_secs: u64,
}

impl AttestationVerifier {
    pub fn new(
        authority_pubkey_hex: &str,
        expected_measurement: &str,
        trusted_hsms: Vec<String>,
        max_age_secs: u64,
    ) -> anyhow::Result<Self> {
        let bytes = hex::decode(authority_pubkey_hex)?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("authority pubkey must be 32 bytes"))?;
        Ok(Self {
            authority: VerifyingKey::from_bytes(&arr)?,
            expected_measurement: expected_measurement.to_string(),
            trusted_hsms,
            max_age_secs,
        })
    }

    /// Verify `token` (`base64url(doc_json).base64url(sig)`) and confirm it
    /// vouches for `node_public_key_hex`.
    pub fn verify(
        &self,
        token: &str,
        node_public_key_hex: &str,
    ) -> Result<AttestationDoc, AttestationError> {
        let (doc_b64, sig_b64) = token.split_once('.').ok_or(AttestationError::Malformed)?;
        let doc_bytes = B64
            .decode(doc_b64)
            .map_err(|_| AttestationError::Malformed)?;
        let sig_bytes = B64
            .decode(sig_b64)
            .map_err(|_| AttestationError::Malformed)?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AttestationError::Malformed)?;

        self.authority
            .verify(&doc_bytes, &Signature::from_bytes(&sig_arr))
            .map_err(|_| AttestationError::BadSignature)?;

        let doc: AttestationDoc =
            serde_json::from_slice(&doc_bytes).map_err(|_| AttestationError::Malformed)?;

        if doc.measurement != self.expected_measurement {
            return Err(AttestationError::MeasurementMismatch);
        }
        if !self.trusted_hsms.iter().any(|h| h == &doc.hsm_id) {
            return Err(AttestationError::UntrustedHsm);
        }
        let now = unix_now();
        if doc.expires_at < now || doc.issued_at + self.max_age_secs < now {
            return Err(AttestationError::Stale);
        }
        if doc.node_public_key != node_public_key_hex {
            return Err(AttestationError::PublicKeyMismatch);
        }
        Ok(doc)
    }
}

/// Test/dev helper: mint attestation documents the verifier accepts.
pub mod mint {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    pub fn mint(authority: &SigningKey, doc: &AttestationDoc) -> String {
        let bytes = serde_json::to_vec(doc).expect("doc serialize");
        let sig = authority.sign(&bytes);
        format!("{}.{}", B64.encode(&bytes), B64.encode(sig.to_bytes()))
    }

    pub fn valid_doc(node_pubkey_hex: &str, measurement: &str, hsm_id: &str) -> AttestationDoc {
        let now = unix_now();
        AttestationDoc {
            node_public_key: node_pubkey_hex.to_string(),
            measurement: measurement.to_string(),
            hsm_id: hsm_id.to_string(),
            issued_at: now,
            expires_at: now + 300,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mint::{mint, valid_doc};
    use super::*;
    use ed25519_dalek::SigningKey;

    const MEAS: &str = "pcr0-abc123";
    const HSM: &str = "hsm-prod-1";

    fn setup() -> (SigningKey, AttestationVerifier) {
        let authority = SigningKey::generate(&mut rand::rngs::OsRng);
        let v = AttestationVerifier::new(
            &hex::encode(authority.verifying_key().to_bytes()),
            MEAS,
            vec![HSM.to_string()],
            300,
        )
        .unwrap();
        (authority, v)
    }

    #[test]
    fn valid_attestation_accepted() {
        let (authority, v) = setup();
        let token = mint(&authority, &valid_doc("node-pk-hex", MEAS, HSM));
        let doc = v.verify(&token, "node-pk-hex").unwrap();
        assert_eq!(doc.hsm_id, HSM);
    }

    #[test]
    fn wrong_measurement_rejected() {
        let (authority, v) = setup();
        let token = mint(&authority, &valid_doc("node-pk-hex", "pcr0-EVIL", HSM));
        assert_eq!(
            v.verify(&token, "node-pk-hex").unwrap_err(),
            AttestationError::MeasurementMismatch
        );
    }

    #[test]
    fn untrusted_hsm_rejected() {
        let (authority, v) = setup();
        let token = mint(&authority, &valid_doc("node-pk-hex", MEAS, "hsm-rogue"));
        assert_eq!(
            v.verify(&token, "node-pk-hex").unwrap_err(),
            AttestationError::UntrustedHsm
        );
    }

    #[test]
    fn wrong_authority_rejected() {
        let (_, v) = setup();
        let rogue = SigningKey::generate(&mut rand::rngs::OsRng);
        let token = mint(&rogue, &valid_doc("node-pk-hex", MEAS, HSM));
        assert_eq!(
            v.verify(&token, "node-pk-hex").unwrap_err(),
            AttestationError::BadSignature
        );
    }

    #[test]
    fn stale_attestation_rejected() {
        let (authority, v) = setup();
        let mut doc = valid_doc("node-pk-hex", MEAS, HSM);
        doc.issued_at = unix_now() - 10_000;
        doc.expires_at = unix_now() - 1;
        let token = mint(&authority, &doc);
        assert_eq!(
            v.verify(&token, "node-pk-hex").unwrap_err(),
            AttestationError::Stale
        );
    }

    #[test]
    fn pubkey_mismatch_rejected() {
        let (authority, v) = setup();
        let token = mint(&authority, &valid_doc("node-pk-hex", MEAS, HSM));
        assert_eq!(
            v.verify(&token, "different-node-pk").unwrap_err(),
            AttestationError::PublicKeyMismatch
        );
    }

    #[test]
    fn malformed_rejected() {
        let (_, v) = setup();
        for bad in ["", "no-dot", "a.b"] {
            assert!(v.verify(bad, "node-pk-hex").is_err());
        }
    }
}
