//! `KeyShareStore` boundary. Cleartext shares only ever exist inside the
//! enclave/HSM; `unwrap_share` returns cleartext strictly for use by
//! enclave-resident signing code, never to be logged or persisted by the host.

use std::collections::HashMap;
use std::sync::RwLock;

use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StoreError {
    #[error("share not found: {0}")]
    NotFound(String),
    #[error("unwrap failed: ciphertext integrity check failed")]
    IntegrityFailure,
    #[error("restore denied: quorum proof missing or invalid")]
    RestoreDenied,
}

/// Opaque wrapped share as seen by host code: ciphertext + integrity tag. The
/// cleartext is never present in this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedShare {
    pub key_id: String,
    pub node_id: String,
    pub ciphertext: Vec<u8>,
    pub tag: Vec<u8>,
}

/// Storage boundary for key shares. Implementations keep the wrapping key
/// inside the secure boundary; `unwrap_share` is the only path that yields
/// cleartext, and only into enclave-resident callers.
pub trait KeyShareStore: Send + Sync {
    /// Wrap a cleartext share for storage. The input cleartext is consumed.
    fn wrap_share(&self, key_id: &str, node_id: &str, cleartext: Vec<u8>) -> WrappedShare;
    /// Unwrap a stored share into enclave memory. Returns cleartext only for
    /// enclave-resident signing; host code must not log or persist it.
    fn unwrap_share_in_enclave(&self, key_id: &str, node_id: &str) -> Result<Vec<u8>, StoreError>;
    /// Export the wrapped (ciphertext) form for encrypted backup.
    fn backup(&self, key_id: &str, node_id: &str) -> Result<WrappedShare, StoreError>;
    /// Restore a wrapped share from backup — requires a valid quorum proof.
    fn restore(&self, wrapped: WrappedShare, quorum_proof: &[u8]) -> Result<(), StoreError>;
}

/// Software mock of an HSM-backed store for local dev / CI. NEVER used in
/// production (guarded at the call site by build/config). The "wrapping key"
/// is an in-process secret; real deployments use a non-exportable HSM key.
pub struct MockHsmStore {
    wrapping_key: [u8; 32],
    shares: RwLock<HashMap<String, WrappedShare>>,
}

impl Default for MockHsmStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MockHsmStore {
    pub fn new() -> Self {
        // A fixed dev wrapping key; a real HSM generates a non-exportable one.
        Self {
            wrapping_key: *b"mpc-mock-hsm-wrapping-key-32byte",
            shares: RwLock::new(HashMap::new()),
        }
    }

    fn slot(key_id: &str, node_id: &str) -> String {
        format!("{key_id}:{node_id}")
    }

    /// Keystream-XOR "wrap" keyed by the wrapping key + slot. Stands in for an
    /// HSM AEAD; the point is that host code never sees the wrapping key.
    fn keystream(&self, slot: &str, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut counter: u64 = 0;
        while out.len() < len {
            let mut mac = Hmac::<Sha256>::new_from_slice(&self.wrapping_key).expect("hmac key len");
            mac.update(slot.as_bytes());
            mac.update(&counter.to_be_bytes());
            out.extend_from_slice(&mac.finalize().into_bytes());
            counter += 1;
        }
        out.truncate(len);
        out
    }

    fn tag(&self, slot: &str, ciphertext: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.wrapping_key).expect("hmac key len");
        mac.update(b"tag");
        mac.update(slot.as_bytes());
        mac.update(ciphertext);
        mac.finalize().into_bytes().to_vec()
    }
}

impl KeyShareStore for MockHsmStore {
    fn wrap_share(&self, key_id: &str, node_id: &str, mut cleartext: Vec<u8>) -> WrappedShare {
        let slot = Self::slot(key_id, node_id);
        let ks = self.keystream(&slot, cleartext.len());
        let ciphertext: Vec<u8> = cleartext
            .iter()
            .zip(ks.iter())
            .map(|(a, b)| a ^ b)
            .collect();
        // Zeroize the caller's cleartext copy.
        for b in cleartext.iter_mut() {
            *b = 0;
        }
        let tag = self.tag(&slot, &ciphertext);
        let wrapped = WrappedShare {
            key_id: key_id.to_string(),
            node_id: node_id.to_string(),
            ciphertext,
            tag,
        };
        self.shares.write().unwrap().insert(slot, wrapped.clone());
        wrapped
    }

    fn unwrap_share_in_enclave(&self, key_id: &str, node_id: &str) -> Result<Vec<u8>, StoreError> {
        let slot = Self::slot(key_id, node_id);
        let wrapped = self
            .shares
            .read()
            .unwrap()
            .get(&slot)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(slot.clone()))?;
        if self.tag(&slot, &wrapped.ciphertext) != wrapped.tag {
            return Err(StoreError::IntegrityFailure);
        }
        let ks = self.keystream(&slot, wrapped.ciphertext.len());
        Ok(wrapped
            .ciphertext
            .iter()
            .zip(ks.iter())
            .map(|(a, b)| a ^ b)
            .collect())
    }

    fn backup(&self, key_id: &str, node_id: &str) -> Result<WrappedShare, StoreError> {
        let slot = Self::slot(key_id, node_id);
        self.shares
            .read()
            .unwrap()
            .get(&slot)
            .cloned()
            .ok_or(StoreError::NotFound(slot))
    }

    fn restore(&self, wrapped: WrappedShare, quorum_proof: &[u8]) -> Result<(), StoreError> {
        if quorum_proof.is_empty() {
            return Err(StoreError::RestoreDenied);
        }
        let slot = Self::slot(&wrapped.key_id, &wrapped.node_id);
        // Integrity-check before accepting a restored ciphertext.
        if self.tag(&slot, &wrapped.ciphertext) != wrapped.tag {
            return Err(StoreError::IntegrityFailure);
        }
        self.shares.write().unwrap().insert(slot, wrapped);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_unwrap_round_trip() {
        let store = MockHsmStore::new();
        let secret = vec![1u8, 2, 3, 4, 5];
        let wrapped = store.wrap_share("k1", "node-1", secret.clone());
        // Ciphertext must not equal cleartext (host never sees cleartext).
        assert_ne!(wrapped.ciphertext, secret);
        let unwrapped = store.unwrap_share_in_enclave("k1", "node-1").unwrap();
        assert_eq!(unwrapped, secret);
    }

    #[test]
    fn tampered_ciphertext_fails_integrity() {
        let store = MockHsmStore::new();
        store.wrap_share("k1", "node-1", vec![9, 9, 9]);
        // Tamper directly in the store.
        {
            let mut g = store.shares.write().unwrap();
            g.get_mut("k1:node-1").unwrap().ciphertext[0] ^= 0xFF;
        }
        assert_eq!(
            store.unwrap_share_in_enclave("k1", "node-1").unwrap_err(),
            StoreError::IntegrityFailure
        );
    }

    #[test]
    fn unknown_share_not_found() {
        let store = MockHsmStore::new();
        assert!(matches!(
            store.unwrap_share_in_enclave("k", "n").unwrap_err(),
            StoreError::NotFound(_)
        ));
    }

    #[test]
    fn backup_and_restore_requires_quorum_proof() {
        let src = MockHsmStore::new();
        let wrapped = src.wrap_share("k1", "node-1", vec![7, 7, 7, 7]);
        let backed = src.backup("k1", "node-1").unwrap();
        assert_eq!(backed, wrapped);

        // Restore into a fresh store — without a quorum proof it is denied.
        let dst = MockHsmStore::new();
        assert_eq!(
            dst.restore(backed.clone(), &[]).unwrap_err(),
            StoreError::RestoreDenied
        );
        // With a quorum proof it succeeds and unwraps to the original.
        dst.restore(backed, b"quorum-proof").unwrap();
        assert_eq!(
            dst.unwrap_share_in_enclave("k1", "node-1").unwrap(),
            vec![7, 7, 7, 7]
        );
    }

    #[test]
    fn restore_rejects_tampered_backup() {
        let store = MockHsmStore::new();
        let mut wrapped = store.wrap_share("k1", "node-1", vec![3, 1, 4]);
        wrapped.ciphertext[0] ^= 0x01;
        assert_eq!(
            store.restore(wrapped, b"quorum-proof").unwrap_err(),
            StoreError::IntegrityFailure
        );
    }
}
