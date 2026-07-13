//! Domain types shared across policy, engine, store, and audit modules.

use serde::{Deserialize, Serialize};

/// Chain families the service can sign for. Mirrors the proto `Chain` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Evm,
    Solana,
    Aptos,
    Sui,
    Bitcoin,
}

impl Chain {
    /// Signature scheme used by the chain family.
    pub fn scheme(&self) -> SignatureScheme {
        match self {
            Chain::Evm | Chain::Bitcoin => SignatureScheme::EcdsaSecp256k1,
            Chain::Solana | Chain::Aptos | Chain::Sui => SignatureScheme::Ed25519,
        }
    }

    pub fn from_proto(v: i32) -> Option<Self> {
        match v {
            1 => Some(Chain::Evm),
            2 => Some(Chain::Solana),
            3 => Some(Chain::Aptos),
            4 => Some(Chain::Sui),
            5 => Some(Chain::Bitcoin),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Chain::Evm => "evm",
            Chain::Solana => "solana",
            Chain::Aptos => "aptos",
            Chain::Sui => "sui",
            Chain::Bitcoin => "bitcoin",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    EcdsaSecp256k1,
    Ed25519,
}

/// Opaque identifier of a signing key (assigned at DKG / provider onboarding).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyId(pub String);

/// Identifier of an MPC node participating in ceremonies.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub String);

/// Identifier of one signing session (one SignTx attempt).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SigningSessionId(pub String);

impl SigningSessionId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
}

impl Default for SigningSessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Lifecycle of a signing session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Pending,
    Denied,
    Signing,
    Signed,
    Failed,
}

/// Lifecycle of a key share held by a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyShareStatus {
    Active,
    Cooling,
    Retired,
}

/// Metadata about a key share (never the share material itself).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    pub key_id: KeyId,
    pub node_id: NodeId,
    pub chain: Chain,
    pub epoch: u64,
    pub status: KeyShareStatus,
}

/// One signing attempt tracked from request to signature or denial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningSession {
    pub id: SigningSessionId,
    pub key_id: KeyId,
    pub chain: Chain,
    /// SHA-256 of the tx payload (never the payload itself).
    pub request_hash: String,
    pub status: SessionStatus,
    pub denial_reason: Option<String>,
    pub created_at_unix: u64,
}

/// Public metadata for a key, as returned by GetKeyMetadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub key_id: KeyId,
    pub chain: Chain,
    pub public_key: Vec<u8>,
    pub status: KeyShareStatus,
    pub epoch: u64,
}

/// Current unix time in seconds.
pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Hex-encoded SHA-256 of arbitrary bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_scheme_mapping() {
        assert_eq!(Chain::Evm.scheme(), SignatureScheme::EcdsaSecp256k1);
        assert_eq!(Chain::Bitcoin.scheme(), SignatureScheme::EcdsaSecp256k1);
        assert_eq!(Chain::Solana.scheme(), SignatureScheme::Ed25519);
        assert_eq!(Chain::Aptos.scheme(), SignatureScheme::Ed25519);
        assert_eq!(Chain::Sui.scheme(), SignatureScheme::Ed25519);
    }

    #[test]
    fn chain_proto_round_trip() {
        for (i, c) in [
            (1, Chain::Evm),
            (2, Chain::Solana),
            (3, Chain::Aptos),
            (4, Chain::Sui),
            (5, Chain::Bitcoin),
        ] {
            assert_eq!(Chain::from_proto(i), Some(c));
        }
        assert_eq!(Chain::from_proto(0), None);
        assert_eq!(Chain::from_proto(42), None);
    }

    #[test]
    fn sha256_hex_known_vector() {
        // sha256("abc")
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
