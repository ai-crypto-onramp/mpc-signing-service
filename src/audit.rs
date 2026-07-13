//! Signed audit records + async emitter (Stage 9).
//!
//! Every signing attempt — approved or denied — produces a
//! `SigningAuditRecord` signed by this node's Ed25519 identity key. Records
//! are streamed to the Audit / Event Log asynchronously with retries; audit
//! delivery never blocks the sign path.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::domain::{unix_now, Chain, KeyId, SigningSessionId};

/// Outcome of a signing attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Signed,
    Denied,
    Failed,
}

/// One node's signature over the canonical record bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeSignature {
    pub node_id: String,
    /// Hex Ed25519 signature over the canonical (unsigned) record JSON.
    pub signature: String,
    /// Hex Ed25519 public key of the signing node.
    pub public_key: String,
}

/// Tamper-evident record of one signing attempt (matches README data model).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningAuditRecord {
    pub record_id: String,
    pub signing_session_id: SigningSessionId,
    pub key_id: KeyId,
    pub chain: Chain,
    /// Hex SHA-256 of the tx payload — never the payload itself.
    pub request_hash: String,
    pub participants: Vec<String>,
    pub result: AuditResult,
    pub denial_reason: Option<String>,
    /// Hex of the produced signature (empty on denial).
    pub signature: Option<String>,
    pub created_at: u64,
    /// Signatures by participant nodes over the canonical record.
    pub node_signatures: Vec<NodeSignature>,
}

impl SigningAuditRecord {
    /// Canonical bytes covered by node signatures: the record serialized with
    /// `node_signatures` empty.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut unsigned = self.clone();
        unsigned.node_signatures = Vec::new();
        serde_json::to_vec(&unsigned).expect("audit record serialize")
    }

    /// Verify every node signature against the canonical bytes.
    pub fn verify(&self) -> bool {
        if self.node_signatures.is_empty() {
            return false;
        }
        let bytes = self.canonical_bytes();
        self.node_signatures.iter().all(|ns| {
            let (Ok(sig_bytes), Ok(pk_bytes)) =
                (hex::decode(&ns.signature), hex::decode(&ns.public_key))
            else {
                return false;
            };
            let (Ok(sig_arr), Ok(pk_arr)) = (
                <[u8; 64]>::try_from(sig_bytes.as_slice()),
                <[u8; 32]>::try_from(pk_bytes.as_slice()),
            ) else {
                return false;
            };
            let Ok(pk) = VerifyingKey::from_bytes(&pk_arr) else {
                return false;
            };
            pk.verify(&bytes, &ed25519_dalek::Signature::from_bytes(&sig_arr))
                .is_ok()
        })
    }
}

/// Builds and signs audit records with this node's identity key.
pub struct AuditSigner {
    node_id: String,
    key: SigningKey,
}

impl AuditSigner {
    /// `seed_hex` is a 32-byte Ed25519 seed; when `None`, an ephemeral dev key
    /// is generated (audit records remain verifiable within the process).
    pub fn new(node_id: &str, seed_hex: Option<&str>) -> anyhow::Result<Self> {
        let key = match seed_hex {
            Some(h) => {
                let bytes = hex::decode(h)?;
                let arr: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("node signing key must be 32 bytes"))?;
                SigningKey::from_bytes(&arr)
            }
            None => SigningKey::generate(&mut rand::rngs::OsRng),
        };
        Ok(Self {
            node_id: node_id.to_string(),
            key,
        })
    }

    /// Builds a record for one signing attempt and signs it.
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        session_id: &SigningSessionId,
        key_id: &KeyId,
        chain: Chain,
        request_hash: &str,
        result: AuditResult,
        denial_reason: Option<String>,
        signature_hex: Option<String>,
    ) -> SigningAuditRecord {
        let mut rec = SigningAuditRecord {
            record_id: uuid::Uuid::new_v4().to_string(),
            signing_session_id: session_id.clone(),
            key_id: key_id.clone(),
            chain,
            request_hash: request_hash.to_string(),
            participants: vec![self.node_id.clone()],
            result,
            denial_reason,
            signature: signature_hex,
            created_at: unix_now(),
            node_signatures: Vec::new(),
        };
        let sig = self.key.sign(&rec.canonical_bytes());
        rec.node_signatures.push(NodeSignature {
            node_id: self.node_id.clone(),
            signature: hex::encode(sig.to_bytes()),
            public_key: hex::encode(self.key.verifying_key().to_bytes()),
        });
        rec
    }
}

/// Sink receiving finished audit records (the Audit / Event Log, or a test
/// collector).
#[async_trait::async_trait]
pub trait AuditSink: Send + Sync {
    async fn deliver(&self, record: &SigningAuditRecord) -> anyhow::Result<()>;
}

/// HTTP sink POSTing records to `AUDIT_EVENT_LOG_URL/v1/events`.
pub struct HttpAuditSink {
    url: String,
    client: reqwest::Client,
}

impl HttpAuditSink {
    pub fn new(base_url: &str) -> Self {
        Self {
            url: format!("{}/v1/events", base_url.trim_end_matches('/')),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl AuditSink for HttpAuditSink {
    async fn deliver(&self, record: &SigningAuditRecord) -> anyhow::Result<()> {
        let resp = self.client.post(&self.url).json(record).send().await?;
        if !resp.status().is_success() {
            anyhow::bail!("audit sink returned {}", resp.status());
        }
        Ok(())
    }
}

/// Async, non-blocking audit emitter with bounded retries.
#[derive(Clone)]
pub struct AuditEmitter {
    tx: mpsc::Sender<SigningAuditRecord>,
}

impl AuditEmitter {
    /// Spawns the background delivery task. When `sink` is `None`, records
    /// are logged and dropped (local dev).
    pub fn start(sink: Option<Arc<dyn AuditSink>>) -> Self {
        let (tx, mut rx) = mpsc::channel::<SigningAuditRecord>(1024);
        tokio::spawn(async move {
            while let Some(rec) = rx.recv().await {
                match &sink {
                    None => {
                        tracing::info!(record_id = %rec.record_id, result = ?rec.result, "audit record (no sink configured)");
                    }
                    Some(s) => {
                        let mut attempt = 0u32;
                        loop {
                            match s.deliver(&rec).await {
                                Ok(()) => break,
                                Err(err) if attempt < 3 => {
                                    attempt += 1;
                                    tracing::warn!(record_id = %rec.record_id, %err, attempt, "audit delivery retry");
                                    tokio::time::sleep(Duration::from_millis(
                                        100 * 2u64.pow(attempt),
                                    ))
                                    .await;
                                }
                                Err(err) => {
                                    tracing::error!(record_id = %rec.record_id, %err, "audit delivery failed; dropping");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });
        Self { tx }
    }

    /// Queues a record without blocking the sign path. A full queue drops the
    /// record with an error log rather than stalling signing.
    pub fn emit(&self, record: SigningAuditRecord) {
        if let Err(err) = self.tx.try_send(record) {
            tracing::error!(%err, "audit queue full; record dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn signer() -> AuditSigner {
        AuditSigner::new("node-test", None).unwrap()
    }

    fn sample_record(s: &AuditSigner) -> SigningAuditRecord {
        s.record(
            &SigningSessionId("sess-1".into()),
            &KeyId("k1".into()),
            Chain::Evm,
            "deadbeef",
            AuditResult::Signed,
            None,
            Some("aabb".into()),
        )
    }

    #[test]
    fn record_signs_and_verifies() {
        let rec = sample_record(&signer());
        assert!(rec.verify());
        assert_eq!(rec.participants, vec!["node-test"]);
    }

    #[test]
    fn tampered_record_fails_verification() {
        let mut rec = sample_record(&signer());
        rec.request_hash = "beefdead".into();
        assert!(!rec.verify());
    }

    #[test]
    fn unsigned_record_fails_verification() {
        let mut rec = sample_record(&signer());
        rec.node_signatures.clear();
        assert!(!rec.verify());
    }

    #[test]
    fn seeded_signer_is_deterministic() {
        let seed = hex::encode([7u8; 32]);
        let a = AuditSigner::new("n", Some(&seed)).unwrap();
        let b = AuditSigner::new("n", Some(&seed)).unwrap();
        let ra = sample_record(&a);
        let rb = sample_record(&b);
        assert_eq!(
            ra.node_signatures[0].public_key,
            rb.node_signatures[0].public_key
        );
    }

    struct CollectingSink(Mutex<Vec<SigningAuditRecord>>, std::sync::atomic::AtomicU32);

    #[async_trait::async_trait]
    impl AuditSink for CollectingSink {
        async fn deliver(&self, record: &SigningAuditRecord) -> anyhow::Result<()> {
            // Fail the first attempt to exercise the retry path.
            if self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                anyhow::bail!("transient");
            }
            self.0.lock().unwrap().push(record.clone());
            Ok(())
        }
    }

    #[tokio::test]
    async fn emitter_delivers_with_retry() {
        let sink = Arc::new(CollectingSink(
            Mutex::new(Vec::new()),
            std::sync::atomic::AtomicU32::new(0),
        ));
        let emitter = AuditEmitter::start(Some(sink.clone()));
        emitter.emit(sample_record(&signer()));
        // allow the background task to retry and deliver
        for _ in 0..50 {
            if !sink.0.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(sink.0.lock().unwrap().len(), 1);
        assert!(sink.0.lock().unwrap()[0].verify());
    }

    #[tokio::test]
    async fn emitter_without_sink_does_not_block() {
        let emitter = AuditEmitter::start(None);
        for _ in 0..10 {
            emitter.emit(sample_record(&signer()));
        }
    }
}
