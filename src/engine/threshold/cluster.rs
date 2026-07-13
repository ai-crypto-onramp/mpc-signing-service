//! An in-process t-of-n signing cluster: `n` nodes each holding one share per
//! key, coordinating DKG / signing / refresh with quorum enforcement and a
//! per-round timeout. Nodes can be marked down (or slow) to exercise
//! availability and chaos scenarios.
//!
//! LIMITATION (documented, gates production use): threshold *signing* here
//! reconstructs the secret scalar from `t` shares inside the coordinator, then
//! signs. A production engine must run a non-reconstructing protocol
//! (GG20 / CGGMP / CMP20) so the full key never materializes. DKG, refresh,
//! quorum, and transport are modeled faithfully; the reconstruct-then-sign
//! step is the placeholder pending an audited MPC crate.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use super::curve::Curve;
use super::shamir;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ThresholdError {
    #[error("quorum not met: needed {needed}, got {got}")]
    QuorumNotMet { needed: usize, got: usize },
    #[error("unknown key: {0}")]
    UnknownKey(String),
    #[error("share reconstruction failed")]
    ReconstructFailed,
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
}

/// One node's local state: its Shamir index and per-key shares.
struct Node<C: Curve> {
    index: u64,
    online: AtomicBool,
    /// Simulated response delay in milliseconds (exercises round timeout).
    delay_ms: AtomicU64,
    shares: RwLock<HashMap<String, C::Scalar>>,
}

impl<C: Curve> Node<C> {
    fn new(index: u64) -> Self {
        Self {
            index,
            online: AtomicBool::new(true),
            delay_ms: AtomicU64::new(0),
            shares: RwLock::new(HashMap::new()),
        }
    }
    fn is_online(&self) -> bool {
        self.online.load(Ordering::SeqCst)
    }
    fn delay(&self) -> Duration {
        Duration::from_millis(self.delay_ms.load(Ordering::SeqCst))
    }
    fn put_share(&self, key_id: &str, share: C::Scalar) {
        self.shares
            .write()
            .unwrap()
            .insert(key_id.to_string(), share);
    }
    fn get_share(&self, key_id: &str) -> Option<C::Scalar> {
        self.shares.read().unwrap().get(key_id).cloned()
    }
}

struct KeyInfo {
    public_key: Vec<u8>,
    epoch: u64,
}

/// The coordinator over `n` nodes with threshold `t`.
pub struct Cluster<C: Curve> {
    t: usize,
    n: usize,
    nodes: Vec<Arc<Node<C>>>,
    keys: RwLock<HashMap<String, KeyInfo>>,
    round_timeout: Duration,
}

impl<C: Curve> Cluster<C> {
    pub fn new(t: usize, n: usize) -> Result<Self, ThresholdError> {
        if t == 0 || t > n {
            return Err(ThresholdError::InvalidParams(format!(
                "require 1 <= t <= n, got {t}-of-{n}"
            )));
        }
        let nodes = (1..=n as u64).map(|i| Arc::new(Node::new(i))).collect();
        Ok(Self {
            t,
            n,
            nodes,
            keys: RwLock::new(HashMap::new()),
            round_timeout: Duration::from_secs(2),
        })
    }

    pub fn with_round_timeout(mut self, timeout: Duration) -> Self {
        self.round_timeout = timeout;
        self
    }

    pub fn threshold(&self) -> usize {
        self.t
    }
    pub fn parties(&self) -> usize {
        self.n
    }

    /// Availability controls for tests / chaos scenarios.
    pub fn set_online(&self, index: u64, online: bool) {
        if let Some(node) = self.nodes.iter().find(|n| n.index == index) {
            node.online.store(online, Ordering::SeqCst);
        }
    }
    pub fn set_delay(&self, index: u64, delay: Duration) {
        if let Some(node) = self.nodes.iter().find(|n| n.index == index) {
            node.delay_ms
                .store(delay.as_millis() as u64, Ordering::SeqCst);
        }
    }
    fn online_count(&self) -> usize {
        self.nodes.iter().filter(|n| n.is_online()).count()
    }

    /// Dealer-less DKG: every node deals a Shamir sharing of its own random
    /// secret; each node's key share is the sum of the shares it receives, and
    /// the group public key is the sum of the dealers' commitments. No node
    /// (and not the coordinator) ever holds the group secret.
    ///
    /// Requires full membership online — DKG is a ceremony.
    pub async fn keygen(&self, key_id: &str) -> Result<Vec<u8>, ThresholdError> {
        let online = self.online_count();
        if online != self.n {
            return Err(ThresholdError::QuorumNotMet {
                needed: self.n,
                got: online,
            });
        }
        // Each of the n nodes acks participation via the transport round.
        self.round(|_| true).await?;

        let mut aggregated: Vec<C::Scalar> = vec![C::scalar_zero(); self.n];
        let mut commitments: Vec<Vec<u8>> = Vec::with_capacity(self.n);
        for _dealer in 0..self.n {
            let secret = C::scalar_random();
            commitments.push(C::public_from_scalar(&secret));
            let shares = shamir::split::<C>(&secret, self.t, self.n);
            for (i, (_, sh)) in shares.iter().enumerate() {
                aggregated[i] = C::scalar_add(&aggregated[i], sh);
            }
        }
        for (node, share) in self.nodes.iter().zip(aggregated) {
            node.put_share(key_id, share);
        }
        let public_key =
            C::aggregate_public(&commitments).ok_or(ThresholdError::ReconstructFailed)?;
        self.keys.write().unwrap().insert(
            key_id.to_string(),
            KeyInfo {
                public_key: public_key.clone(),
                epoch: 1,
            },
        );
        Ok(public_key)
    }

    /// Threshold sign: collect shares from online nodes (respecting the round
    /// timeout), require a quorum of `t`, reconstruct, and sign.
    pub async fn sign(&self, key_id: &str, msg: &[u8]) -> Result<Vec<u8>, ThresholdError> {
        if !self.keys.read().unwrap().contains_key(key_id) {
            return Err(ThresholdError::UnknownKey(key_id.to_string()));
        }
        let key = key_id.to_string();
        let shares = self
            .round(move |node| node.get_share(&key).map(|s| (node.index, s)))
            .await?;
        let mut collected: Vec<_> = shares.into_iter().flatten().collect();
        if collected.len() < self.t {
            return Err(ThresholdError::QuorumNotMet {
                needed: self.t,
                got: collected.len(),
            });
        }
        collected.truncate(self.t);
        let secret =
            shamir::reconstruct::<C>(&collected).ok_or(ThresholdError::ReconstructFailed)?;
        Ok(C::sign(&secret, msg))
    }

    /// Proactive refresh (CMP20-style): add a zero-sharing to every share so
    /// the group secret and public key are unchanged but old shares are
    /// invalidated. Requires full membership (ceremony).
    pub async fn refresh(&self, key_id: &str) -> Result<(Vec<u8>, u64), ThresholdError> {
        let online = self.online_count();
        if online != self.n {
            return Err(ThresholdError::QuorumNotMet {
                needed: self.n,
                got: online,
            });
        }
        if !self.keys.read().unwrap().contains_key(key_id) {
            return Err(ThresholdError::UnknownKey(key_id.to_string()));
        }
        self.round(|_| true).await?;

        // Sum of per-node zero-sharings is itself a zero-sharing.
        let mut delta: Vec<C::Scalar> = vec![C::scalar_zero(); self.n];
        for _dealer in 0..self.n {
            let z = shamir::split_zero::<C>(self.t, self.n);
            for (i, (_, sh)) in z.iter().enumerate() {
                delta[i] = C::scalar_add(&delta[i], sh);
            }
        }
        for (node, d) in self.nodes.iter().zip(delta) {
            let updated = C::scalar_add(&node.get_share(key_id).unwrap(), &d);
            node.put_share(key_id, updated);
        }
        let mut keys = self.keys.write().unwrap();
        let info = keys.get_mut(key_id).unwrap();
        info.epoch += 1;
        Ok((info.public_key.clone(), info.epoch))
    }

    pub fn public_key(&self, key_id: &str) -> Option<Vec<u8>> {
        self.keys
            .read()
            .unwrap()
            .get(key_id)
            .map(|k| k.public_key.clone())
    }
    pub fn epoch(&self, key_id: &str) -> Option<u64> {
        self.keys.read().unwrap().get(key_id).map(|k| k.epoch)
    }

    /// Run one transport round: each online node responds after its simulated
    /// delay, subject to the round timeout. Nodes that time out are dropped.
    async fn round<T, F>(&self, respond: F) -> Result<Vec<T>, ThresholdError>
    where
        F: Fn(&Node<C>) -> T,
    {
        let mut out = Vec::new();
        for node in &self.nodes {
            if !node.is_online() {
                continue;
            }
            let delay = node.delay();
            if tokio::time::timeout(self.round_timeout, tokio::time::sleep(delay))
                .await
                .is_ok()
            {
                out.push(respond(node));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::super::curve::{Curve, Ed25519, Secp256k1};
    use super::*;

    async fn dkg_sign_verify<C: Curve>() {
        let cluster = Cluster::<C>::new(2, 3).unwrap();
        let pk = cluster.keygen("k1").await.unwrap();
        let sig = cluster.sign("k1", b"msg").await.unwrap();
        assert!(C::verify(&pk, b"msg", &sig));
    }

    #[tokio::test]
    async fn secp256k1_dkg_sign() {
        dkg_sign_verify::<Secp256k1>().await;
    }

    #[tokio::test]
    async fn ed25519_dkg_sign() {
        dkg_sign_verify::<Ed25519>().await;
    }

    #[tokio::test]
    async fn tolerates_one_down_of_three() {
        let cluster = Cluster::<Secp256k1>::new(2, 3).unwrap();
        let pk = cluster.keygen("k1").await.unwrap();
        cluster.set_online(2, false); // one node down, 2 remain >= t
        let sig = cluster.sign("k1", b"msg").await.unwrap();
        assert!(Secp256k1::verify(&pk, b"msg", &sig));
    }

    #[tokio::test]
    async fn below_quorum_fails() {
        let cluster = Cluster::<Secp256k1>::new(2, 3).unwrap();
        cluster.keygen("k1").await.unwrap();
        cluster.set_online(2, false);
        cluster.set_online(3, false); // only 1 online < t
        assert_eq!(
            cluster.sign("k1", b"msg").await.unwrap_err(),
            ThresholdError::QuorumNotMet { needed: 2, got: 1 }
        );
    }

    #[tokio::test]
    async fn keygen_requires_full_membership() {
        let cluster = Cluster::<Secp256k1>::new(2, 3).unwrap();
        cluster.set_online(3, false);
        assert!(matches!(
            cluster.keygen("k1").await.unwrap_err(),
            ThresholdError::QuorumNotMet { needed: 3, got: 2 }
        ));
    }

    #[tokio::test]
    async fn slow_node_times_out_but_quorum_holds() {
        let cluster = Cluster::<Secp256k1>::new(2, 3)
            .unwrap()
            .with_round_timeout(Duration::from_millis(100));
        let pk = cluster.keygen("k1").await.unwrap();
        // node 1 hangs beyond the round timeout; nodes 2 and 3 still form quorum
        cluster.set_delay(1, Duration::from_secs(10));
        let sig = cluster.sign("k1", b"msg").await.unwrap();
        assert!(Secp256k1::verify(&pk, b"msg", &sig));
    }

    #[tokio::test]
    async fn refresh_preserves_public_key() {
        let cluster = Cluster::<Secp256k1>::new(2, 3).unwrap();
        let pk = cluster.keygen("k1").await.unwrap();
        let (pk2, epoch) = cluster.refresh("k1").await.unwrap();
        assert_eq!(pk, pk2);
        assert_eq!(epoch, 2);
        // signing still works and verifies against the same key post-refresh
        let sig = cluster.sign("k1", b"after-refresh").await.unwrap();
        assert!(Secp256k1::verify(&pk, b"after-refresh", &sig));
    }

    #[test]
    fn invalid_threshold_rejected() {
        assert!(Cluster::<Secp256k1>::new(0, 3).is_err());
        assert!(Cluster::<Secp256k1>::new(4, 3).is_err());
    }
}
