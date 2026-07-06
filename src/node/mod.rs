//! Signing node coordination — inter-node mTLS, MPC round orchestration,
//! quorum tracking, timeouts.
//!
//! Stub. Stage 8+ implements node join / attestation and round orchestration.

#![allow(dead_code)]

use crate::Error;
use crate::Result;

/// A signing node's identity.
#[derive(Debug, Clone)]
pub struct NodeId(pub String);

/// Cluster membership / quorum tracker. Stage 8 implements real peer
/// discovery and quorum enforcement.
pub trait NodeCluster: Send + Sync {
    /// Number of live nodes that can currently participate.
    fn live_nodes(&self) -> usize;

    /// Whether at least `t` live nodes are reachable for a signing round.
    fn has_quorum(&self, threshold: usize) -> bool {
        self.live_nodes() >= threshold
    }

    /// Join a node to the cluster (stub).
    fn join(&self, node_id: &NodeId) -> Result<()> {
        let _ = node_id;
        Err(Error::Unimplemented("NodeCluster::join (Stage 8)"))
    }
}
