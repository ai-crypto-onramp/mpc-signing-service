//! Stage 7 acceptance: a local 3-node cluster (t=2, n=3) runs DKG → sign →
//! verify end-to-end for both curves; rotation produces new shares that sign
//! to the same public key; and t-1 nodes cannot produce a signature.
//!
//!   cargo test --test mpc_rounds --features in-house

#![cfg(feature = "in-house")]

use std::time::Duration;

use mpc_signing_service::engine::threshold::cluster::{Cluster, ThresholdError};
use mpc_signing_service::engine::threshold::curve::{Curve, Ed25519, Secp256k1};

async fn full_lifecycle<C: Curve>() {
    let cluster = Cluster::<C>::new(2, 3).unwrap();

    // DKG across 3 nodes, no dealer.
    let pk = cluster.keygen("key-a").await.unwrap();

    // t nodes sign; signature verifies against the DKG public key.
    let sig = cluster.sign("key-a", b"transfer 1 ETH").await.unwrap();
    assert!(C::verify(&pk, b"transfer 1 ETH", &sig));

    // Rotation refreshes shares without changing the public key / address.
    let (pk2, epoch) = cluster.refresh("key-a").await.unwrap();
    assert_eq!(pk, pk2, "rotation must preserve the public key");
    assert_eq!(epoch, 2);

    // Post-rotation signing verifies against the same key.
    let sig2 = cluster.sign("key-a", b"after rotation").await.unwrap();
    assert!(C::verify(&pk, b"after rotation", &sig2));
}

#[tokio::test]
async fn secp256k1_three_node_lifecycle() {
    full_lifecycle::<Secp256k1>().await;
}

#[tokio::test]
async fn ed25519_three_node_lifecycle() {
    full_lifecycle::<Ed25519>().await;
}

#[tokio::test]
async fn t_minus_one_nodes_cannot_sign() {
    let cluster = Cluster::<Secp256k1>::new(2, 3).unwrap();
    cluster.keygen("key-a").await.unwrap();

    // Take two nodes down; only 1 (< t) remains — signing must be refused.
    cluster.set_online(2, false);
    cluster.set_online(3, false);
    let err = cluster.sign("key-a", b"msg").await.unwrap_err();
    assert_eq!(err, ThresholdError::QuorumNotMet { needed: 2, got: 1 });
}

#[tokio::test]
async fn signatures_indistinguishable_from_single_key() {
    // A threshold signature must verify with the ordinary single-key verifier
    // and be the standard on-wire size (64 bytes for both schemes here).
    let ecdsa = Cluster::<Secp256k1>::new(2, 3).unwrap();
    let pk = ecdsa.keygen("k").await.unwrap();
    let sig = ecdsa.sign("k", b"m").await.unwrap();
    assert_eq!(sig.len(), 64);
    assert!(Secp256k1::verify(&pk, b"m", &sig));

    let eddsa = Cluster::<Ed25519>::new(2, 3).unwrap();
    let pk = eddsa.keygen("k").await.unwrap();
    let sig = eddsa.sign("k", b"m").await.unwrap();
    assert_eq!(sig.len(), 64);
    assert!(Ed25519::verify(&pk, b"m", &sig));
}

#[tokio::test]
async fn chaos_kill_and_restore_membership() {
    // Kill n-t nodes: signing still succeeds. Restore: rotation (full
    // membership) works again.
    let cluster = Cluster::<Secp256k1>::new(2, 3)
        .unwrap()
        .with_round_timeout(Duration::from_millis(200));
    let pk = cluster.keygen("k").await.unwrap();

    cluster.set_online(3, false); // 2 of 3 remain
    let sig = cluster.sign("k", b"degraded").await.unwrap();
    assert!(Secp256k1::verify(&pk, b"degraded", &sig));

    // Rotation needs full membership: fails while a node is down...
    assert!(cluster.refresh("k").await.is_err());
    // ...and succeeds once the node returns.
    cluster.set_online(3, true);
    let (pk2, _) = cluster.refresh("k").await.unwrap();
    assert_eq!(pk, pk2);
}
