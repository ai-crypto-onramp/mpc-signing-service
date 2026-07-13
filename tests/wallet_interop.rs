//! Live interop test against a REAL wallet-management instance speaking its
//! JSON-codec gRPC. Skipped unless TEST_WALLET_MGMT_URL is set, e.g.:
//!
//!   docker compose -f ../.github/docker-compose.yml up -d wallet-management
//!   TEST_WALLET_MGMT_URL=http://localhost:9090 cargo test --test wallet_interop -- --nocapture

use mpc_signing_service::wallet::{GrpcWalletClient, WalletError, WalletManagementClient};

#[tokio::test]
async fn resolve_key_id_against_real_wallet_management() {
    let Some(url) = std::env::var("TEST_WALLET_MGMT_URL")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        eprintln!("TEST_WALLET_MGMT_URL not set; skipping live interop test");
        return;
    };

    let client = GrpcWalletClient::connect(&url).await.unwrap();

    // A random wallet id must round-trip the JSON codec and come back as a
    // clean NotFound — not a transport/codec failure.
    let wallet_id = uuid::Uuid::new_v4().to_string();
    match client.resolve_keys(&wallet_id).await {
        Err(WalletError::NotFound) => {
            eprintln!("wallet-management returned NotFound (expected for a random id)");
        }
        Ok(rec) => panic!("random wallet id unexpectedly resolved: {rec:?}"),
        Err(WalletError::Unavailable(msg)) => {
            // Codec-level failures would surface here — fail loudly.
            panic!("interop failure talking to wallet-management: {msg}");
        }
        Err(other) => panic!("unexpected error: {other}"),
    }

    // Positive path: TEST_WALLET_ID names a wallet with a bound key (e.g.
    // created via wallet-management's REST API before running this test).
    if let Ok(known) = std::env::var("TEST_WALLET_ID") {
        if !known.is_empty() {
            let rec = client
                .resolve_keys(&known)
                .await
                .expect("known wallet must resolve");
            eprintln!("resolved {known}: {rec:?}");
            assert!(
                !rec.current_key_id.is_empty() || !rec.key_ids.is_empty(),
                "known wallet must have at least one key id"
            );
        }
    }
}
