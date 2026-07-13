//! Smoke test against a RUNNING mpc-signing-service (e.g. the Docker image
//! with the INSECURE dev flags). Skipped unless TEST_MPC_GRPC_URL is set:
//!
//!   docker compose up -d --wait
//!   TEST_MPC_GRPC_URL=http://localhost:9090 cargo test --test container_smoke -- --nocapture

use mpc_signing_service::pb::mpc_signing_service_client::MpcSigningServiceClient;
use mpc_signing_service::pb::{DkgRequest, SignTxRequest};

#[tokio::test]
async fn dkg_and_sign_against_running_service() {
    let Some(url) = std::env::var("TEST_MPC_GRPC_URL")
        .ok()
        .filter(|v| !v.is_empty())
    else {
        eprintln!("TEST_MPC_GRPC_URL not set; skipping container smoke test");
        return;
    };

    let mut client = MpcSigningServiceClient::connect(url).await.unwrap();

    let dkg = client
        .dkg(DkgRequest {
            chain: 1, // EVM
            threshold: 2,
            parties: 3,
        })
        .await
        .unwrap()
        .into_inner();
    eprintln!(
        "dkg key_id={} pubkey={} bytes",
        dkg.key_id,
        dkg.public_key.len()
    );

    let resp = client
        .sign_tx(SignTxRequest {
            key_id: dkg.key_id,
            chain: 1,
            tx_payload: b"container-smoke-tx".to_vec(),
            policy_decision_token: String::new(), // INSECURE_SKIP_POLICY dev mode
            wallet_id: String::new(),
        })
        .await
        .unwrap()
        .into_inner();

    // verify the returned ECDSA signature against the DKG public key
    use k256::ecdsa::signature::Verifier as _;
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&resp.public_key).unwrap();
    let sig = k256::ecdsa::Signature::from_slice(&resp.signature).unwrap();
    vk.verify(b"container-smoke-tx", &sig).unwrap();
    eprintln!(
        "sign ok: session={} signature verifies against DKG public key",
        resp.signing_session_id
    );
}
