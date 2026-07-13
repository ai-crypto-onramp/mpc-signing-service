//! Custody adapter integration tests against a mock provider (wiremock).
//!
//! The shared `CustodyHttp` core (used by all three feature-gated adapters)
//! is exercised directly: happy path with locally verified signatures,
//! provider rejection, unknown key, provider outage, and a malicious
//! provider returning a signature that does not verify.

use k256::ecdsa::signature::Signer as _;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use mpc_signing_service::domain::{Chain, KeyId};
use mpc_signing_service::engine::custody::{CustodyHttp, ProviderProfile};
use mpc_signing_service::engine::{DkgParams, EngineError, EngineSignRequest, RestoreParams};

fn profile() -> ProviderProfile {
    ProviderProfile {
        name: "fireblocks",
        auth_header: "Authorization",
        auth_prefix: "Bearer ",
    }
}

fn http(base: &str) -> CustodyHttp {
    CustodyHttp::new(profile(), base, "test-api-key")
}

fn sign_request() -> EngineSignRequest {
    EngineSignRequest {
        key_id: KeyId("prov-key-1".into()),
        chain: Chain::Evm,
        payload: b"evm-tx-bytes".to_vec(),
    }
}

#[tokio::test]
async fn sign_happy_path_verifies_provider_signature() {
    let server = MockServer::start().await;

    // The mock provider signs with a real secp256k1 key.
    let sk = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let sig: k256::ecdsa::Signature = sk.sign(b"evm-tx-bytes");

    Mock::given(method("POST"))
        .and(path("/v1/fireblocks/sign"))
        .and(header("Authorization", "Bearer test-api-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature_hex": hex::encode(sig.to_vec()),
            "public_key_hex": hex::encode(sk.verifying_key().to_sec1_bytes()),
        })))
        .mount(&server)
        .await;

    let out = http(&server.uri()).sign(&sign_request()).await.unwrap();
    assert_eq!(out.signature, sig.to_vec());
}

#[tokio::test]
async fn tampered_provider_signature_rejected() {
    let server = MockServer::start().await;

    // valid key, but a signature over DIFFERENT bytes — must not be accepted
    let sk = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let sig: k256::ecdsa::Signature = sk.sign(b"some-other-payload");

    Mock::given(method("POST"))
        .and(path("/v1/fireblocks/sign"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature_hex": hex::encode(sig.to_vec()),
            "public_key_hex": hex::encode(sk.verifying_key().to_sec1_bytes()),
        })))
        .mount(&server)
        .await;

    let err = http(&server.uri()).sign(&sign_request()).await.unwrap_err();
    assert!(matches!(err, EngineError::Internal(_)), "got {err:?}");
    assert!(err.to_string().contains("signature verification failed"));
}

#[tokio::test]
async fn provider_rejection_maps_to_denied() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/fireblocks/sign"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let err = http(&server.uri()).sign(&sign_request()).await.unwrap_err();
    assert!(matches!(err, EngineError::Denied(_)), "got {err:?}");
}

#[tokio::test]
async fn unknown_key_maps_to_not_found() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/fireblocks/sign"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let err = http(&server.uri()).sign(&sign_request()).await.unwrap_err();
    assert!(matches!(err, EngineError::KeyNotFound(_)), "got {err:?}");
}

#[tokio::test]
async fn provider_5xx_maps_to_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/fireblocks/sign"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let err = http(&server.uri()).sign(&sign_request()).await.unwrap_err();
    assert!(
        matches!(err, EngineError::ProviderUnavailable(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn provider_connection_refused_maps_to_unavailable() {
    // no server listening on this port
    let err = http("http://127.0.0.1:1")
        .sign(&sign_request())
        .await
        .unwrap_err();
    assert!(
        matches!(err, EngineError::ProviderUnavailable(_)),
        "got {err:?}"
    );
}

#[tokio::test]
async fn dkg_rotate_metadata_flow() {
    let server = MockServer::start().await;
    let pk_hex = hex::encode([2u8; 33]);

    Mock::given(method("POST"))
        .and(path("/v1/fireblocks/keys"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "key_id": "prov-key-1",
            "public_key_hex": pk_hex,
            "epoch": 1,
        })))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/fireblocks/keys/prov-key-1/rotate"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "key_id": "prov-key-1",
            "public_key_hex": pk_hex,
            "epoch": 2,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/fireblocks/keys/prov-key-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "key_id": "prov-key-1",
            "public_key_hex": pk_hex,
            "epoch": 2,
            "status": "cooling",
        })))
        .mount(&server)
        .await;

    let h = http(&server.uri());
    let dkg = h
        .dkg(&DkgParams {
            chain: Chain::Evm,
            threshold: 2,
            parties: 3,
        })
        .await
        .unwrap();
    assert_eq!(dkg.key_id.0, "prov-key-1");

    let rot = h.rotate(&dkg.key_id).await.unwrap();
    assert_eq!(rot.epoch, 2);
    assert_eq!(rot.public_key, dkg.public_key);

    let meta = h.key_metadata(&dkg.key_id, Chain::Evm).await.unwrap();
    assert_eq!(meta.epoch, 2);
    assert_eq!(
        meta.status,
        mpc_signing_service::domain::KeyShareStatus::Cooling
    );
}

#[tokio::test]
async fn restore_requires_quorum_proof() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/fireblocks/keys/prov-key-1/restore"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
        .mount(&server)
        .await;

    let h = http(&server.uri());
    let err = h
        .restore(&RestoreParams {
            key_id: KeyId("prov-key-1".into()),
            node_id: "n1".into(),
            quorum_proof: vec![],
        })
        .await
        .unwrap_err();
    assert!(matches!(err, EngineError::Denied(_)));

    assert!(h
        .restore(&RestoreParams {
            key_id: KeyId("prov-key-1".into()),
            node_id: "n1".into(),
            quorum_proof: vec![1],
        })
        .await
        .unwrap());
}

#[tokio::test]
async fn ed25519_provider_signature_verified() {
    use ed25519_dalek::Signer as _;
    let server = MockServer::start().await;

    let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let sig = sk.sign(b"sol-tx");

    Mock::given(method("POST"))
        .and(path("/v1/fireblocks/sign"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature_hex": hex::encode(sig.to_bytes()),
            "public_key_hex": hex::encode(sk.verifying_key().to_bytes()),
        })))
        .mount(&server)
        .await;

    let req = EngineSignRequest {
        key_id: KeyId("prov-key-1".into()),
        chain: Chain::Solana,
        payload: b"sol-tx".to_vec(),
    };
    let out = http(&server.uri()).sign(&req).await.unwrap();
    assert_eq!(out.signature, sig.to_bytes().to_vec());
}
