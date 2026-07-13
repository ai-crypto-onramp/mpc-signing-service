//! Per-provider adapter smoke tests (compiled only with the matching
//! feature; CI runs them via `cargo test --all-features`). The shared
//! behavior is covered in custody_adapter.rs — these prove each adapter's
//! config loading, URL layout, and auth header.

#![allow(unused_imports)]

use mpc_signing_service::config::{Config, CustodyProvider};
use mpc_signing_service::domain::{Chain, KeyId};
use mpc_signing_service::engine::{EngineSignRequest, SigningEngine};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[allow(dead_code)]
fn cfg_with(provider: CustodyProvider, url: Option<&str>) -> Config {
    Config {
        custody_provider: provider,
        custody_api_url: url.map(String::from),
        custody_api_key: Some("adapter-key".into()),
        ..Config::default()
    }
}

#[allow(dead_code)]
async fn mock_provider(provider_path: &str, auth_header: &str, auth_value: &str) -> MockServer {
    use k256::ecdsa::signature::Signer as _;
    let server = MockServer::start().await;
    let sk = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
    let sig: k256::ecdsa::Signature = sk.sign(b"payload");
    Mock::given(method("POST"))
        .and(path(format!("/v1/{provider_path}/sign")))
        .and(header(auth_header, auth_value))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "signature_hex": hex::encode(sig.to_vec()),
            "public_key_hex": hex::encode(sk.verifying_key().to_sec1_bytes()),
        })))
        .mount(&server)
        .await;
    server
}

#[allow(dead_code)]
fn sign_req() -> EngineSignRequest {
    EngineSignRequest {
        key_id: KeyId("k1".into()),
        chain: Chain::Evm,
        payload: b"payload".to_vec(),
    }
}

#[cfg(feature = "fireblocks")]
mod fireblocks {
    use super::*;
    use mpc_signing_service::engine::fireblocks::FireblocksEngine;

    #[test]
    fn missing_config_rejected() {
        assert!(
            FireblocksEngine::from_config(&cfg_with(CustodyProvider::Fireblocks, None)).is_err()
        );
    }

    #[tokio::test]
    async fn signs_with_bearer_auth() {
        let server = mock_provider("fireblocks", "Authorization", "Bearer adapter-key").await;
        let engine = FireblocksEngine::from_config(&cfg_with(
            CustodyProvider::Fireblocks,
            Some(&server.uri()),
        ))
        .unwrap();
        engine.sign(&sign_req()).await.unwrap();
    }
}

#[cfg(feature = "dfns")]
mod dfns {
    use super::*;
    use mpc_signing_service::engine::dfns::DfnsEngine;

    #[test]
    fn missing_config_rejected() {
        assert!(DfnsEngine::from_config(&cfg_with(CustodyProvider::Dfns, None)).is_err());
    }

    #[tokio::test]
    async fn signs_with_api_key_header() {
        let server = mock_provider("dfns", "X-DFNS-APIKEY", "adapter-key").await;
        let engine =
            DfnsEngine::from_config(&cfg_with(CustodyProvider::Dfns, Some(&server.uri()))).unwrap();
        engine.sign(&sign_req()).await.unwrap();
    }
}

#[cfg(feature = "turnkey")]
mod turnkey {
    use super::*;
    use mpc_signing_service::engine::turnkey::TurnkeyEngine;

    #[test]
    fn missing_config_rejected() {
        assert!(TurnkeyEngine::from_config(&cfg_with(CustodyProvider::Turnkey, None)).is_err());
    }

    #[tokio::test]
    async fn signs_with_api_key_header() {
        let server = mock_provider("turnkey", "X-API-Key", "adapter-key").await;
        let engine =
            TurnkeyEngine::from_config(&cfg_with(CustodyProvider::Turnkey, Some(&server.uri())))
                .unwrap();
        engine.sign(&sign_req()).await.unwrap();
    }
}
