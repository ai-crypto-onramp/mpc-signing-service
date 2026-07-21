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
    use rsa::pkcs8::{EncodePrivateKey, LineEnding};
    use rsa::RsaPrivateKey;
    use serde_json::json;
    use wiremock::matchers::{header_exists, header_regex, method, path};

    fn cfg_with_secret(url: Option<&str>) -> Config {
        let mut rng = rand::rngs::OsRng;
        let priv_key = RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
        let pem = priv_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("pkcs8 pem")
            .to_string();
        Config {
            custody_provider: CustodyProvider::Fireblocks,
            custody_api_url: url.map(String::from),
            custody_api_key: Some("adapter-key".into()),
            custody_api_secret_key: Some(pem),
            ..Config::default()
        }
    }

    #[test]
    fn missing_config_rejected() {
        assert!(
            FireblocksEngine::from_config(&cfg_with(CustodyProvider::Fireblocks, None)).is_err()
        );
    }

    /// The real Fireblocks sign flow: `POST /v1/transactions` returns a
    /// pending tx id; `GET /v1/transactions/{id}` returns `COMPLETED` with a
    /// `signedMessages` array. Verifies the request carries `X-API-Key` and
    /// a `Bearer <jwt>` Authorization header, and the returned signature is
    /// locally verified.
    #[tokio::test]
    async fn signs_via_transactions_endpoint_with_jwt() {
        use k256::ecdsa::signature::Signer as _;
        let server = MockServer::start().await;
        let sk = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let sig: k256::ecdsa::Signature = sk.sign(b"payload");
        let sig_hex = hex::encode(sig.to_vec());
        let pk_hex = hex::encode(sk.verifying_key().to_sec1_bytes());

        Mock::given(method("POST"))
            .and(path("/v1/transactions"))
            .and(header_exists("X-API-Key"))
            .and(header_regex("Authorization", "^Bearer .+\\..+\\..+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "tx-1",
                "status": "SUBMITTED",
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/v1/transactions/tx-1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "tx-1",
                "status": "COMPLETED",
                "signedMessages": [{
                    "signature": sig_hex,
                    "publicKey": pk_hex,
                }],
            })))
            .mount(&server)
            .await;

        let engine = FireblocksEngine::from_config(&cfg_with_secret(Some(&server.uri()))).unwrap();
        engine.sign(&sign_req()).await.unwrap();
    }

    /// `restore_share` is unsupported on Fireblocks (they manage shares).
    #[tokio::test]
    async fn restore_share_is_unsupported() {
        let server = MockServer::start().await;
        let engine = FireblocksEngine::from_config(&cfg_with_secret(Some(&server.uri()))).unwrap();
        let res = engine
            .restore_share(&mpc_signing_service::engine::RestoreParams {
                key_id: KeyId("v1".into()),
                node_id: "n1".into(),
                quorum_proof: vec![1, 2, 3],
            })
            .await;
        assert!(res.is_err());
    }
}

#[cfg(feature = "dfns")]
mod dfns {
    use super::*;
    use mpc_signing_service::engine::dfns::DfnsEngine;

    fn cfg_with_dfns(url: Option<&str>) -> Config {
        Config {
            custody_provider: CustodyProvider::Dfns,
            custody_api_url: url.map(String::from),
            custody_api_key: Some("adapter-token".into()),
            custody_service_account_key: Some("cr-test".into()),
            custody_service_account_secret: Some(hex::encode([0u8; 32])),
            ..Config::default()
        }
    }

    #[test]
    fn missing_config_rejected() {
        // No service-account token, cred id, or secret.
        assert!(DfnsEngine::from_config(&cfg_with(CustodyProvider::Dfns, None)).is_err());
    }

    /// End-to-end sign flow against a mock that fakes the User Action Signing
    /// handshake (`/auth/action/init` + `/auth/action`) and the
    /// `POST /keys/{keyId}/signatures` + poll-on-`GET` shape.
    #[tokio::test]
    async fn signs_via_keys_signatures_endpoint() {
        use k256::ecdsa::signature::Signer as _;
        let server = MockServer::start().await;

        let sk = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        // k256 `sign(payload)` hashes `payload` with SHA-256 internally and
        // signs the digest. The engine sends Dfns `kind: Hash` with
        // SHA-256(payload), so Dfns signs the same digest k256 would
        // produce; `custody::verify_signature` re-hashes `payload` and
        // checks the signature against that hash. Sign the raw payload here
        // so the returned signature verifies.
        let sig: k256::ecdsa::Signature = sk.sign(b"payload");
        let sig_hex = format!("0x{}", hex::encode(sig.to_vec()));
        let pk_hex = hex::encode(sk.verifying_key().to_sec1_bytes());

        // /auth/action/init — returns a challenge.
        Mock::given(method("POST"))
            .and(path("/auth/action/init"))
            .and(header("Authorization", "Bearer adapter-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "challenge": "challenge-abc",
                "challengeIdentifier": "ci-abc",
                "supportedCredentialKinds": [],
                "userVerification": "required",
                "attestation": "direct",
                "allowCredentials": { "key": [], "webauthn": [] },
                "externalAuthenticationUrl": "",
            })))
            .mount(&server)
            .await;

        // /auth/action — returns the one-time userAction token.
        Mock::given(method("POST"))
            .and(path("/auth/action"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "userAction": "ua-token",
            })))
            .mount(&server)
            .await;

        // POST /keys/k1/signatures — returns the new signature request id
        // with status Signed immediately.
        Mock::given(method("POST"))
            .and(path("/keys/k1/signatures"))
            .and(header("X-DFNS-USERACTION", "ua-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": "sig-1",
                "status": "Signed",
                "signature": { "r": "0x01", "s": "0x02", "encoded": sig_hex },
                "publicKey": pk_hex,
            })))
            .mount(&server)
            .await;

        let engine = DfnsEngine::from_config(&cfg_with_dfns(Some(&server.uri()))).unwrap();
        let out = engine.sign(&sign_req()).await.expect("sign ok");
        assert_eq!(out.public_key, hex::decode(pk_hex).unwrap());
    }
}

#[cfg(feature = "turnkey")]
mod turnkey {
    use super::*;
    use mpc_signing_service::engine::turnkey::TurnkeyEngine;

    fn cfg_with_turnkey(url: Option<&str>) -> Config {
        let sk = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let sk_hex = hex::encode(sk.to_bytes());
        let pub_hex = hex::encode(sk.verifying_key().to_sec1_bytes());
        Config {
            custody_provider: CustodyProvider::Turnkey,
            custody_api_url: url.map(String::from),
            custody_api_key: Some(pub_hex),
            custody_api_private_key: Some(sk_hex),
            custody_organization_id: Some("org-123".into()),
            ..Config::default()
        }
    }

    #[test]
    fn missing_config_rejected() {
        // No URL: from_config falls back to the default base URL and only
        // checks the org id + API key + private key, so this still errors
        // because the default cfg has no organization id / api key.
        assert!(TurnkeyEngine::from_config(&cfg_with(CustodyProvider::Turnkey, None)).is_err());
        // With URL + org + key pair present, from_config succeeds.
        assert!(
            TurnkeyEngine::from_config(&cfg_with_turnkey(Some("https://api.turnkey.com"))).is_ok()
        );
    }

    #[tokio::test]
    async fn submits_stamped_rpc_sign_request() {
        use k256::ecdsa::signature::Signer as _;
        let server = MockServer::start().await;
        let cfg = cfg_with_turnkey(Some(&server.uri()));
        let sk_hex = cfg.custody_api_private_key.clone().unwrap();
        let _sk = k256::ecdsa::SigningKey::from_slice(&hex::decode(&sk_hex).unwrap()).unwrap();

        let signing_sk = k256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng);
        let sig: k256::ecdsa::Signature = signing_sk.sign(b"payload");
        let r_hex = hex::encode(&sig.to_vec()[0..32]);
        let s_hex = hex::encode(&sig.to_vec()[32..64]);
        let pubkey_hex = hex::encode(signing_sk.verifying_key().to_sec1_bytes());

        // get_wallet_account: return address + publicKey (used to pick signWith
        // and to verify the returned signature locally).
        Mock::given(method("POST"))
            .and(path("/public/v1/query/get_wallet_account"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "account": {
                    "address": "0xabc",
                    "publicKey": pubkey_hex,
                    "curve": "CURVE_SECP256K1",
                    "path": "m/44'/60'/0'/0/0",
                }
            })))
            .mount(&server)
            .await;

        // sign_raw_payload submit: return COMPLETED status with the r/s result
        // inline (Turnkey activities are optimistic-sync when possible).
        Mock::given(method("POST"))
            .and(path("/public/v1/submit/sign_raw_payload"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "activity": {
                    "id": "act-1",
                    "status": "ACTIVITY_STATUS_COMPLETED",
                    "result": {
                        "signRawPayloadResult": {
                            "r": r_hex,
                            "s": s_hex,
                            "v": "27"
                        }
                    }
                }
            })))
            .mount(&server)
            .await;

        let engine = TurnkeyEngine::from_config(&cfg).unwrap();
        let out = engine.sign(&sign_req()).await.expect("sign ok");
        assert_eq!(out.public_key, hex::decode(pubkey_hex).unwrap());
    }
}
