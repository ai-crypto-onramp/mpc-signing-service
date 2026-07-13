//! End-to-end gRPC tests: a real tonic server on a loopback port, driven by
//! the generated client. Covers the SignTx pipeline (policy → wallet →
//! engine → audit), engine-agnostic orchestration, and control-plane RPCs.

use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use tonic::transport::Channel;

use mpc_signing_service::audit::{AuditEmitter, AuditSigner, AuditSink, SigningAuditRecord};
use mpc_signing_service::domain::Chain;
use mpc_signing_service::engine::noop::MockEngine;
use mpc_signing_service::engine::SigningEngine;
use mpc_signing_service::grpc::MpcService;
use mpc_signing_service::pb::mpc_signing_service_client::MpcSigningServiceClient;
use mpc_signing_service::pb::{
    DkgRequest, GetKeyMetadataRequest, RestoreShareRequest, RotateKeyRequest, SignTxRequest,
};
use mpc_signing_service::policy::mint::{claims_for, mint_token};
use mpc_signing_service::policy::Ed25519TokenVerifier;
use mpc_signing_service::store::{InMemSessionStore, InMemUsedTokenStore};
use mpc_signing_service::wallet::MockWalletClient;

/// Audit sink that collects records for assertions.
#[derive(Default)]
struct CollectingSink(Mutex<Vec<SigningAuditRecord>>);

#[async_trait::async_trait]
impl AuditSink for CollectingSink {
    async fn deliver(&self, record: &SigningAuditRecord) -> anyhow::Result<()> {
        self.0.lock().unwrap().push(record.clone());
        Ok(())
    }
}

struct Harness {
    client: MpcSigningServiceClient<Channel>,
    policy_key: SigningKey,
    wallet: Arc<MockWalletClient>,
    sink: Arc<CollectingSink>,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

async fn start(engine: Arc<dyn SigningEngine>) -> Harness {
    let policy_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let verifier = Ed25519TokenVerifier::new(
        &hex::encode(policy_key.verifying_key().to_bytes()),
        30,
        Arc::new(InMemUsedTokenStore::new()),
    )
    .unwrap();
    let wallet = Arc::new(MockWalletClient::new());
    let sink = Arc::new(CollectingSink::default());

    let service = MpcService {
        verifier: Some(Arc::new(verifier)),
        wallet: Some(wallet.clone()),
        engine,
        sessions: Arc::new(InMemSessionStore::new()),
        audit_signer: Arc::new(AuditSigner::new("node-e2e", None).unwrap()),
        audit: AuditEmitter::start(Some(sink.clone())),
        skip_policy: false,
        skip_wallet_check: false,
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener); // free the port for tonic to rebind
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(mpc_signing_service::grpc::serve(
        service,
        addr,
        None,
        async {
            let _ = rx.await;
        },
    ));

    // wait for the server to accept connections
    let endpoint = format!("http://{addr}");
    let mut client = None;
    for _ in 0..50 {
        match MpcSigningServiceClient::connect(endpoint.clone()).await {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
        }
    }

    Harness {
        client: client.expect("server did not come up"),
        policy_key,
        wallet,
        sink,
        _shutdown: tx,
    }
}

fn sign_req(h: &Harness, payload: &[u8], key_id: &str, wallet_id: &str) -> SignTxRequest {
    let token = mint_token(&h.policy_key, &claims_for(payload, key_id, Chain::Evm, 60));
    SignTxRequest {
        key_id: key_id.to_string(),
        chain: 1, // EVM
        tx_payload: payload.to_vec(),
        policy_decision_token: token,
        wallet_id: wallet_id.to_string(),
    }
}

async fn wait_for_audit(sink: &CollectingSink, n: usize) {
    for _ in 0..100 {
        if sink.0.lock().unwrap().len() >= n {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("expected {n} audit records");
}

#[tokio::test]
async fn sign_happy_path_with_mock_engine() {
    let engine = Arc::new(MockEngine::new());
    let mut h = start(engine.clone()).await;
    h.wallet.bind("w1", &["k1"], "k1");

    let resp = h
        .client
        .sign_tx(sign_req(&h, b"tx-payload", "k1", "w1"))
        .await
        .unwrap()
        .into_inner();

    assert!(!resp.signing_session_id.is_empty());
    assert_eq!(resp.signature, vec![0xAA; 64]);
    assert_eq!(
        engine.sign_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    wait_for_audit(&h.sink, 1).await;
    let records = h.sink.0.lock().unwrap();
    assert_eq!(records.len(), 1);
    assert!(records[0].verify(), "audit record must verify");
    assert_eq!(
        records[0].result,
        mpc_signing_service::audit::AuditResult::Signed
    );
}

#[tokio::test]
async fn deny_paths_never_reach_engine_and_are_audited() {
    let engine = Arc::new(MockEngine::new());
    let mut h = start(engine.clone()).await;
    h.wallet.bind("w1", &["k1"], "k1");

    // 1. garbage token
    let mut req = sign_req(&h, b"tx", "k1", "w1");
    req.policy_decision_token = "garbage".into();
    let err = h.client.sign_tx(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);

    // 2. token bound to a different payload
    let mut req = sign_req(&h, b"tx", "k1", "w1");
    req.tx_payload = b"other-payload".to_vec();
    let err = h.client.sign_tx(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("tx_payload_hash_mismatch"));

    // 3. replayed token
    let req = sign_req(&h, b"replay-tx", "k1", "w1");
    h.client.sign_tx(req.clone()).await.unwrap();
    let err = h.client.sign_tx(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("token_replayed"));

    // only the successful replay-setup call reached the engine
    assert_eq!(
        engine.sign_calls.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    // all four attempts audited: three denials + one signed
    wait_for_audit(&h.sink, 4).await;
    let records = h.sink.0.lock().unwrap();
    let denied = records
        .iter()
        .filter(|r| r.result == mpc_signing_service::audit::AuditResult::Denied)
        .count();
    assert_eq!(denied, 3);
    assert!(records.iter().all(|r| r.verify()));
}

#[tokio::test]
async fn wallet_mismatch_and_outage_fail_closed() {
    let engine = Arc::new(MockEngine::new());
    let mut h = start(engine.clone()).await;
    h.wallet.bind("w1", &["k1"], "k1");

    // key not bound to wallet
    let err = h
        .client
        .sign_tx(sign_req(&h, b"t1", "k-unbound", "w1"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("wallet_key_mismatch"));

    // unknown wallet
    let err = h
        .client
        .sign_tx(sign_req(&h, b"t2", "k1", "w-unknown"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
    assert!(err.message().contains("wallet_not_found"));

    // outage → fail closed with UNAVAILABLE
    h.wallet.set_outage(true);
    let err = h
        .client
        .sign_tx(sign_req(&h, b"t3", "k1", "w1"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unavailable);

    assert_eq!(
        engine.sign_calls.load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn engine_errors_map_to_grpc_codes() {
    let engine = Arc::new(MockEngine::new());
    let mut h = start(engine.clone()).await;
    h.wallet.bind("w1", &["k1"], "k1");

    engine
        .fail_next(|| mpc_signing_service::engine::EngineError::ProviderUnavailable("down".into()));
    let err = h
        .client
        .sign_tx(sign_req(&h, b"t1", "k1", "w1"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unavailable);

    engine.fail_next(|| mpc_signing_service::engine::EngineError::KeyNotFound("k1".into()));
    let err = h
        .client
        .sign_tx(sign_req(&h, b"t2", "k1", "w1"))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);

    // failures are audited as Failed
    wait_for_audit(&h.sink, 2).await;
    let records = h.sink.0.lock().unwrap();
    assert!(records
        .iter()
        .all(|r| r.result == mpc_signing_service::audit::AuditResult::Failed));
}

#[cfg(feature = "in-house")]
#[tokio::test]
async fn full_flow_with_in_house_engine_signature_verifies() {
    use k256::ecdsa::signature::Verifier as _;

    let engine = Arc::new(mpc_signing_service::engine::local::LocalEngine::new());
    let mut h = start(engine).await;

    // DKG first — the engine must know the key
    let dkg = h
        .client
        .dkg(DkgRequest {
            chain: 1,
            threshold: 2,
            parties: 3,
        })
        .await
        .unwrap()
        .into_inner();
    h.wallet.bind("w1", &[&dkg.key_id], &dkg.key_id);

    let resp = h
        .client
        .sign_tx(sign_req(&h, b"evm-transaction", &dkg.key_id, "w1"))
        .await
        .unwrap()
        .into_inner();

    // the signature must verify against the DKG public key
    assert_eq!(resp.public_key, dkg.public_key);
    let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&resp.public_key).unwrap();
    let sig = k256::ecdsa::Signature::from_slice(&resp.signature).unwrap();
    vk.verify(b"evm-transaction", &sig).unwrap();

    // rotation preserves the public key; signing still works afterwards
    let rot = h
        .client
        .rotate_key(RotateKeyRequest {
            key_id: dkg.key_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(rot.public_key, dkg.public_key);
    assert_eq!(rot.epoch, 2);

    let meta = h
        .client
        .get_key_metadata(GetKeyMetadataRequest {
            key_id: dkg.key_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(meta.public_key, dkg.public_key);
    assert_eq!(meta.epoch, 2);
    assert_eq!(meta.status, "active");

    // restore requires a quorum proof
    let err = h
        .client
        .restore_share(RestoreShareRequest {
            key_id: dkg.key_id.clone(),
            node_id: "n1".into(),
            quorum_proof: vec![],
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    let ok = h
        .client
        .restore_share(RestoreShareRequest {
            key_id: dkg.key_id,
            node_id: "n1".into(),
            quorum_proof: vec![1, 2, 3],
        })
        .await
        .unwrap()
        .into_inner();
    assert!(ok.restored);
}

#[tokio::test]
async fn invalid_arguments_rejected() {
    let engine = Arc::new(MockEngine::new());
    let mut h = start(engine).await;

    // unknown chain
    let mut req = sign_req(&h, b"t", "k1", "w1");
    req.chain = 0;
    assert_eq!(
        h.client.sign_tx(req).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );

    // missing key_id
    let mut req = sign_req(&h, b"t", "k1", "w1");
    req.key_id = String::new();
    assert_eq!(
        h.client.sign_tx(req).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );

    // missing payload
    let mut req = sign_req(&h, b"t", "k1", "w1");
    req.tx_payload = vec![];
    assert_eq!(
        h.client.sign_tx(req).await.unwrap_err().code(),
        tonic::Code::InvalidArgument
    );

    assert_eq!(
        h.client
            .rotate_key(RotateKeyRequest {
                key_id: String::new()
            })
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
}
