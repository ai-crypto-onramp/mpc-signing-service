//! Stage 9 acceptance: mTLS on the gRPC port. A client with a cert issued by
//! the internal CA connects and calls an RPC; a client presenting a cert from
//! a different (rogue) CA is rejected at the TLS layer.

use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use mpc_signing_service::audit::{AuditEmitter, AuditSigner};
use mpc_signing_service::engine::noop::MockEngine;
use mpc_signing_service::grpc::MpcService;
use mpc_signing_service::mtls::MtlsMaterial;
use mpc_signing_service::pb::mpc_signing_service_client::MpcSigningServiceClient;
use mpc_signing_service::pb::DkgRequest;
use mpc_signing_service::store::InMemSessionStore;

struct Leaf {
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
}

fn ca() -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let cert = params.self_signed(&key).unwrap();
    (cert, key)
}

fn leaf(san: &str, ca_cert: &rcgen::Certificate, ca_key: &KeyPair) -> Leaf {
    let key = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec![san.to_string()]).unwrap();
    let cert = params.signed_by(&key, ca_cert, ca_key).unwrap();
    Leaf {
        cert_pem: cert.pem().into_bytes(),
        key_pem: key.serialize_pem().into_bytes(),
    }
}

fn service() -> MpcService {
    MpcService {
        verifier: None,
        wallet: None,
        engine: Arc::new(MockEngine::new()),
        sessions: Arc::new(InMemSessionStore::new()),
        audit_signer: Arc::new(AuditSigner::new("node-mtls", None).unwrap()),
        audit: AuditEmitter::start(None),
        skip_policy: true,
        skip_wallet_check: true,
    }
}

async fn start_mtls_server(
    server_material: MtlsMaterial,
) -> (String, tokio::sync::oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(mpc_signing_service::grpc::serve(
        service(),
        addr,
        Some(server_material.server_config()),
        async {
            let _ = rx.await;
        },
    ));
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    (format!("https://{addr}"), tx)
}

async fn connect(endpoint: &str, tls: ClientTlsConfig) -> Result<Channel, tonic::transport::Error> {
    Channel::from_shared(endpoint.to_string())
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
}

#[tokio::test]
async fn client_with_ca_signed_cert_is_accepted() {
    let (ca_cert, ca_key) = ca();
    let ca_pem = ca_cert.pem().into_bytes();
    let server = leaf("localhost", &ca_cert, &ca_key);
    let client = leaf("localhost", &ca_cert, &ca_key);

    let server_material = MtlsMaterial::from_pem(server.cert_pem, server.key_pem, ca_pem.clone());
    let (endpoint, _shutdown) = start_mtls_server(server_material).await;

    let client_tls = ClientTlsConfig::new()
        .identity(Identity::from_pem(&client.cert_pem, &client.key_pem))
        .ca_certificate(Certificate::from_pem(&ca_pem))
        .domain_name("localhost");

    let channel = connect(&endpoint, client_tls).await.expect("mTLS connect");
    let mut c = MpcSigningServiceClient::new(channel);
    let resp = c
        .dkg(DkgRequest {
            chain: 1,
            threshold: 2,
            parties: 3,
        })
        .await
        .expect("authenticated RPC");
    assert!(!resp.into_inner().key_id.is_empty());
}

#[tokio::test]
async fn client_with_rogue_ca_cert_is_rejected() {
    let (ca_cert, ca_key) = ca();
    let ca_pem = ca_cert.pem().into_bytes();
    let server = leaf("localhost", &ca_cert, &ca_key);

    // A client cert from an unrelated CA the server does not trust.
    let (rogue_ca, rogue_key) = ca();
    let rogue_client = leaf("localhost", &rogue_ca, &rogue_key);

    let server_material = MtlsMaterial::from_pem(server.cert_pem, server.key_pem, ca_pem.clone());
    let (endpoint, _shutdown) = start_mtls_server(server_material).await;

    let client_tls = ClientTlsConfig::new()
        .identity(Identity::from_pem(
            &rogue_client.cert_pem,
            &rogue_client.key_pem,
        ))
        .ca_certificate(Certificate::from_pem(&ca_pem)) // trusts the real server
        .domain_name("localhost");

    // The server must reject the rogue client cert during the mTLS handshake;
    // this surfaces as a failed connect or a failed first RPC.
    let outcome: Result<(), Box<dyn std::error::Error>> = async {
        let channel = connect(&endpoint, client_tls).await?;
        let mut c = MpcSigningServiceClient::new(channel);
        c.dkg(DkgRequest {
            chain: 1,
            threshold: 2,
            parties: 3,
        })
        .await?;
        Ok(())
    }
    .await;
    assert!(outcome.is_err(), "rogue client cert must be rejected");
}
