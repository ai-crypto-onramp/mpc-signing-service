//! Interop test for the JSON-codec gRPC wallet client: spins up an in-process
//! tonic server that mimics wallet-management's Go server — same service name
//! (`wallet.WalletService`), same JSON codec over plain structs — and drives
//! `GrpcWalletClient` against it.

use std::task::{Context, Poll};

use serde::{Deserialize, Serialize};
use tonic::body::BoxBody;
use tonic::server::NamedService;

use mpc_signing_service::grpc::json_codec::JsonCodec;
use mpc_signing_service::wallet::{GrpcWalletClient, WalletError, WalletManagementClient};

#[derive(Debug, Deserialize)]
struct ResolveKeyIdRequest {
    #[serde(default)]
    wallet_id: String,
}

#[derive(Debug, Serialize)]
struct ResolveKeyIdResponse {
    key_ids: Vec<String>,
    current_key_id: String,
}

/// Minimal JSON-codec gRPC server mirroring wallet-management's surface.
#[derive(Clone)]
struct FakeWalletService;

impl NamedService for FakeWalletService {
    const NAME: &'static str = "wallet.WalletService";
}

struct ResolveHandler;

impl tonic::server::UnaryService<ResolveKeyIdRequest> for ResolveHandler {
    type Response = ResolveKeyIdResponse;
    type Future = std::future::Ready<Result<tonic::Response<Self::Response>, tonic::Status>>;

    fn call(&mut self, request: tonic::Request<ResolveKeyIdRequest>) -> Self::Future {
        let req = request.into_inner();
        let resp = if req.wallet_id == "known-wallet" {
            Ok(tonic::Response::new(ResolveKeyIdResponse {
                key_ids: vec!["k-old".into(), "k-new".into()],
                current_key_id: "k-new".into(),
            }))
        } else {
            Err(tonic::Status::not_found("wallet has no bound key"))
        };
        std::future::ready(resp)
    }
}

impl tower::Service<http::Request<BoxBody>> for FakeWalletService {
    type Response = http::Response<BoxBody>;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<BoxBody>) -> Self::Future {
        Box::pin(async move {
            match req.uri().path() {
                "/wallet.WalletService/ResolveKeyID" => {
                    let codec: JsonCodec<ResolveKeyIdResponse, ResolveKeyIdRequest> =
                        JsonCodec::default();
                    let mut grpc = tonic::server::Grpc::new(codec);
                    Ok(grpc.unary(ResolveHandler, req).await)
                }
                _ => Ok(http::Response::builder()
                    .status(200)
                    .header("grpc-status", "12") // UNIMPLEMENTED
                    .body(tonic::body::empty_body())
                    .unwrap()),
            }
        })
    }
}

async fn start_fake_wallet() -> (String, tokio::sync::oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FakeWalletService)
            .serve_with_shutdown(addr, async {
                let _ = rx.await;
            }),
    );
    // give the server a moment to bind
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    (format!("http://{addr}"), tx)
}

#[tokio::test]
async fn resolve_keys_round_trips_json_codec() {
    let (url, _shutdown) = start_fake_wallet().await;
    let client = GrpcWalletClient::connect(&url).await.unwrap();

    let rec = client.resolve_keys("known-wallet").await.unwrap();
    assert_eq!(rec.current_key_id, "k-new");
    assert_eq!(rec.key_ids, vec!["k-old".to_string(), "k-new".to_string()]);

    // binding check accepts both current and cooling keys
    client
        .check_key_binding("known-wallet", "k-new")
        .await
        .unwrap();
    client
        .check_key_binding("known-wallet", "k-old")
        .await
        .unwrap();
    assert!(matches!(
        client
            .check_key_binding("known-wallet", "k-x")
            .await
            .unwrap_err(),
        WalletError::KeyMismatch
    ));
}

#[tokio::test]
async fn unknown_wallet_maps_to_not_found() {
    let (url, _shutdown) = start_fake_wallet().await;
    let client = GrpcWalletClient::connect(&url).await.unwrap();
    assert!(matches!(
        client.resolve_keys("missing").await.unwrap_err(),
        WalletError::NotFound
    ));
}

#[tokio::test]
async fn connection_refused_fails_closed() {
    let client = GrpcWalletClient::connect("http://127.0.0.1:1")
        .await
        .unwrap();
    assert!(matches!(
        client.resolve_keys("w").await.unwrap_err(),
        WalletError::Unavailable(_)
    ));
}
