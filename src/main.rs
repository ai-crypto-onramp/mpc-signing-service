//! mpc-signing-service binary: wires config → policy verifier → wallet
//! client → signing engine → audit emitter, then serves gRPC (signing API)
//! and HTTP (/healthz + custody webhook) until SIGTERM/ctrl-c.

use std::sync::Arc;

use axum::{routing::get, routing::post, Json, Router};
use serde_json::{json, Value};

use mpc_signing_service::audit::{AuditEmitter, AuditSigner, KafkaAuditSink};
use mpc_signing_service::config::Config;
use mpc_signing_service::engine::build_engine;
use mpc_signing_service::grpc::{serve, MpcService};
use mpc_signing_service::policy::Ed25519TokenVerifier;
use mpc_signing_service::store::{InMemSessionStore, InMemUsedTokenStore};
use mpc_signing_service::wallet::GrpcWalletClient;

async fn healthz() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

/// Inbound custody webhook: HMAC-verified against CUSTODY_WEBHOOK_SECRET.
async fn custody_webhook(
    axum::extract::State(secret): axum::extract::State<Option<String>>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> (axum::http::StatusCode, Json<Value>) {
    let Some(secret) = secret else {
        return (
            axum::http::StatusCode::NOT_IMPLEMENTED,
            Json(json!({"error": "webhook secret not configured"})),
        );
    };
    let sig = headers
        .get("x-custody-signature")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if !mpc_signing_service::engine::custody::verify_webhook(&secret, &body, sig) {
        return (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid webhook signature"})),
        );
    }
    tracing::info!(bytes = body.len(), "custody webhook accepted");
    (axum::http::StatusCode::OK, Json(json!({"status": "ok"})))
}

fn http_app(webhook_secret: Option<String>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/custody/webhook", post(custody_webhook))
        .with_state(webhook_secret)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cfg = Config::from_env();
    tracing::info!(provider = ?cfg.custody_provider, "starting mpc-signing-service");

    // Policy verifier (fail closed when unset unless the dev flag is on).
    let used_tokens = Arc::new(InMemUsedTokenStore::new());
    let verifier = match &cfg.policy_engine_pubkey {
        Some(pk) => Some(Arc::new(Ed25519TokenVerifier::new(
            pk,
            cfg.token_max_skew.as_secs(),
            used_tokens,
        )?)
            as Arc<dyn mpc_signing_service::policy::PolicyTokenVerifier>),
        None => {
            tracing::warn!("POLICY_ENGINE_PUBKEY not set; SignTx will fail closed");
            None
        }
    };

    // Wallet Management client (fail closed when unset unless the dev flag is on).
    let wallet = match &cfg.wallet_management_url {
        Some(url) => Some(Arc::new(
            GrpcWalletClient::connect(url)
                .await
                .map_err(|e| anyhow::anyhow!("wallet management client: {e}"))?,
        )
            as Arc<dyn mpc_signing_service::wallet::WalletManagementClient>),
        None => {
            tracing::warn!("WALLET_MANAGEMENT_URL not set; SignTx will fail closed");
            None
        }
    };

    let engine = build_engine(&cfg)?;
    let audit_signer = Arc::new(AuditSigner::new(
        &cfg.node_id,
        cfg.node_signing_key.as_deref(),
    )?);
    let audit_sink: Option<Arc<dyn mpc_signing_service::audit::AuditSink>> = match &cfg.kafka_brokers {
        Some(brokers) => match KafkaAuditSink::new(brokers, &cfg.node_id) {
            Ok(sink) => Some(Arc::new(sink) as Arc<dyn mpc_signing_service::audit::AuditSink>),
            Err(e) => {
                if cfg.dev_mode {
                    tracing::warn!("KAFKA_BROKERS set but producer init failed (DEV_MODE): {e}; audit records will be logged");
                    None
                } else {
                    return Err(anyhow::anyhow!("audit kafka producer init: {e}"));
                }
            }
        },
        None => {
            if cfg.dev_mode {
                tracing::warn!("KAFKA_BROKERS unset and DEV_MODE=1; audit records will be logged to stderr only");
                None
            } else {
                return Err(anyhow::anyhow!("KAFKA_BROKERS unset and DEV_MODE not set; cannot start audit producer"));
            }
        }
    };
    let audit = AuditEmitter::start(audit_sink);

    let service = MpcService {
        verifier,
        wallet,
        engine,
        sessions: Arc::new(InMemSessionStore::new()),
        audit_signer,
        audit,
        skip_policy: cfg.insecure_skip_policy,
        skip_wallet_check: cfg.insecure_skip_wallet_check,
    };

    // HTTP: healthz + custody webhook.
    let http_addr = std::net::SocketAddr::from(([0, 0, 0, 0], cfg.http_port));
    let http_listener = tokio::net::TcpListener::bind(http_addr).await?;
    let webhook_secret = cfg.custody_webhook_secret.clone();
    let http = tokio::spawn(async move {
        tracing::info!(%http_addr, "http listening (healthz, custody webhook)");
        axum::serve(http_listener, http_app(webhook_secret))
            .with_graceful_shutdown(shutdown_signal())
            .await
    });

    // gRPC: the signing API, mTLS when MTLS_* are configured.
    let tls = match mpc_signing_service::mtls::MtlsMaterial::from_env()? {
        Some(m) => {
            tracing::info!("mTLS enabled for the gRPC port");
            Some(m.server_config())
        }
        None => {
            tracing::warn!("MTLS_* not set; gRPC served in plaintext (dev only)");
            None
        }
    };
    let grpc_addr = std::net::SocketAddr::from(([0, 0, 0, 0], cfg.grpc_port));
    serve(service, grpc_addr, tls, shutdown_signal()).await?;

    http.abort();
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn healthz_ok() {
        let resp = http_app(None)
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["status"], "ok");
    }

    #[tokio::test]
    async fn webhook_unconfigured_returns_501() {
        let resp = http_app(None)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/custody/webhook")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn webhook_verifies_hmac() {
        use mpc_signing_service::engine::custody::webhook_signature;
        let app = http_app(Some("s3cret".into()));

        let body = br#"{"event":"tx_signed"}"#;
        let sig = webhook_signature("s3cret", body);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/custody/webhook")
                    .header("x-custody-signature", sig)
                    .body(Body::from(&body[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/custody/webhook")
                    .header("x-custody-signature", "deadbeef")
                    .body(Body::from(&body[..]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
