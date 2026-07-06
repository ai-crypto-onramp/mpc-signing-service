//! MPC Signing Service binary.
//!
//! Stage 1 skeleton — starts a placeholder gRPC server is intentionally
//! deferred to Stage 2. For now the binary loads config, initializes tracing,
//! and logs the service identity + active provider, proving the workspace
//! links end-to-end against all four feature combinations.

use mpc_signing_service::{config, version};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let settings = config::from_env().unwrap_or_else(|e| {
        tracing::warn!("environment config incomplete, using defaults: {e}");
        config::Settings::default()
    });

    tracing::info!(
        version = version(),
        node_id = %settings.node_id,
        port = settings.port,
        custody_provider = %settings.custody_provider,
        "mpc-signing-service stage-1 skeleton starting (gRPC surface lands in Stage 2)"
    );

    // Stage 2 binds the tonic server here. For now we block on a shutdown
    // signal so the process behaves like a long-running service while keeping
    // the skeleton dependency-free.
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| anyhow::anyhow!("failed to install ctrl-c handler: {e}"))?;
    tracing::info!("shutdown signal received, exiting");
    Ok(())
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).with_target(false).init();
}
