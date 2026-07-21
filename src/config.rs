//! Environment-driven configuration (12-factor).

use std::time::Duration;

/// Which signing backend the engine factory selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyProvider {
    InHouse,
    Fireblocks,
    Dfns,
    Turnkey,
}

impl CustodyProvider {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "in_house" | "in-house" | "inhouse" => Some(Self::InHouse),
            "fireblocks" => Some(Self::Fireblocks),
            "dfns" => Some(Self::Dfns),
            "turnkey" => Some(Self::Turnkey),
            _ => None,
        }
    }
}

/// Runtime configuration for the service.
#[derive(Debug, Clone)]
pub struct Config {
    /// HTTP port for /healthz and custody webhooks.
    pub http_port: u16,
    /// gRPC port for the MpcSigningService.
    pub grpc_port: u16,
    /// Hex-encoded Ed25519 public key of the Policy / Risk Engine used to
    /// verify policy decision tokens.
    pub policy_engine_pubkey: Option<String>,
    /// Allowed clock skew when checking token freshness.
    pub token_max_skew: Duration,
    /// Wallet Management gRPC endpoint (e.g. http://wallet-management:9090).
    pub wallet_management_url: Option<String>,
    /// Selected signing backend.
    pub custody_provider: CustodyProvider,
    /// Custody provider REST API base URL.
    pub custody_api_url: Option<String>,
    /// Custody provider API key.
    pub custody_api_key: Option<String>,
    /// RSA-4096 PEM private key contents for Fireblocks JWT signing. Loaded
    /// from `CUSTODY_API_SECRET_KEY` (inline PEM) or
    /// `CUSTODY_API_SECRET_KEY_PATH` (file path). Ignored by non-Fireblocks
    /// providers.
    pub custody_api_secret_key: Option<String>,
    /// When true, FireblocksEngine targets the Fireblocks sandbox
    /// (`https://sandbox-api.fireblocks.io`) instead of the production API.
    /// Set via `CUSTODY_SANDBOX=1`.
    pub custody_sandbox: bool,
    /// Shared secret for verifying inbound custody webhooks (HMAC-SHA256).
    pub custody_webhook_secret: Option<String>,
    /// Turnkey organization ID (required on every Turnkey request).
    pub custody_organization_id: Option<String>,
    /// Turnkey API key private key (secp256k1) hex used to stamp requests.
    pub custody_api_private_key: Option<String>,
    /// Optional Turnkey sub-organization ID (embedded-wallet per-end-user mode).
    pub custody_sub_organization_id: Option<String>,
    /// Dfns service account credential id (`cr-...`, base64url) used to pick
    /// the signing key in the User Action Signing flow. Required for the
    /// `dfns` provider.
    pub custody_service_account_key: Option<String>,
    /// Dfns service account Ed25519 private key, hex-encoded 32-byte seed,
    /// used to sign User Action challenges. Required for the `dfns` provider.
    pub custody_service_account_secret: Option<String>,
    /// Audit / Event Log ingestion URL. Deprecated: producers now publish
    /// to Kafka topic `audit.v1` (see KAFKA_BROKERS). Retained only for
    /// compatibility with tests; production wiring ignores it.
    pub audit_event_log_url: Option<String>,
    /// Kafka brokers (comma-separated) for the audit.v1 producer.
    pub kafka_brokers: Option<String>,
    /// DEV_MODE=1 allows startup with no KAFKA_BROKERS and no policy
    /// pubkey; audit records fall back to stderr logging instead of
    /// being published.
    pub dev_mode: bool,
    /// Stable identifier of this node in audit records.
    pub node_id: String,
    /// Hex-encoded Ed25519 seed for the node's audit-record signing key.
    /// Generated ephemerally when unset (dev only).
    pub node_signing_key: Option<String>,
    /// DEV ONLY: skip policy token verification. The sign path fails closed
    /// without a configured `POLICY_ENGINE_PUBKEY` unless this is set.
    pub insecure_skip_policy: bool,
    /// DEV ONLY: skip the Wallet Management key-binding check.
    pub insecure_skip_wallet_check: bool,
    /// Threshold `t` for the in-house engine (min signers).
    pub threshold_t: usize,
    /// Total nodes `n` for the in-house engine.
    pub total_n: usize,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            http_port: env_parse("PORT", 8080),
            grpc_port: env_parse("GRPC_PORT", 9090),
            policy_engine_pubkey: env_opt("POLICY_ENGINE_PUBKEY"),
            token_max_skew: Duration::from_secs(env_parse("TOKEN_MAX_SKEW_SECS", 30)),
            wallet_management_url: env_opt("WALLET_MANAGEMENT_URL"),
            custody_provider: env_opt("CUSTODY_PROVIDER")
                .and_then(|v| CustodyProvider::parse(&v))
                .unwrap_or(CustodyProvider::InHouse),
            custody_api_url: env_opt("CUSTODY_API_URL"),
            custody_api_key: env_opt("CUSTODY_API_KEY"),
            custody_api_secret_key: env_opt("CUSTODY_API_SECRET_KEY")
                .or_else(|| env_opt("CUSTODY_API_SECRET_KEY_PATH").and_then(load_secret_file)),
            custody_sandbox: env_parse("CUSTODY_SANDBOX", false),
            custody_webhook_secret: env_opt("CUSTODY_WEBHOOK_SECRET"),
            custody_organization_id: env_opt("CUSTODY_ORGANIZATION_ID"),
            custody_api_private_key: env_opt("CUSTODY_API_PRIVATE_KEY"),
            custody_sub_organization_id: env_opt("CUSTODY_SUB_ORGANIZATION_ID"),
            custody_service_account_key: env_opt("CUSTODY_SERVICE_ACCOUNT_KEY"),
            custody_service_account_secret: env_opt("CUSTODY_SERVICE_ACCOUNT_SECRET"),
            audit_event_log_url: env_opt("AUDIT_EVENT_LOG_URL"),
            kafka_brokers: env_opt("KAFKA_BROKERS"),
            dev_mode: env_parse("DEV_MODE", false),
            node_id: env_opt("NODE_ID").unwrap_or_else(|| "node-0".to_string()),
            node_signing_key: env_opt("NODE_SIGNING_KEY"),
            insecure_skip_policy: env_parse("INSECURE_SKIP_POLICY", false),
            insecure_skip_wallet_check: env_parse("INSECURE_SKIP_WALLET_CHECK", false),
            threshold_t: env_parse("THRESHOLD_T", 2),
            total_n: env_parse("TOTAL_N", 3),
        }
    }
}

impl Default for Config {
    /// A localhost dev configuration; no external services configured.
    fn default() -> Self {
        Self {
            http_port: 8080,
            grpc_port: 9090,
            policy_engine_pubkey: None,
            token_max_skew: Duration::from_secs(30),
            wallet_management_url: None,
            custody_provider: CustodyProvider::InHouse,
            custody_api_url: None,
            custody_api_key: None,
            custody_api_secret_key: None,
            custody_sandbox: false,
            custody_webhook_secret: None,
            custody_organization_id: None,
            custody_api_private_key: None,
            custody_sub_organization_id: None,
            custody_service_account_key: None,
            custody_service_account_secret: None,
            audit_event_log_url: None,
            kafka_brokers: None,
            dev_mode: false,
            node_id: "node-0".to_string(),
            node_signing_key: None,
            insecure_skip_policy: false,
            insecure_skip_wallet_check: false,
            threshold_t: 2,
            total_n: 3,
        }
    }
}

fn env_opt(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

fn env_parse<T: std::str::FromStr>(key: &str, default: T) -> T {
    env_opt(key).and_then(|v| v.parse().ok()).unwrap_or(default)
}

/// Read the Fireblocks RSA private key from a file path pointed to by
/// `CUSTODY_API_SECRET_KEY_PATH`. Returns `None` if the read fails —
/// `FireblocksEngine::from_config` surfaces a clear error in that case.
fn load_secret_file(path: String) -> Option<String> {
    std::fs::read_to_string(&path)
        .map_err(|e| tracing::warn!("CUSTODY_API_SECRET_KEY_PATH={path} unreadable: {e}"))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_parse() {
        assert_eq!(
            CustodyProvider::parse("in_house"),
            Some(CustodyProvider::InHouse)
        );
        assert_eq!(
            CustodyProvider::parse("Fireblocks"),
            Some(CustodyProvider::Fireblocks)
        );
        assert_eq!(CustodyProvider::parse("DFNS"), Some(CustodyProvider::Dfns));
        assert_eq!(
            CustodyProvider::parse("turnkey"),
            Some(CustodyProvider::Turnkey)
        );
        assert_eq!(CustodyProvider::parse("nope"), None);
    }

    #[test]
    fn default_config_is_in_house() {
        let cfg = Config::default();
        assert_eq!(cfg.custody_provider, CustodyProvider::InHouse);
        assert_eq!(cfg.http_port, 8080);
        assert_eq!(cfg.grpc_port, 9090);
    }

    #[test]
    fn from_env_reads_and_defaults() {
        // Only this test touches these variables; the lib test binary runs
        // no other env-dependent tests concurrently.
        std::env::set_var("PORT", "18080");
        std::env::set_var("GRPC_PORT", "not-a-number"); // falls back to default
        std::env::set_var("CUSTODY_PROVIDER", "fireblocks");
        std::env::set_var("CUSTODY_API_URL", "http://custody.local");
        std::env::set_var("TOKEN_MAX_SKEW_SECS", "120");
        std::env::set_var("INSECURE_SKIP_POLICY", "true");
        std::env::set_var("NODE_ID", "node-7");

        let cfg = Config::from_env();
        assert_eq!(cfg.http_port, 18080);
        assert_eq!(cfg.grpc_port, 9090);
        assert_eq!(cfg.custody_provider, CustodyProvider::Fireblocks);
        assert_eq!(cfg.custody_api_url.as_deref(), Some("http://custody.local"));
        assert_eq!(cfg.token_max_skew, Duration::from_secs(120));
        assert!(cfg.insecure_skip_policy);
        assert!(!cfg.insecure_skip_wallet_check);
        assert_eq!(cfg.node_id, "node-7");

        for k in [
            "PORT",
            "GRPC_PORT",
            "CUSTODY_PROVIDER",
            "CUSTODY_API_URL",
            "TOKEN_MAX_SKEW_SECS",
            "INSECURE_SKIP_POLICY",
            "NODE_ID",
        ] {
            std::env::remove_var(k);
        }
    }
}
