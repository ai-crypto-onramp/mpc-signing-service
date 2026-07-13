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
    /// Shared secret for verifying inbound custody webhooks (HMAC-SHA256).
    pub custody_webhook_secret: Option<String>,
    /// Audit / Event Log ingestion URL.
    pub audit_event_log_url: Option<String>,
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
            custody_webhook_secret: env_opt("CUSTODY_WEBHOOK_SECRET"),
            audit_event_log_url: env_opt("AUDIT_EVENT_LOG_URL"),
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
            custody_webhook_secret: None,
            audit_event_log_url: None,
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
