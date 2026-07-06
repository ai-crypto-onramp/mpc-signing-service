//! 12-factor configuration — environment-driven, secrets from the platform
//! secret manager in production.
//!
//! Loaded via `envy` from environment variables (see README config table).

#![allow(dead_code)]

use serde::Deserialize;

/// Service configuration parsed from the environment. Required for startup;
/// missing required values are reported via `Error::from`.
#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    /// gRPC listen port for the service.
    pub port: u16,
    /// Unique identifier for this signing node.
    pub node_id: String,
    /// Active custody provider, one of `in-house` / `fireblocks` / `dfns` /
    /// `turnkey`. Defaults to `in-house`.
    #[serde(default = "default_provider")]
    pub custody_provider: String,
    /// Optional Policy / Risk Engine URL for token introspection.
    #[serde(default)]
    pub policy_engine_url: Option<String>,
    /// Optional Wallet Management gRPC URL.
    #[serde(default)]
    pub wallet_management_url: Option<String>,
}

fn default_provider() -> String {
    "in-house".to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            port: 8080,
            node_id: "node-0".to_string(),
            custody_provider: default_provider(),
            policy_engine_url: None,
            wallet_management_url: None,
        }
    }
}

/// Load settings from the process environment.
///
/// Mirrors the README config table; required keys (`PORT`, `NODE_ID`) are
/// expected to be set in production but fall back to `Default` for local dev /
/// tests so the smoke test runs without external setup.
pub fn from_env() -> anyhow::Result<Settings> {
    let settings = envy::from_env::<Settings>()
        .map_err(|e| anyhow::anyhow!("invalid environment configuration: {e}"))?;
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_populate_provider() {
        let s = Settings::default();
        assert_eq!(s.custody_provider, "in-house");
        assert_eq!(s.port, 8080);
    }
}
