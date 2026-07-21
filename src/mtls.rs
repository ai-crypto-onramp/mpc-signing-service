//! mTLS material for client and inter-node gRPC (Stage 9).
//!
//! Loads the node's certificate, private key, and the internal CA from
//! `MTLS_CERT` / `MTLS_KEY` / `MTLS_CA` (PEM file paths) and builds tonic
//! server/client TLS configs that require and verify peer certificates. The
//! same material secures the public RPC port and the inter-node MPC channel;
//! short-lived certs are issued by the internal PKI (`make mtls` for local
//! dev).

use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};

/// PEM-encoded mTLS material for this node.
#[derive(Clone, Debug)]
pub struct MtlsMaterial {
    cert_pem: Vec<u8>,
    key_pem: Vec<u8>,
    ca_pem: Vec<u8>,
}

impl MtlsMaterial {
    /// Load from explicit PEM file paths.
    pub fn from_paths(cert: &str, key: &str, ca: &str) -> anyhow::Result<Self> {
        Ok(Self {
            cert_pem: std::fs::read(cert)
                .map_err(|e| anyhow::anyhow!("read MTLS_CERT {cert}: {e}"))?,
            key_pem: std::fs::read(key).map_err(|e| anyhow::anyhow!("read MTLS_KEY {key}: {e}"))?,
            ca_pem: std::fs::read(ca).map_err(|e| anyhow::anyhow!("read MTLS_CA {ca}: {e}"))?,
        })
    }

    /// Load from `MTLS_CERT` / `MTLS_KEY` / `MTLS_CA` (or the equivalent
    /// `TLS_CERT_FILE` / `TLS_KEY_FILE` / `TLS_CA_FILE` trio). Returns
    /// `Ok(None)` when none are set, or an error if some but not all are set.
    /// In `DEV_MODE!=1` with all three unset it fatals at startup.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let cert = std::env::var("MTLS_CERT")
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| {
                std::env::var("TLS_CERT_FILE")
                    .ok()
                    .filter(|v| !v.is_empty())
            });
        let key = std::env::var("MTLS_KEY")
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| std::env::var("TLS_KEY_FILE").ok().filter(|v| !v.is_empty()));
        let ca = std::env::var("MTLS_CA")
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| std::env::var("TLS_CA_FILE").ok().filter(|v| !v.is_empty()));
        match (cert, key, ca) {
            (Some(c), Some(k), Some(a)) => Ok(Some(Self::from_paths(&c, &k, &a)?)),
            (None, None, None) => {
                if std::env::var("DEV_MODE").as_deref() == Ok("1") {
                    Ok(None)
                } else {
                    anyhow::bail!(
                        "MTLS_CERT/MTLS_KEY/MTLS_CA (or TLS_CERT_FILE/TLS_KEY_FILE/TLS_CA_FILE) required when DEV_MODE!=1"
                    )
                }
            }
            _ => anyhow::bail!(
                "MTLS_CERT, MTLS_KEY, and MTLS_CA must all be set together (or all unset)"
            ),
        }
    }

    /// Build directly from PEM bytes (used by tests and in-memory PKI).
    pub fn from_pem(cert_pem: Vec<u8>, key_pem: Vec<u8>, ca_pem: Vec<u8>) -> Self {
        Self {
            cert_pem,
            key_pem,
            ca_pem,
        }
    }

    /// Server config: present our identity and require client certs signed by
    /// the internal CA (mutual auth).
    pub fn server_config(&self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(Identity::from_pem(&self.cert_pem, &self.key_pem))
            .client_ca_root(Certificate::from_pem(&self.ca_pem))
    }

    /// Client config: present our identity and verify the server against the
    /// internal CA for the given SNI domain.
    pub fn client_config(&self, domain: &str) -> ClientTlsConfig {
        ClientTlsConfig::new()
            .identity(Identity::from_pem(&self.cert_pem, &self.key_pem))
            .ca_certificate(Certificate::from_pem(&self.ca_pem))
            .domain_name(domain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_env_none_when_unset() {
        // The env is clean in this isolated test binary path.
        std::env::remove_var("MTLS_CERT");
        std::env::remove_var("MTLS_KEY");
        std::env::remove_var("MTLS_CA");
        std::env::remove_var("TLS_CERT_FILE");
        std::env::remove_var("TLS_KEY_FILE");
        std::env::remove_var("TLS_CA_FILE");
        std::env::set_var("DEV_MODE", "1");
        assert!(MtlsMaterial::from_env().unwrap().is_none());
        std::env::remove_var("DEV_MODE");
    }

    #[test]
    fn from_env_prod_missing_is_error() {
        for k in [
            "MTLS_CERT",
            "MTLS_KEY",
            "MTLS_CA",
            "TLS_CERT_FILE",
            "TLS_KEY_FILE",
            "TLS_CA_FILE",
            "DEV_MODE",
        ] {
            std::env::remove_var(k);
        }
        assert!(MtlsMaterial::from_env().is_err());
    }

    #[test]
    fn from_env_tls_cert_file_trio_works() {
        std::env::remove_var("MTLS_CERT");
        std::env::remove_var("MTLS_KEY");
        std::env::remove_var("MTLS_CA");
        std::env::set_var("TLS_CERT_FILE", "/x/cert.pem");
        std::env::set_var("TLS_KEY_FILE", "/x/key.pem");
        std::env::set_var("TLS_CA_FILE", "/x/ca.pem");
        // from_env reads the trio but from_paths will fail because the files
        // don't exist; verify it tries to load by asserting an error mentioning
        // read MTLS_CERT or the path.
        let err = MtlsMaterial::from_env().unwrap_err().to_string();
        assert!(err.contains("read MTLS_CERT") || err.contains("/x/cert.pem"));
        std::env::remove_var("TLS_CERT_FILE");
        std::env::remove_var("TLS_KEY_FILE");
        std::env::remove_var("TLS_CA_FILE");
    }

    #[test]
    fn from_env_partial_is_error() {
        std::env::set_var("MTLS_CERT", "/x/cert.pem");
        std::env::remove_var("MTLS_KEY");
        std::env::remove_var("MTLS_CA");
        assert!(MtlsMaterial::from_env().is_err());
        std::env::remove_var("MTLS_CERT");
    }

    #[test]
    fn from_paths_missing_file_errors() {
        assert!(MtlsMaterial::from_paths("/no/cert", "/no/key", "/no/ca").is_err());
    }

    #[test]
    fn from_pem_builds_configs() {
        // Well-formed-shape PEM is accepted at config-build time (tonic parses
        // lazily at serve time); the real handshake is covered by the
        // mtls_handshake integration test.
        let m = MtlsMaterial::from_pem(b"cert".to_vec(), b"key".to_vec(), b"ca".to_vec());
        let _ = m.clone().server_config();
        let _ = m.client_config("localhost");
    }
}
