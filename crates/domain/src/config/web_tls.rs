use serde::{Deserialize, Serialize};

/// Configuration for TLS on the web dashboard and REST API.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebTlsConfig {
    /// Whether HTTPS is enabled for the web server.
    #[serde(default)]
    pub enabled: bool,

    /// Path to the PEM-encoded TLS certificate file.
    #[serde(default = "default_cert_path")]
    pub tls_cert_path: String,

    /// Path to the PEM-encoded TLS private key file.
    #[serde(default = "default_key_path")]
    pub tls_key_path: String,
}

fn default_cert_path() -> String {
    "/data/cert.pem".to_string()
}

fn default_key_path() -> String {
    "/data/key.pem".to_string()
}

impl Default for WebTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tls_cert_path: default_cert_path(),
            tls_key_path: default_key_path(),
        }
    }
}
