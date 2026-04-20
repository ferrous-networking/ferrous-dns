use serde::{Deserialize, Serialize};

/// DNS Cookies anti-spoofing configuration (RFC 7873).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsCookiesConfig {
    /// Master switch — enabled by default for anti-spoofing protection.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Hex-encoded 32-byte HMAC secret (64 hex chars).
    /// When empty, the server generates an ephemeral secret on startup that
    /// will not survive a restart — suitable for testing only.
    #[serde(default)]
    pub server_secret: String,

    /// How often the server rotates to a new secret (seconds).
    /// The previous secret remains accepted during one full rotation window
    /// to allow in-flight clients to re-negotiate without errors.
    #[serde(default = "default_rotation_secs")]
    pub secret_rotation_secs: u64,

    /// When `true`, queries that carry an invalid or absent server cookie are
    /// rejected with REFUSED + EDE 25 (Bad or Missing EDNS Cookie).
    /// When `false` (default), the server responds normally but always
    /// echoes a fresh server cookie so clients can learn and cache it.
    #[serde(default = "default_false")]
    pub require_valid_cookie: bool,
}

impl Default for DnsCookiesConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            server_secret: String::new(),
            secret_rotation_secs: default_rotation_secs(),
            require_valid_cookie: default_false(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_rotation_secs() -> u64 {
    3600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_empty_toml_with_defaults() {
        let config: DnsCookiesConfig = toml::from_str("").unwrap();
        assert!(config.enabled);
        assert!(config.server_secret.is_empty());
        assert_eq!(config.secret_rotation_secs, 3600);
        assert!(!config.require_valid_cookie);
    }

    #[test]
    fn deserializes_partial_toml_preserves_defaults() {
        let toml = r#"
            enabled = true
            secret_rotation_secs = 7200
        "#;
        let config: DnsCookiesConfig = toml::from_str(toml).unwrap();
        assert!(config.enabled);
        assert!(config.server_secret.is_empty());
        assert_eq!(config.secret_rotation_secs, 7200);
        assert!(!config.require_valid_cookie);
    }

    #[test]
    fn serializes_and_deserializes_roundtrip() {
        let original = DnsCookiesConfig {
            enabled: true,
            server_secret: "aabbcc".repeat(10).chars().take(64).collect(),
            secret_rotation_secs: 1800,
            require_valid_cookie: true,
        };
        let toml_str = toml::to_string(&original).unwrap();
        let restored: DnsCookiesConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.enabled, original.enabled);
        assert_eq!(restored.server_secret, original.server_secret);
        assert_eq!(restored.secret_rotation_secs, original.secret_rotation_secs);
        assert_eq!(restored.require_valid_cookie, original.require_valid_cookie);
    }
}
