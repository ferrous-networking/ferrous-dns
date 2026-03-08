use serde::{Deserialize, Serialize};

/// Authentication configuration, defined in `[auth]` section of `ferrous-dns.toml`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    /// Enable or disable authentication globally.
    /// When disabled, all endpoints are accessible without credentials.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Session cookie lifetime in hours when "Remember Me" is NOT checked.
    /// Default: 24 (1 day). Short-lived session for shared/public devices.
    #[serde(default = "default_session_ttl_hours")]
    pub session_ttl_hours: u32,

    /// Session cookie lifetime in days when "Remember Me" IS checked.
    /// Default: 30 days. Long-lived session for trusted home devices.
    #[serde(default = "default_remember_me_days")]
    pub remember_me_days: u32,

    /// Max failed login attempts before IP lockout.
    #[serde(default = "default_rate_limit_attempts")]
    pub login_rate_limit_attempts: u32,

    /// Rate limit window in seconds. Default: 900 (15 minutes).
    #[serde(default = "default_rate_limit_window_secs")]
    pub login_rate_limit_window_secs: u64,

    /// Admin account configured in TOML — always recoverable via file edit.
    #[serde(default)]
    pub admin: AdminConfig,
}

/// Admin account defined in the TOML config file.
///
/// This is the "escape hatch" — if a user loses access to database users,
/// they can always edit the TOML file and restart to regain admin access.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct AdminConfig {
    /// Admin username. Default: "admin".
    #[serde(default = "default_admin_username")]
    pub username: String,

    /// Argon2id password hash. Set via `--reset-password` CLI or setup endpoint.
    /// When empty/None, first-run setup is triggered.
    pub password_hash: Option<String>,
}

fn default_enabled() -> bool {
    true
}

fn default_session_ttl_hours() -> u32 {
    24
}

fn default_remember_me_days() -> u32 {
    30
}

fn default_rate_limit_attempts() -> u32 {
    5
}

fn default_rate_limit_window_secs() -> u64 {
    900
}

fn default_admin_username() -> String {
    "admin".to_string()
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            session_ttl_hours: default_session_ttl_hours(),
            remember_me_days: default_remember_me_days(),
            login_rate_limit_attempts: default_rate_limit_attempts(),
            login_rate_limit_window_secs: default_rate_limit_window_secs(),
            admin: AdminConfig::default(),
        }
    }
}
