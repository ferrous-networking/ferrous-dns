use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: String,

    #[serde(default = "default_true")]
    pub log_queries: bool,

    #[serde(default = "default_queries_log_stored")]
    pub queries_log_stored: u32,

    /// Minimum seconds between consecutive `update_last_seen` DB writes for
    /// the same client IP. Lower values increase write pressure on SQLite;
    /// higher values reduce it at the cost of less-frequent last-seen updates.
    /// Default: 60 seconds.
    #[serde(default = "default_client_tracking_interval")]
    pub client_tracking_interval: u64,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
            log_queries: true,
            queries_log_stored: default_queries_log_stored(),
            client_tracking_interval: default_client_tracking_interval(),
        }
    }
}

fn default_db_path() -> String {
    "./ferrous-dns.db".to_string()
}

fn default_true() -> bool {
    true
}

fn default_queries_log_stored() -> u32 {
    30
}

fn default_client_tracking_interval() -> u64 {
    60
}
