use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: String,

    #[serde(default = "default_true")]
    pub log_queries: bool,

    #[serde(default = "default_queries_log_stored")]
    pub queries_log_stored: u32,

    #[serde(default = "default_client_tracking_interval")]
    pub client_tracking_interval: u64,

    #[serde(default = "default_query_log_channel_capacity")]
    pub query_log_channel_capacity: usize,

    #[serde(default = "default_query_log_max_batch_size")]
    pub query_log_max_batch_size: usize,

    #[serde(default = "default_query_log_flush_interval_ms")]
    pub query_log_flush_interval_ms: u64,

    #[serde(default = "default_query_log_sample_rate")]
    pub query_log_sample_rate: u32,

    #[serde(default = "default_client_channel_capacity")]
    pub client_channel_capacity: usize,

    #[serde(default = "default_write_pool_max_connections")]
    pub write_pool_max_connections: u32,

    #[serde(default = "default_read_pool_max_connections")]
    pub read_pool_max_connections: u32,

    #[serde(default = "default_write_busy_timeout_secs")]
    pub write_busy_timeout_secs: u64,

    #[serde(default = "default_read_busy_timeout_secs")]
    pub read_busy_timeout_secs: u64,

    #[serde(default = "default_read_acquire_timeout_secs")]
    pub read_acquire_timeout_secs: u64,

    #[serde(default = "default_wal_autocheckpoint")]
    pub wal_autocheckpoint: u32,

    #[serde(default = "default_sqlite_cache_size_kb")]
    pub sqlite_cache_size_kb: u32,

    #[serde(default = "default_sqlite_mmap_size_mb")]
    pub sqlite_mmap_size_mb: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: default_db_path(),
            log_queries: true,
            queries_log_stored: default_queries_log_stored(),
            client_tracking_interval: default_client_tracking_interval(),
            query_log_channel_capacity: default_query_log_channel_capacity(),
            query_log_max_batch_size: default_query_log_max_batch_size(),
            query_log_flush_interval_ms: default_query_log_flush_interval_ms(),
            query_log_sample_rate: default_query_log_sample_rate(),
            client_channel_capacity: default_client_channel_capacity(),
            write_pool_max_connections: default_write_pool_max_connections(),
            read_pool_max_connections: default_read_pool_max_connections(),
            write_busy_timeout_secs: default_write_busy_timeout_secs(),
            read_busy_timeout_secs: default_read_busy_timeout_secs(),
            read_acquire_timeout_secs: default_read_acquire_timeout_secs(),
            wal_autocheckpoint: default_wal_autocheckpoint(),
            sqlite_cache_size_kb: default_sqlite_cache_size_kb(),
            sqlite_mmap_size_mb: default_sqlite_mmap_size_mb(),
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

fn default_query_log_channel_capacity() -> usize {
    10_000
}

fn default_query_log_max_batch_size() -> usize {
    500
}

fn default_query_log_flush_interval_ms() -> u64 {
    100
}

fn default_query_log_sample_rate() -> u32 {
    1
}

fn default_client_channel_capacity() -> usize {
    4_096
}

fn default_write_pool_max_connections() -> u32 {
    2
}

fn default_read_pool_max_connections() -> u32 {
    4
}

fn default_write_busy_timeout_secs() -> u64 {
    30
}

fn default_read_busy_timeout_secs() -> u64 {
    15
}

fn default_read_acquire_timeout_secs() -> u64 {
    15
}

fn default_wal_autocheckpoint() -> u32 {
    0
}

fn default_sqlite_cache_size_kb() -> u32 {
    16_384
}

fn default_sqlite_mmap_size_mb() -> u32 {
    64
}
