pub mod blocklist;
pub mod cache;
pub mod config;
pub mod health;
pub mod hostname;
pub mod local_records;
pub mod queries;
pub mod stats;

pub use blocklist::get_blocklist;
pub use cache::{get_cache_metrics, get_cache_stats};
pub use config::{get_config, get_settings, reload_config, update_config, update_settings};
pub use health::health_check;
pub use hostname::get_hostname;
pub use queries::get_queries;
pub use stats::get_stats;
pub mod upstream;
