//! Configuration module for Ferrous DNS
//!
//! This module contains all configuration structures organized by domain:
//! - `root`: Main configuration and CLI overrides
//! - `server`: Server ports and binding
//! - `dns`: DNS resolution settings
//! - `upstream`: Upstream server pools and strategies
//! - `health`: Health check configuration
//! - `blocking`: Ad-blocking configuration
//! - `logging`: Logging settings
//! - `database`: Database configuration
//! - `local_records`: Local DNS records
//! - `errors`: Configuration errors

pub mod blocking;
pub mod database;
pub mod dns;
pub mod errors;
pub mod health;
pub mod local_records;
pub mod logging;
pub mod root;
pub mod server;
pub mod upstream;

pub use blocking::BlockingConfig;
pub use database::DatabaseConfig;
pub use dns::{ConditionalForward, DnsConfig};
pub use errors::ConfigError;
pub use health::HealthCheckConfig;
pub use local_records::LocalDnsRecord;
pub use logging::LoggingConfig;
pub use root::{CliOverrides, Config};
pub use server::ServerConfig;
pub use upstream::{UpstreamPool, UpstreamStrategy};
