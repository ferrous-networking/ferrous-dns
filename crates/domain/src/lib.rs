pub mod blocklist;
pub mod client;
pub mod config;
pub mod dns_protocol;
pub mod dns_query;
pub mod dns_record;
pub mod dns_request;
pub mod errors;
pub mod query_filters;
pub mod query_log;

pub use blocklist::BlockedDomain;
pub use client::{Client, ClientStats};
pub use config::{
    CliOverrides, ConditionalForward, Config, ConfigError, DnsConfig, HealthCheckConfig,
    LocalDnsRecord, UpstreamPool, UpstreamStrategy,
};
pub use dns_protocol::DnsProtocol;
pub use dns_query::DnsQuery;
pub use dns_record::{DnsRecord, RecordCategory, RecordType};
pub use dns_request::DnsRequest;
pub use errors::DomainError;
pub use query_filters::{FqdnFilter, PrivateIpFilter};
pub use query_log::{CacheStats, QueryLog, QuerySource, QueryStats};
