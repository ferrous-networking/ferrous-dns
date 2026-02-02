//! Ferrous DNS Domain Layer
pub mod errors;
pub mod dns_record;
pub mod query_log;
pub mod blocklist;
pub mod config;
pub mod dns_request;
pub mod dns_query;

pub use blocklist::BlockedDomain;
pub use config::DnsConfig;
pub use dns_query::DnsQuery;
pub use dns_record::{DnsRecord, RecordType};
pub use dns_request::DnsRequest;
pub use errors::DomainError;
pub use query_log::{QueryLog, QueryStats};
