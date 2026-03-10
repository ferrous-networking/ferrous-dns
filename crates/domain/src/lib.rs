pub mod config;
pub mod dns_record;
pub mod entities;
pub mod errors;
pub mod value_objects;

pub use entities::blocklist;
pub use entities::client;
pub use entities::query_log;
pub use entities::schedule;
pub use entities::whitelist;

pub use config::{
    AdminConfig, AuthConfig, CliOverrides, Config, ConfigError, DgaDetectionAction,
    DgaDetectionConfig, DnsConfig, EncryptedDnsConfig, HealthCheckConfig, LocalDnsRecord,
    NxdomainHijackAction, NxdomainHijackConfig, RateLimitConfig, ResponseIpFilterAction,
    ResponseIpFilterConfig, TunnelingAction, TunnelingDetectionConfig, UpstreamPool,
    UpstreamStrategy,
};
pub use dns_record::{DnsRecord, RecordCategory, RecordType};
pub use entities::api_token::ApiToken;
pub use entities::auth_session::AuthSession;
pub use entities::block_source::BlockSource;
pub use entities::blocked_service::BlockedService;
pub use entities::blocklist::BlockedDomain;
pub use entities::blocklist_source::BlocklistSource;
pub use entities::client::{Client, ClientStats};
pub use entities::client_subnet::{ClientSubnet, SubnetMatcher};
pub use entities::custom_service::CustomService;
pub use entities::group::{Group, GroupStats};
pub use entities::managed_domain::{DomainAction, ManagedDomain};
pub use entities::query_log::{CacheStats, QueryLog, QuerySource, QueryStats};
pub use entities::regex_filter::RegexFilter;
pub use entities::safe_search::{SafeSearchConfig, SafeSearchEngine, YouTubeMode};
pub use entities::schedule::{
    evaluate_slots, GroupOverride, ScheduleAction, ScheduleProfile, TimeSlot, UnknownScheduleAction,
};
pub use entities::service_catalog::ServiceDefinition;
pub use entities::user::{User, UserRole, UserSource};
pub use entities::whitelist::WhitelistedDomain;
pub use entities::whitelist_source::WhitelistSource;
pub use errors::domain_error::DomainError;
pub use value_objects::dns_protocol::{DnsProtocol, UpstreamAddr};
pub use value_objects::dns_query::DnsQuery;
pub use value_objects::dns_request::DnsRequest;
pub use value_objects::query_filters::{FqdnFilter, PrivateIpFilter};
