use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum DomainError {
    #[error("Invalid domain name: {0}")]
    InvalidDomainName(String),

    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("DNSSEC validation failed: {0}")]
    DnssecValidationFailed(String),

    #[error("Insecure DNSSEC delegation: no DS records")]
    InsecureDelegation,

    #[error("Invalid DNS response: {0}")]
    InvalidDnsResponse(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Domain is blocked")]
    Blocked,

    #[error("Domain not found (NXDOMAIN)")]
    NxDomain,

    #[error("Local domain not found (NXDOMAIN from local DNS server)")]
    LocalNxDomain,

    #[error("Query timeout")]
    QueryTimeout,

    #[error("Query filtered: {0}")]
    FilteredQuery(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Group not found: {0}")]
    GroupNotFound(i64),

    #[error("Protected group cannot be disabled")]
    ProtectedGroupCannotBeDisabled,

    #[error("Protected group cannot be deleted")]
    ProtectedGroupCannotBeDeleted,

    #[error("Cannot delete group with {0} assigned clients")]
    GroupHasAssignedClients(u64),

    #[error("Invalid group name: {0}")]
    InvalidGroupName(String),

    #[error("Invalid CIDR format: {0}")]
    InvalidCidr(String),

    #[error("Subnet not found: {0}")]
    SubnetNotFound(String),

    #[error("Subnet conflicts with existing: {0}")]
    SubnetConflict(String),

    #[error("Client not found: {0}")]
    ClientNotFound(String),

    #[error("Blocklist source not found: {0}")]
    BlocklistSourceNotFound(i64),

    #[error("Invalid blocklist source: {0}")]
    InvalidBlocklistSource(String),

    #[error("Whitelist source not found: {0}")]
    WhitelistSourceNotFound(i64),

    #[error("Invalid whitelist source: {0}")]
    InvalidWhitelistSource(String),

    #[error("Block filter fetch error: {0}")]
    BlockFilterFetchError(String),

    #[error("Block filter compile error: {0}")]
    BlockFilterCompileError(String),

    #[error("Managed domain not found: {0}")]
    ManagedDomainNotFound(i64),

    #[error("Invalid managed domain: {0}")]
    InvalidManagedDomain(String),

    #[error("Regex filter not found: {0}")]
    RegexFilterNotFound(i64),

    #[error("Service not found in catalog: {0}")]
    ServiceNotFoundInCatalog(String),

    #[error("Service already blocked: {0}")]
    BlockedServiceAlreadyExists(String),

    #[error("Custom service not found: {0}")]
    CustomServiceNotFound(String),

    #[error("Custom service already exists: {0}")]
    CustomServiceAlreadyExists(String),

    #[error("Invalid regex filter: {0}")]
    InvalidRegexFilter(String),

    #[error("Transport timeout connecting to {server}")]
    TransportTimeout { server: String },

    #[error("Transport connection refused by {server}")]
    TransportConnectionRefused { server: String },

    #[error("Transport connection reset by {server}")]
    TransportConnectionReset { server: String },

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("No healthy upstream servers available")]
    TransportNoHealthyServers,

    #[error("All upstream servers are unreachable")]
    TransportAllServersUnreachable,
}
