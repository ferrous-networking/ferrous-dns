use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum DomainError {
    #[error("Invalid domain name: {0}")]
    InvalidDomainName(String),

    #[error("Invalid Safe Search engine: {0}")]
    InvalidSafeSearchEngine(String),

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

    #[error("DNS query rate limited")]
    DnsRateLimited,

    #[error("DNS query rate limited (truncated, retry via TCP)")]
    DnsRateLimitedSlip,

    #[error("DNS tunneling detected")]
    DnsTunnelingDetected,

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

    #[error("Schedule profile not found: {0}")]
    ScheduleProfileNotFound(i64),

    #[error("Schedule profile name already exists: {0}")]
    DuplicateScheduleProfileName(String),

    #[error("Invalid schedule profile: {0}")]
    InvalidScheduleProfile(String),

    #[error("Group has no schedule assigned: {0}")]
    GroupHasNoSchedule(i64),

    #[error("Time slot not found: {0}")]
    TimeSlotNotFound(i64),

    #[error("Invalid time slot: {0}")]
    InvalidTimeSlot(String),

    #[error("Invalid timezone: {0}")]
    InvalidTimezone(String),

    // Auth errors
    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Authentication required")]
    AuthRequired,

    #[error("Session not found or expired")]
    SessionNotFound,

    #[error("Too many login attempts, try again later")]
    RateLimited,

    #[error("Password not configured, run initial setup")]
    PasswordNotConfigured,

    #[error("Password already configured")]
    PasswordAlreadyConfigured,

    #[error("API token not found: {0}")]
    ApiTokenNotFound(i64),

    #[error("API token name already exists: {0}")]
    DuplicateApiTokenName(String),

    #[error("User not found: {0}")]
    UserNotFound(String),

    #[error("Username already exists: {0}")]
    DuplicateUsername(String),

    #[error("Protected user cannot be modified via API")]
    ProtectedUser,

    #[error("Invalid username: {0}")]
    InvalidUsername(String),

    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    #[error("Insufficient permissions")]
    InsufficientPermissions,

    #[error("Invalid input: {0}")]
    InvalidInput(String),
}
