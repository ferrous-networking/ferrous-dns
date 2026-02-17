use thiserror::Error;

#[derive(Error, Debug)]
pub enum DomainError {
    #[error("Invalid domain name: {0}")]
    InvalidDomainName(String),

    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),

    #[error("DNSSEC validation failed: {0}")]
    DnssecValidationFailed(String),

    #[error("Invalid DNS response: {0}")]
    InvalidDnsResponse(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("Query timeout")]
    QueryTimeout,

    #[error("Query filtered: {0}")]
    FilteredQuery(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Group not found: {0}")]
    GroupNotFound(String),

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
    BlocklistSourceNotFound(String),

    #[error("Invalid blocklist source: {0}")]
    InvalidBlocklistSource(String),
}
