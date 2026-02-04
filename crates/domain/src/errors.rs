use thiserror::Error;

#[derive(Error, Debug)]
pub enum DomainError {
    #[error("Invalid domain name: {0}")]
    InvalidDomainName(String),

    #[error("Invalid IP address: {0}")]
    InvalidIpAddress(String),
    
    #[error("DNSSEC validation failed: {0}")]
    DnssecValidationFailed(String),
}
