use ferrous_dns_domain::DomainError;

/// EDNS option code for Extended DNS Errors (RFC 8914, Section 2).
/// hickory-proto 0.26.0-alpha.1 does not have a native EDE variant in
/// EdnsOption, so we encode via EdnsOption::Unknown(OPTION_CODE, data).
pub const OPTION_CODE: u16 = 15;

pub mod codes {
    pub const OTHER: u16 = 0;
    pub const DNSSEC_BOGUS: u16 = 6;
    pub const DNSKEY_MISSING: u16 = 9;
    pub const BLOCKED: u16 = 15;
    pub const PROHIBITED: u16 = 18;
    pub const NO_REACHABLE_AUTHORITY: u16 = 22;
    pub const NETWORK_ERROR: u16 = 23;
}

pub struct ExtendedDnsError {
    pub info_code: u16,
    pub extra_text: Option<&'static str>,
}

pub fn from_domain_error(err: &DomainError) -> Option<ExtendedDnsError> {
    let code = match err {
        DomainError::Blocked | DomainError::DgaDomainDetected => codes::BLOCKED,
        DomainError::DnsTunnelingDetected | DomainError::DnsRateLimited => codes::PROHIBITED,
        DomainError::DnssecValidationFailed(_) => codes::DNSSEC_BOGUS,
        DomainError::InsecureDelegation => codes::DNSKEY_MISSING,
        DomainError::QueryTimeout
        | DomainError::TransportNoHealthyServers
        | DomainError::TransportAllServersUnreachable => codes::NO_REACHABLE_AUTHORITY,
        DomainError::TransportTimeout { .. }
        | DomainError::TransportConnectionRefused { .. }
        | DomainError::TransportConnectionReset { .. } => codes::NETWORK_ERROR,
        _ => return None,
    };
    Some(ExtendedDnsError {
        info_code: code,
        extra_text: None,
    })
}
