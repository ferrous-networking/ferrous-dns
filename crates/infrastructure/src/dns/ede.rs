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
    let (code, text) = match err {
        DomainError::Blocked => (codes::BLOCKED, "domain is in blocklist"),
        DomainError::DgaDomainDetected => (codes::BLOCKED, "DGA domain detected"),
        DomainError::FilteredQuery(_) => (codes::BLOCKED, "query filtered by policy"),
        DomainError::DnsTunnelingDetected => (codes::PROHIBITED, "DNS tunneling detected"),
        DomainError::DnsRateLimited => (codes::PROHIBITED, "rate limit exceeded"),
        DomainError::DnssecValidationFailed(_) => {
            (codes::DNSSEC_BOGUS, "DNSSEC signature validation failed")
        }
        DomainError::InsecureDelegation => (codes::DNSKEY_MISSING, "insecure delegation"),
        DomainError::QueryTimeout => (codes::NO_REACHABLE_AUTHORITY, "upstream query timed out"),
        DomainError::TransportNoHealthyServers => {
            (codes::NO_REACHABLE_AUTHORITY, "no healthy upstream servers")
        }
        DomainError::TransportAllServersUnreachable => (
            codes::NO_REACHABLE_AUTHORITY,
            "all upstream servers unreachable",
        ),
        DomainError::TransportTimeout { .. } => {
            (codes::NETWORK_ERROR, "upstream connection timed out")
        }
        DomainError::TransportConnectionRefused { .. } => {
            (codes::NETWORK_ERROR, "upstream connection refused")
        }
        DomainError::TransportConnectionReset { .. } => {
            (codes::NETWORK_ERROR, "upstream connection reset")
        }
        _ => return None,
    };
    Some(ExtendedDnsError {
        info_code: code,
        extra_text: Some(text),
    })
}
