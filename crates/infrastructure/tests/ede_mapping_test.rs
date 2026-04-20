use ferrous_dns_domain::DomainError;
use ferrous_dns_infrastructure::dns::ede::{self, codes, OPTION_CODE};

#[test]
fn should_return_blocked_when_domain_blocked() {
    let ede = ede::from_domain_error(&DomainError::Blocked).unwrap();
    assert_eq!(ede.info_code, codes::BLOCKED);
}

#[test]
fn should_return_blocked_when_dga_detected() {
    let ede = ede::from_domain_error(&DomainError::DgaDomainDetected).unwrap();
    assert_eq!(ede.info_code, codes::BLOCKED);
}

#[test]
fn should_return_prohibited_when_tunneling_detected() {
    let ede = ede::from_domain_error(&DomainError::DnsTunnelingDetected).unwrap();
    assert_eq!(ede.info_code, codes::PROHIBITED);
}

#[test]
fn should_return_prohibited_when_rate_limited() {
    let ede = ede::from_domain_error(&DomainError::DnsRateLimited).unwrap();
    assert_eq!(ede.info_code, codes::PROHIBITED);
}

#[test]
fn should_return_dnssec_bogus_when_validation_failed() {
    let ede =
        ede::from_domain_error(&DomainError::DnssecValidationFailed("sig expired".into())).unwrap();
    assert_eq!(ede.info_code, codes::DNSSEC_BOGUS);
}

#[test]
fn should_return_dnskey_missing_when_insecure_delegation() {
    let ede = ede::from_domain_error(&DomainError::InsecureDelegation).unwrap();
    assert_eq!(ede.info_code, codes::DNSKEY_MISSING);
}

#[test]
fn should_return_no_reachable_authority_when_query_timeout() {
    let ede = ede::from_domain_error(&DomainError::QueryTimeout).unwrap();
    assert_eq!(ede.info_code, codes::NO_REACHABLE_AUTHORITY);
}

#[test]
fn should_return_no_reachable_authority_when_no_healthy_servers() {
    let ede = ede::from_domain_error(&DomainError::TransportNoHealthyServers).unwrap();
    assert_eq!(ede.info_code, codes::NO_REACHABLE_AUTHORITY);
}

#[test]
fn should_return_no_reachable_authority_when_all_servers_unreachable() {
    let ede = ede::from_domain_error(&DomainError::TransportAllServersUnreachable).unwrap();
    assert_eq!(ede.info_code, codes::NO_REACHABLE_AUTHORITY);
}

#[test]
fn should_return_network_error_when_transport_timeout() {
    let ede = ede::from_domain_error(&DomainError::TransportTimeout {
        server: "8.8.8.8:853".into(),
    })
    .unwrap();
    assert_eq!(ede.info_code, codes::NETWORK_ERROR);
}

#[test]
fn should_return_network_error_when_transport_connection_refused() {
    let ede = ede::from_domain_error(&DomainError::TransportConnectionRefused {
        server: "1.1.1.1:53".into(),
    })
    .unwrap();
    assert_eq!(ede.info_code, codes::NETWORK_ERROR);
}

#[test]
fn should_return_network_error_when_transport_connection_reset() {
    let ede = ede::from_domain_error(&DomainError::TransportConnectionReset {
        server: "9.9.9.9:853".into(),
    })
    .unwrap();
    assert_eq!(ede.info_code, codes::NETWORK_ERROR);
}

#[test]
fn should_return_none_when_nxdomain() {
    assert!(ede::from_domain_error(&DomainError::NxDomain).is_none());
}

#[test]
fn should_return_none_when_unrelated_error() {
    assert!(ede::from_domain_error(&DomainError::InvalidCredentials).is_none());
}

#[test]
fn should_return_blocked_when_filtered_query() {
    let ede = ede::from_domain_error(&DomainError::FilteredQuery("private PTR".into())).unwrap();
    assert_eq!(ede.info_code, codes::BLOCKED);
}

#[test]
fn should_return_extra_text_when_blocked() {
    let ede = ede::from_domain_error(&DomainError::Blocked).unwrap();
    assert_eq!(ede.extra_text, Some("domain is in blocklist"));
}

#[test]
fn should_return_extra_text_when_tunneling_detected() {
    let ede = ede::from_domain_error(&DomainError::DnsTunnelingDetected).unwrap();
    assert_eq!(ede.extra_text, Some("DNS tunneling detected"));
}

#[test]
fn should_return_extra_text_when_rate_limited() {
    let ede = ede::from_domain_error(&DomainError::DnsRateLimited).unwrap();
    assert_eq!(ede.extra_text, Some("rate limit exceeded"));
}

#[test]
fn should_return_extra_text_when_query_timeout() {
    let ede = ede::from_domain_error(&DomainError::QueryTimeout).unwrap();
    assert_eq!(ede.extra_text, Some("upstream query timed out"));
}

#[test]
fn ede_option_code_is_15_per_rfc8914() {
    assert_eq!(OPTION_CODE, 15u16);
}
