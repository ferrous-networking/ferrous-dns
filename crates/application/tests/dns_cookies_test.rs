mod helpers;

use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_application::use_cases::dns::DnsCookieGuard;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{DnsCookiesConfig, DnsRequest, DomainError, RecordType};
use helpers::{MockBlockFilterEngine, MockDnsResolver, MockQueryLogRepository};
use std::net::IpAddr;
use std::sync::Arc;

const CLIENT_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
const SECRET: [u8; 32] = [0xDEu8; 32];

fn cookies_config(require_valid: bool) -> DnsCookiesConfig {
    DnsCookiesConfig {
        enabled: true,
        server_secret: String::new(),
        secret_rotation_secs: 3600,
        require_valid_cookie: require_valid,
    }
}

async fn resolver_ok() -> MockDnsResolver {
    let resolver = MockDnsResolver::new();
    resolver
        .set_response(
            "example.com",
            DnsResolution::new(vec!["1.2.3.4".parse().unwrap()], false),
        )
        .await;
    resolver
}

fn make_use_case(
    resolver: MockDnsResolver,
    guard: DnsCookieGuard,
) -> (HandleDnsQueryUseCase, Arc<MockQueryLogRepository>) {
    let log = Arc::new(MockQueryLogRepository::new());
    let use_case = HandleDnsQueryUseCase::new(
        Arc::new(resolver),
        Arc::new(MockBlockFilterEngine::new()),
        log.clone(),
    )
    .with_dns_cookies(guard);
    (use_case, log)
}

fn valid_cookie_for(client_ip: IpAddr) -> Vec<u8> {
    let config = cookies_config(true);
    let guard = DnsCookieGuard::from_config(&config, SECRET);
    let client_cookie = [0xAAu8; 8];
    let server_cookie = guard.generate_server_cookie(client_ip, &client_cookie);
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&client_cookie);
    data.extend_from_slice(&server_cookie);
    data
}

// ── Cookie disabled ──────────────────────────────────────────────────────────

#[tokio::test]
async fn should_pass_through_when_disabled() {
    let resolver = resolver_ok().await;
    let guard = DnsCookieGuard::disabled();
    let (use_case, _log) = make_use_case(resolver, guard);

    // Even a completely absent cookie is fine when the guard is disabled.
    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;
    assert!(result.is_ok());
}

// ── require_valid_cookie = false ─────────────────────────────────────────────

#[tokio::test]
async fn should_allow_query_without_cookie_when_require_valid_cookie_false() {
    let resolver = resolver_ok().await;
    let config = cookies_config(false);
    let guard = DnsCookieGuard::from_config(&config, SECRET);
    let (use_case, _log) = make_use_case(resolver, guard);

    // No cookie attached to the request.
    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;
    assert!(
        result.is_ok(),
        "query without cookie must be allowed when require_valid_cookie is false"
    );
}

#[tokio::test]
async fn should_allow_query_with_only_client_cookie_when_require_valid_cookie_false() {
    let resolver = resolver_ok().await;
    let config = cookies_config(false);
    let guard = DnsCookieGuard::from_config(&config, SECRET);
    let (use_case, _log) = make_use_case(resolver, guard);

    // Only client cookie present (bootstrapping handshake).
    let request =
        DnsRequest::new("example.com", RecordType::A, CLIENT_IP).with_cookie([0xBBu8; 8].to_vec());
    let result = use_case.execute(&request).await;
    assert!(
        result.is_ok(),
        "bootstrapping client cookie must be allowed when require_valid_cookie is false"
    );
}

// ── require_valid_cookie = true ──────────────────────────────────────────────

#[tokio::test]
async fn should_allow_query_with_valid_server_cookie() {
    let resolver = resolver_ok().await;
    let config = cookies_config(true);
    let guard = DnsCookieGuard::from_config(&config, SECRET);
    let (use_case, _log) = make_use_case(resolver, guard);

    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP)
        .with_cookie(valid_cookie_for(CLIENT_IP));
    let result = use_case.execute(&request).await;
    assert!(result.is_ok(), "valid cookie must be accepted");
}

#[tokio::test]
async fn should_reject_query_with_invalid_server_cookie() {
    let resolver = resolver_ok().await;
    let config = cookies_config(true);
    let guard = DnsCookieGuard::from_config(&config, SECRET);
    let (use_case, _log) = make_use_case(resolver, guard);

    // Craft a 16-byte cookie where the server portion is garbage.
    let mut bad_cookie = [0x00u8; 16];
    bad_cookie[..8].copy_from_slice(&[0xAAu8; 8]); // client cookie
    bad_cookie[8..].copy_from_slice(&[0xFFu8; 8]); // wrong server cookie

    let request =
        DnsRequest::new("example.com", RecordType::A, CLIENT_IP).with_cookie(bad_cookie.to_vec());
    let result = use_case.execute(&request).await;
    assert!(
        matches!(result, Err(DomainError::DnsCookieInvalid)),
        "invalid server cookie must cause DnsCookieInvalid error"
    );
}

#[tokio::test]
async fn should_reject_query_without_cookie_when_require_valid_cookie_true() {
    let resolver = resolver_ok().await;
    let config = cookies_config(true);
    let guard = DnsCookieGuard::from_config(&config, SECRET);
    let (use_case, _log) = make_use_case(resolver, guard);

    // No cookie at all — the guard sees an empty slice which is < 8 bytes → Invalid.
    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    let result = use_case.execute(&request).await;
    assert!(
        matches!(result, Err(DomainError::DnsCookieInvalid)),
        "absent cookie must be rejected when require_valid_cookie is true"
    );
}

#[tokio::test]
async fn should_reject_query_with_only_client_cookie_when_require_valid_cookie_true() {
    let resolver = resolver_ok().await;
    let config = cookies_config(true);
    let guard = DnsCookieGuard::from_config(&config, SECRET);
    let (use_case, _log) = make_use_case(resolver, guard);

    // Only the 8-byte client cookie — bootstrapping handshake is not enough in strict mode
    // (RFC 7873 §5.2.3: the client must supply a valid server cookie).
    let request =
        DnsRequest::new("example.com", RecordType::A, CLIENT_IP).with_cookie([0xBBu8; 8].to_vec());
    let result = use_case.execute(&request).await;
    assert!(
        matches!(result, Err(DomainError::DnsCookieInvalid)),
        "bootstrapping client cookie must be rejected when require_valid_cookie is true"
    );
}
