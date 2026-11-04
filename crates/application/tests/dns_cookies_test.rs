mod helpers;

use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_application::use_cases::dns::DnsCookieGuard;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockSource, ClientProtocol, CookieStatus, DnsCookiesConfig, DnsRequest, DomainError,
    EdnsCookie, RecordType,
};
use helpers::{MockBlockFilterEngine, MockDnsResolver, MockQueryLogRepository};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

const CLIENT_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
const SECRET: [u8; 32] = [0xDEu8; 32];

fn cookies_config(require_valid: bool) -> DnsCookiesConfig {
    DnsCookiesConfig {
        enabled: true,
        server_secret: None,
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

fn cookie(data: &[u8]) -> EdnsCookie {
    EdnsCookie::from_bytes(data).expect("a valid COOKIE length")
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
        DnsRequest::new("example.com", RecordType::A, CLIENT_IP).with_cookie(cookie(&[0xBBu8; 8]));
    let result = use_case.execute(&request).await;
    assert!(
        result.is_ok(),
        "bootstrapping client cookie must be allowed when require_valid_cookie is false"
    );
}

#[tokio::test]
async fn should_allow_query_with_valid_server_cookie() {
    let resolver = resolver_ok().await;
    let config = cookies_config(true);
    let guard = DnsCookieGuard::from_config(&config, SECRET);
    let (use_case, _log) = make_use_case(resolver, guard);

    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP)
        .with_cookie(cookie(&valid_cookie_for(CLIENT_IP)));
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
        DnsRequest::new("example.com", RecordType::A, CLIENT_IP).with_cookie(cookie(&bad_cookie));
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
        DnsRequest::new("example.com", RecordType::A, CLIENT_IP).with_cookie(cookie(&[0xBBu8; 8]));
    let result = use_case.execute(&request).await;
    assert!(
        matches!(result, Err(DomainError::DnsCookieInvalid)),
        "bootstrapping client cookie must be rejected when require_valid_cookie is true"
    );
}

/// RFC 7873 §5.2.3: TCP, TLS and QUIC already prove the source address, so
/// strict mode validates cookies over UDP only. DoH and DoT clients send none.
#[tokio::test]
async fn should_allow_query_without_cookie_over_stream_transports_when_require_valid_cookie_true() {
    let config = cookies_config(true);
    for protocol in [
        ClientProtocol::Tcp,
        ClientProtocol::Dot,
        ClientProtocol::Doh,
        ClientProtocol::Doq,
    ] {
        let guard = DnsCookieGuard::from_config(&config, SECRET);
        let (use_case, _log) = make_use_case(resolver_ok().await, guard);
        let request =
            DnsRequest::new("example.com", RecordType::A, CLIENT_IP).with_protocol(protocol);
        let result = use_case.execute(&request).await;
        assert!(result.is_ok(), "{protocol} must not need a cookie");
    }

    let guard = DnsCookieGuard::from_config(&config, SECRET);
    let (use_case, _log) = make_use_case(resolver_ok().await, guard);
    let request =
        DnsRequest::new("example.com", RecordType::A, CLIENT_IP).with_protocol(ClientProtocol::Udp);
    let result = use_case.execute(&request).await;
    assert!(
        matches!(result, Err(DomainError::DnsCookieInvalid)),
        "UDP without a cookie must be rejected when require_valid_cookie is true"
    );
}

/// Strict mode validates every UDP query, cache hits included: the inline
/// cache path declines them all and leaves them to `execute`, which does.
#[test]
fn should_leave_cache_hits_to_execute_when_require_valid_cookie_true() {
    for (require_valid, served_inline) in [(true, false), (false, true)] {
        let resolver = MockDnsResolver::new();
        resolver.set_cached_response(
            "example.com",
            DnsResolution::new(vec!["1.2.3.4".parse().unwrap()], true),
        );
        let guard = DnsCookieGuard::from_config(&cookies_config(require_valid), SECRET);
        let (use_case, _log) = make_use_case(resolver, guard);

        let hit = use_case.try_cache_direct(
            "example.com",
            RecordType::A,
            CLIENT_IP,
            ClientProtocol::Udp,
            None,
            |addresses, _ttl, _cookie| Some(addresses.len()),
        );
        assert_eq!(
            hit.is_some(),
            served_inline,
            "require_valid_cookie = {require_valid}"
        );
    }
}

const ROTATION_SECS: u64 = 3600;
/// The start of a rotation window, so each `+ ROTATION_SECS` is the next one.
const WINDOW_START: u64 = 1_800_000_000 / ROTATION_SECS * ROTATION_SECS;
const CLIENT_COOKIE: [u8; 8] = [0xAAu8; 8];

/// A clock the test sets by hand, in Unix seconds.
fn manual_clock(start: u64) -> (Arc<AtomicU64>, impl Fn() -> u64 + Send + Sync + 'static) {
    let now = Arc::new(AtomicU64::new(start));
    let reader = Arc::clone(&now);
    (now, move || reader.load(Ordering::Relaxed))
}

fn rotating_config(secret_rotation_secs: u64) -> DnsCookiesConfig {
    DnsCookiesConfig {
        secret_rotation_secs,
        ..cookies_config(true)
    }
}

fn server_cookie(use_case: &HandleDnsQueryUseCase) -> [u8; 8] {
    use_case
        .cookie_guard()
        .expect("cookies are on")
        .generate_server_cookie(CLIENT_IP, &CLIENT_COOKIE)
}

fn query_with(server_cookie: [u8; 8]) -> DnsRequest {
    let data = [CLIENT_COOKIE, server_cookie].concat();
    DnsRequest::new("example.com", RecordType::A, CLIENT_IP).with_cookie(cookie(&data))
}

/// `secret_rotation_secs`: a server cookie is signed with the secret of its
/// rotation window, and the previous window's secret is still accepted.
#[tokio::test]
async fn test_cookie_is_accepted_one_rotation_later_and_refused_two_later() {
    let (now, clock) = manual_clock(WINDOW_START + 10);
    let guard =
        DnsCookieGuard::from_config(&rotating_config(ROTATION_SECS), SECRET).with_clock(clock);
    let (use_case, _log) = make_use_case(resolver_ok().await, guard);
    let issued = server_cookie(&use_case);

    now.store(WINDOW_START + ROTATION_SECS + 10, Ordering::Relaxed);
    assert!(
        use_case.execute(&query_with(issued)).await.is_ok(),
        "a cookie from the previous rotation window must still be accepted"
    );

    now.store(WINDOW_START + 2 * ROTATION_SECS + 10, Ordering::Relaxed);
    assert!(
        matches!(
            use_case.execute(&query_with(issued)).await,
            Err(DomainError::DnsCookieInvalid)
        ),
        "a cookie two rotation windows old must be refused"
    );
}

#[tokio::test]
async fn test_server_cookie_changes_when_the_rotation_window_turns() {
    let (now, clock) = manual_clock(WINDOW_START + ROTATION_SECS - 1);
    let guard =
        DnsCookieGuard::from_config(&rotating_config(ROTATION_SECS), SECRET).with_clock(clock);
    let (use_case, _log) = make_use_case(resolver_ok().await, guard);
    let before = server_cookie(&use_case);

    now.store(WINDOW_START + ROTATION_SECS, Ordering::Relaxed);
    assert_ne!(server_cookie(&use_case), before);
}

/// Every reply carries a cookie for the current window, so a client that
/// keeps querying never holds one old enough to be refused.
#[tokio::test]
async fn test_cookie_from_a_later_reply_outlives_the_first_one() {
    let (now, clock) = manual_clock(WINDOW_START + 10);
    let guard =
        DnsCookieGuard::from_config(&rotating_config(ROTATION_SECS), SECRET).with_clock(clock);
    let (use_case, _log) = make_use_case(resolver_ok().await, guard);

    now.store(WINDOW_START + ROTATION_SECS + 10, Ordering::Relaxed);
    let refreshed = server_cookie(&use_case);

    now.store(WINDOW_START + 2 * ROTATION_SECS + 10, Ordering::Relaxed);
    assert!(use_case.execute(&query_with(refreshed)).await.is_ok());
}

/// Servers that share `server_secret` (anycast) and keep their clocks in sync
/// accept each other's cookies.
#[tokio::test]
async fn test_guards_sharing_a_secret_and_clock_accept_each_others_cookies() {
    let (_now, clock) = manual_clock(WINDOW_START + 10);
    let (_other_now, other_clock) = manual_clock(WINDOW_START + 10);
    let config = rotating_config(ROTATION_SECS);
    let issuer = DnsCookieGuard::from_config(&config, SECRET).with_clock(clock);
    let issued = issuer.generate_server_cookie(CLIENT_IP, &CLIENT_COOKIE);

    let verifier = DnsCookieGuard::from_config(&config, SECRET).with_clock(other_clock);
    let (use_case, _log) = make_use_case(resolver_ok().await, verifier);
    assert!(use_case.execute(&query_with(issued)).await.is_ok());
}

/// `secret_rotation_secs = 0` keeps one secret for the life of the process.
#[tokio::test]
async fn test_cookie_never_expires_when_rotation_is_off() {
    let (now, clock) = manual_clock(WINDOW_START + 10);
    let guard = DnsCookieGuard::from_config(&rotating_config(0), SECRET).with_clock(clock);
    let (use_case, _log) = make_use_case(resolver_ok().await, guard);
    let issued = server_cookie(&use_case);

    now.store(WINDOW_START + 10 * 365 * 86_400, Ordering::Relaxed);
    assert!(use_case.execute(&query_with(issued)).await.is_ok());
    assert_eq!(server_cookie(&use_case), issued);
}

/// The one row a query logged.
fn logged(log: &MockQueryLogRepository) -> ferrous_dns_domain::QueryLog {
    let mut rows = log.get_sync_logs();
    assert_eq!(rows.len(), 1, "one query, one row: {rows:?}");
    rows.remove(0)
}

fn request_with(sent: Option<&[u8]>) -> DnsRequest {
    let request = DnsRequest::new("example.com", RecordType::A, CLIENT_IP);
    match sent {
        Some(data) => request.with_cookie(cookie(data)),
        None => request,
    }
}

/// The server cookie `SECRET` signs for `CLIENT_COOKIE` at `now`.
fn issued_at(now: u64) -> Vec<u8> {
    let (_now, clock) = manual_clock(now);
    let guard =
        DnsCookieGuard::from_config(&rotating_config(ROTATION_SECS), SECRET).with_clock(clock);
    [
        CLIENT_COOKIE,
        guard.generate_server_cookie(CLIENT_IP, &CLIENT_COOKIE),
    ]
    .concat()
}

/// The Query Log records what each query's DNS Cookie showed.
#[tokio::test]
async fn test_execute_logs_what_the_query_cookie_showed() {
    let current = issued_at(WINDOW_START + 10);
    let previous_window = issued_at(WINDOW_START - 10);
    let forged = [CLIENT_COOKIE, [0xFF; 8]].concat();
    for (sent, expected) in [
        (None, None),
        (Some(&CLIENT_COOKIE[..]), Some(CookieStatus::ClientOnly)),
        (Some(&current[..]), Some(CookieStatus::Valid)),
        (Some(&previous_window[..]), Some(CookieStatus::Valid)),
        (Some(&forged[..]), Some(CookieStatus::Invalid)),
    ] {
        let (_now, clock) = manual_clock(WINDOW_START + 10);
        let config = DnsCookiesConfig {
            secret_rotation_secs: ROTATION_SECS,
            ..cookies_config(false)
        };
        let guard = DnsCookieGuard::from_config(&config, SECRET).with_clock(clock);
        let (use_case, log) = make_use_case(resolver_ok().await, guard);

        use_case.execute(&request_with(sent)).await.unwrap();

        assert_eq!(logged(&log).cookie, expected, "{sent:?}");
    }
}

/// Strict mode refuses a UDP query without a valid server cookie, and the
/// Query Log shows the refusal with the rcode the client got.
#[tokio::test]
async fn test_strict_mode_logs_the_queries_it_refuses() {
    let forged = [CLIENT_COOKIE, [0xFF; 8]].concat();
    for (sent, rcode, expected) in [
        (
            Some(&CLIENT_COOKIE[..]),
            "BADCOOKIE",
            Some(CookieStatus::ClientOnly),
        ),
        (Some(&forged[..]), "BADCOOKIE", Some(CookieStatus::Invalid)),
        (None, "REFUSED", None),
    ] {
        let (_now, clock) = manual_clock(WINDOW_START + 10);
        let guard =
            DnsCookieGuard::from_config(&rotating_config(ROTATION_SECS), SECRET).with_clock(clock);
        let (use_case, log) = make_use_case(resolver_ok().await, guard);

        let result = use_case.execute(&request_with(sent)).await;

        assert!(
            matches!(result, Err(DomainError::DnsCookieInvalid)),
            "{sent:?}"
        );
        let row = logged(&log);
        assert!(row.blocked, "{sent:?}");
        assert_eq!(row.block_source, Some(BlockSource::DnsCookie), "{sent:?}");
        assert_eq!(row.response_status, Some(rcode), "{sent:?}");
        assert_eq!(row.cookie, expected, "{sent:?}");
    }
}

/// Strict mode leaves stream transports unchecked, but their rows still say
/// what the cookie showed.
#[tokio::test]
async fn test_strict_mode_logs_the_cookie_of_a_stream_query_it_answers() {
    let (_now, clock) = manual_clock(WINDOW_START + 10);
    let guard =
        DnsCookieGuard::from_config(&rotating_config(ROTATION_SECS), SECRET).with_clock(clock);
    let (use_case, log) = make_use_case(resolver_ok().await, guard);
    let request = request_with(Some(&CLIENT_COOKIE[..])).with_protocol(ClientProtocol::Tcp);

    use_case.execute(&request).await.unwrap();

    let row = logged(&log);
    assert!(!row.blocked);
    assert_eq!(row.cookie, Some(CookieStatus::ClientOnly));
}
