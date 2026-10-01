//! The upstream budget (issue #239): only a query about to wait on an
//! upstream takes a slot, so answers that need none stay serviceable while
//! slow upstreams hold every slot.

mod helpers;

use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, SafeSearchEnginePort};
use ferrous_dns_application::use_cases::dns::DnsRateLimiter;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    ClientProtocol, DnsQuery, DnsRequest, DomainError, RateLimitConfig, RecordType,
};
use helpers::{MockBlockFilterEngine, MockQueryLogRepository};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;

const CLIENT_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
/// Outside the rate limiter's whitelist, with a one-query burst.
const LIMITED_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
const SAFE_TARGET: &str = "forcesafesearch.google.com";

/// Holds `slow.example.com` until released, fails `fail.example.com` and
/// answers every other name. Caches `cached.example.com`, and a negative
/// entry for `nx.example.com`.
struct HeldResolver {
    entered: Notify,
    release: Semaphore,
}

#[async_trait]
impl DnsResolver for HeldResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        match query.domain.as_ref() {
            "slow.example.com" => {
                self.entered.notify_one();
                self.release.acquire().await.unwrap().forget();
            }
            "fail.example.com" => return Err(DomainError::QueryTimeout),
            _ => {}
        }
        Ok(DnsResolution::new(
            vec![IpAddr::from([192, 0, 2, 1])],
            false,
        ))
    }

    fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        match query.domain.as_ref() {
            "cached.example.com" => {
                Some(DnsResolution::new(vec![IpAddr::from([192, 0, 2, 1])], true))
            }
            "nx.example.com" => Some(DnsResolution::new(vec![], true)),
            _ => None,
        }
    }
}

struct ForceSafeSearch;

#[async_trait]
impl SafeSearchEnginePort for ForceSafeSearch {
    fn cname_for(&self, domain: &str, _group_id: i64) -> Option<&'static str> {
        (domain == "www.google.com").then_some(SAFE_TARGET)
    }
    async fn reload(&self) -> Result<(), DomainError> {
        Ok(())
    }
}

struct Fixture {
    use_case: Arc<HandleDnsQueryUseCase>,
    resolver: Arc<HeldResolver>,
    log: Arc<MockQueryLogRepository>,
}

/// A use case with a single upstream slot.
fn fixture() -> Fixture {
    let resolver = Arc::new(HeldResolver {
        entered: Notify::new(),
        release: Semaphore::new(0),
    });
    let filter = Arc::new(MockBlockFilterEngine::new());
    filter.block_domain("blocked.example.com");
    let log = Arc::new(MockQueryLogRepository::new());
    let rate_limit = RateLimitConfig {
        enabled: true,
        queries_per_second: 1,
        burst_size: 1,
        whitelist: vec!["192.168.1.0/24".to_string()],
        ..RateLimitConfig::default()
    };
    let use_case = HandleDnsQueryUseCase::new(resolver.clone(), filter, log.clone())
        .with_rate_limiter(Arc::new(DnsRateLimiter::new(&rate_limit)))
        .with_safe_search(Arc::new(ForceSafeSearch))
        .with_upstream_limit(1);
    Fixture {
        use_case: Arc::new(use_case),
        resolver,
        log,
    }
}

fn request(domain: &str) -> DnsRequest {
    DnsRequest::new(domain, RecordType::A, CLIENT_IP).with_protocol(ClientProtocol::Udp)
}

/// Starts a query for `slow.example.com` and returns once it holds the slot.
async fn hold_the_slot(fixture: &Fixture) -> JoinHandle<Result<DnsResolution, DomainError>> {
    let use_case = Arc::clone(&fixture.use_case);
    let held = tokio::spawn(async move { use_case.execute(&request("slow.example.com")).await });
    fixture.resolver.entered.notified().await;
    held
}

#[tokio::test]
async fn test_answers_that_need_no_upstream_are_served_while_the_slot_is_held() {
    let fixture = fixture();
    let held = hold_the_slot(&fixture).await;
    let use_case = &fixture.use_case;

    assert!(matches!(
        use_case.execute(&request("blocked.example.com")).await,
        Err(DomainError::Blocked)
    ));
    assert!(
        use_case
            .execute(&request("cached.example.com"))
            .await
            .unwrap()
            .cache_hit
    );
    assert!(matches!(
        use_case.execute(&request("nx.example.com")).await,
        Err(DomainError::NxDomain)
    ));
    let limited = DnsRequest::new("cached.example.com", RecordType::A, LIMITED_IP);
    assert!(use_case.execute(&limited).await.is_ok());
    assert!(matches!(
        use_case.execute(&limited).await,
        Err(DomainError::DnsRateLimited)
    ));

    fixture.resolver.release.add_permits(1);
    assert!(held.await.unwrap().is_ok());
}

#[tokio::test]
async fn test_a_miss_over_the_budget_is_shed_on_every_transport_without_a_log_entry() {
    let fixture = fixture();
    let held = hold_the_slot(&fixture).await;
    let logged = fixture.log.sync_log_count();

    for protocol in [
        ClientProtocol::Udp,
        ClientProtocol::Tcp,
        ClientProtocol::Dot,
        ClientProtocol::Doh,
        ClientProtocol::Doq,
    ] {
        let miss =
            DnsRequest::new("miss.example.com", RecordType::A, CLIENT_IP).with_protocol(protocol);
        assert!(
            matches!(
                fixture.use_case.execute(&miss).await,
                Err(DomainError::UpstreamCapacityExhausted)
            ),
            "{protocol:?}"
        );
    }
    assert_eq!(fixture.log.sync_log_count(), logged);

    fixture.resolver.release.add_permits(1);
    assert!(held.await.unwrap().is_ok());
    assert!(fixture
        .use_case
        .execute(&request("miss.example.com"))
        .await
        .is_ok());
}

#[tokio::test]
async fn test_a_failed_resolve_frees_its_slot() {
    let fixture = fixture();

    assert!(matches!(
        fixture.use_case.execute(&request("fail.example.com")).await,
        Err(DomainError::QueryTimeout)
    ));
    assert!(fixture
        .use_case
        .execute(&request("miss.example.com"))
        .await
        .is_ok());
}

#[tokio::test]
async fn test_a_safe_search_rewrite_that_misses_needs_a_slot() {
    let fixture = fixture();
    let held = hold_the_slot(&fixture).await;

    assert!(matches!(
        fixture.use_case.execute(&request("www.google.com")).await,
        Err(DomainError::UpstreamCapacityExhausted)
    ));

    fixture.resolver.release.add_permits(1);
    assert!(held.await.unwrap().is_ok());
    assert!(fixture
        .use_case
        .execute(&request("www.google.com"))
        .await
        .is_ok());
}
