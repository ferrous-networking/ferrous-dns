//! Answers from `local_dns_server` through the whole query path: the use case
//! over the real resolver stack and cache, as the server wires them.
//!
//! A cached local answer must keep counting as local, both for the rebinding
//! guard (a short name is qualified inside the resolver, so the client's name
//! never matches `local_domain`) and for the NXDOMAIN budget, which must not
//! meter the LAN's own reverse lookups.

#[path = "support/ports.rs"]
mod ports;

use ferrous_dns_application::ports::DnsResolver;
use ferrous_dns_application::use_cases::dns::DnsRateLimiter;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    ClientProtocol, DnsRequest, DomainError, RateLimitConfig, RecordType, UpstreamPool,
    UpstreamStrategy,
};
use ferrous_dns_infrastructure::dns::load_balancer::PoolManager;
use ferrous_dns_infrastructure::dns::resolver::{NonFqdn, QueryFilters, ResolverBuilder};
use ferrous_dns_infrastructure::dns::{DnsCache, DnsCacheConfig, EvictionStrategy};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType as WireType};
use ports::{AllowAllFilter, NoopQueryLog};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;

const NAS_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
/// What the stub answers, as an upstream, for any other A query.
const PUBLIC_NAME_PRIVATE_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 66);
const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));

/// A LAN router: `nas.lan A 192.168.1.10`, NXDOMAIN for every PTR. It also
/// stands in for the upstream pool, answering any other A with a private IP.
async fn spawn_router() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let Ok(req) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let Some(q) = req.queries.first().cloned() else {
                continue;
            };

            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = true;
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = ResponseCode::NoError;
            resp.add_query(q.clone());

            match q.query_type() {
                WireType::A => {
                    let ip = if q.name().to_ascii().eq_ignore_ascii_case("nas.lan.") {
                        NAS_IP
                    } else {
                        PUBLIC_NAME_PRIVATE_IP
                    };
                    resp.add_answer(Record::from_rdata(q.name().clone(), 300, RData::A(A(ip))));
                }
                WireType::PTR => resp.metadata.response_code = ResponseCode::NXDomain,
                _ => {}
            }

            let _ = socket.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });

    addr
}

/// The server's resolver stack for `local_domain = "lan"`, `block_non_fqdn =
/// false` and `local_dns_server` pointing at `router`.
async fn resolver(router: SocketAddr) -> Arc<dyn DnsResolver> {
    let pool = UpstreamPool {
        name: "stub".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec![format!("udp://{router}")],
        weight: None,
        ..Default::default()
    };
    let manager = Arc::new(PoolManager::new(vec![pool], None).await.unwrap());
    let cache = Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries: 1000,
        eviction_strategy: EvictionStrategy::HitRate,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.1,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
    }));
    ResolverBuilder::new(manager, 2000)
        .with_cache(cache, 300, 4)
        .with_local_domain(Some("lan".to_string()))
        .with_local_dns_server(Some(router))
        .with_filters(QueryFilters::new(
            false,
            NonFqdn::Qualify("lan".to_string()),
        ))
        .build()
}

async fn use_case(router: SocketAddr) -> HandleDnsQueryUseCase {
    HandleDnsQueryUseCase::new(
        resolver(router).await,
        Arc::new(AllowAllFilter),
        Arc::new(NoopQueryLog),
    )
    .with_rebinding_protection(Some("lan"), &[])
}

/// The addresses a client gets for an A query: from the UDP cache fast path
/// when it answers, otherwise from the full path, as the server does.
async fn answer_a(
    use_case: &HandleDnsQueryUseCase,
    client: IpAddr,
    name: &str,
) -> Result<Vec<IpAddr>, DomainError> {
    if let Some(addresses) =
        use_case.try_cache_direct(name, RecordType::A, client, ClientProtocol::Udp, |a, _| {
            Some(a.to_vec())
        })
    {
        return Ok(addresses);
    }
    let request = DnsRequest::new(name, RecordType::A, client);
    use_case
        .execute(&request)
        .await
        .map(|resolution| resolution.addresses.to_vec())
}

#[tokio::test]
async fn cached_local_answer_for_a_short_name_is_not_rebinding() {
    let use_case = use_case(spawn_router().await).await;

    for attempt in 1..=3 {
        assert_eq!(
            answer_a(&use_case, CLIENT, "nas")
                .await
                .unwrap_or_else(|e| panic!(
                    "query #{attempt} for the short name must get the router's answer, got {e:?}"
                )),
            vec![IpAddr::V4(NAS_IP)]
        );
    }

    // The full path's own cache probe must agree with the fast path.
    let request = DnsRequest::new("nas", RecordType::A, CLIENT);
    let cached = use_case.execute(&request).await.expect("a cache hit");
    assert!(cached.cache_hit);
    assert_eq!(cached.addresses.as_ref(), &[IpAddr::V4(NAS_IP)]);
}

#[tokio::test]
async fn cached_private_answer_for_a_public_name_is_still_rebinding() {
    let use_case = use_case(spawn_router().await).await;

    for attempt in 1..=3 {
        let result = answer_a(&use_case, CLIENT, "rebind.example.com").await;
        assert!(
            matches!(result, Err(DomainError::Blocked)),
            "query #{attempt}: a public name resolving to a private IP must stay blocked, got {result:?}"
        );
    }
}

#[tokio::test]
async fn local_ptr_sweep_never_spends_the_subnets_nxdomain_budget() {
    let router = spawn_router().await;
    let limiter = DnsRateLimiter::new(&RateLimitConfig {
        enabled: true,
        queries_per_second: 1000,
        burst_size: 10_000,
        ipv4_prefix_len: 24,
        whitelist: vec![],
        nxdomain_per_second: 1,
        slip_ratio: 2,
        dry_run: false,
        ..RateLimitConfig::default()
    });
    let use_case = use_case(router).await.with_rate_limiter(Arc::new(limiter));
    let sweeper: IpAddr = "192.168.1.50".parse().unwrap();
    let neighbour: IpAddr = "192.168.1.60".parse().unwrap();

    // 100 NXDOMAINs against a budget of 2: fresh answers from the router,
    // then negative cache hits on the same names.
    for round in 0..2 {
        for host in 0..50 {
            let ptr = format!("{host}.1.168.192.in-addr.arpa");
            let result = use_case
                .execute(&DnsRequest::new(ptr.as_str(), RecordType::PTR, sweeper))
                .await;
            assert!(
                matches!(result, Err(DomainError::NxDomain)),
                "round {round}, {ptr}: the router's NXDOMAIN must reach the sweeper, got {result:?}"
            );
            assert_eq!(
                answer_a(&use_case, neighbour, "nas.lan")
                    .await
                    .unwrap_or_else(|e| panic!(
                        "round {round}, after {ptr}: the neighbour must keep resolving, got {e:?}"
                    )),
                vec![IpAddr::V4(NAS_IP)]
            );
        }
    }
}
