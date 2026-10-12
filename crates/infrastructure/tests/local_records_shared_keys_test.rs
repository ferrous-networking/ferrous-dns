//! Local records can share a key — an address, or a name and type. Deleting or
//! editing one of them must leave every live index answering for the others,
//! as a restart would.

use async_trait::async_trait;
use ferrous_dns_application::ports::{ConfigRepository, DnsResolution, DnsResolver};
use ferrous_dns_application::use_cases::{
    CreateLocalRecordUseCase, DeleteLocalRecordUseCase, UpdateLocalRecordUseCase,
};
use ferrous_dns_domain::{
    Config, DnsQuery, DomainError, LocalDnsRecord, LocalRecordType, RecordType,
};
use ferrous_dns_infrastructure::dns::resolver::{
    CachedResolver, LocalPtrResolver, LocalWildcardResolver, PtrRegistry, WildcardRegistry,
};
use ferrous_dns_infrastructure::dns::{DnsCache, DnsCacheConfig, EvictionStrategy};
use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

struct NullConfigRepository;

#[async_trait]
impl ConfigRepository for NullConfigRepository {
    async fn save_local_records(&self, _config: &Config) -> Result<(), DomainError> {
        Ok(())
    }
}

/// Answers nothing, so a query that leaves the local indexes fails.
struct Upstream;

#[async_trait]
impl DnsResolver for Upstream {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        Err(DomainError::NxDomain)
    }
}

/// The CRUD use cases wired to the real cache, PTR map and wildcard index,
/// behind the resolver layers that serve them.
struct Live {
    create: CreateLocalRecordUseCase,
    update: UpdateLocalRecordUseCase,
    delete: DeleteLocalRecordUseCase,
    resolver: LocalPtrResolver,
}

impl Live {
    async fn with_records(records: &[LocalDnsRecord]) -> Self {
        let cache = Arc::new(DnsCache::new(DnsCacheConfig {
            max_entries: 100,
            eviction_strategy: EvictionStrategy::HitRate,
            refresh_threshold: 0.0,
            batch_eviction_percentage: 0.2,
            min_frequency: 0,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs: 7200,
            eviction_sample_size: 8,
            lfuk_k_value: 0.5,
            min_ttl: 0,
            max_ttl: 86_400,
        }));
        let ptr_map = LocalPtrResolver::map_from_local_records(&[], None);
        let wildcard_map = LocalWildcardResolver::map_from_local_records(&[], None);
        let resolver = LocalPtrResolver::new(
            Arc::new(LocalWildcardResolver::new(
                Arc::new(CachedResolver::new(
                    Arc::new(Upstream),
                    cache.clone(),
                    300,
                    4,
                )),
                Arc::clone(&wildcard_map),
            )),
            Arc::clone(&ptr_map),
        );
        let ptr = Arc::new(PtrRegistry::new(ptr_map));
        let wildcard = Arc::new(WildcardRegistry::new(wildcard_map));

        let config = Arc::new(RwLock::new(Config::default()));
        let repo = Arc::new(NullConfigRepository);
        let live = Self {
            create: CreateLocalRecordUseCase::new(config.clone(), repo.clone())
                .with_ptr_registry(ptr.clone())
                .with_wildcard_registry(wildcard.clone())
                .with_dns_cache(cache.clone()),
            update: UpdateLocalRecordUseCase::new(config.clone(), repo.clone())
                .with_ptr_registry(ptr.clone())
                .with_wildcard_registry(wildcard.clone())
                .with_dns_cache(cache.clone()),
            delete: DeleteLocalRecordUseCase::new(config, repo)
                .with_ptr_registry(ptr)
                .with_wildcard_registry(wildcard)
                .with_dns_cache(cache),
            resolver,
        };
        for record in records {
            live.create.execute(record.clone()).await.unwrap();
        }
        live
    }

    async fn address(&self, name: &str) -> Option<IpAddr> {
        let resolution = self
            .resolver
            .resolve(&DnsQuery::new(name, RecordType::A))
            .await
            .ok()?;
        resolution.addresses.first().copied()
    }

    async fn ptr(&self, reverse_name: &str) -> Option<String> {
        let resolution = self
            .resolver
            .resolve(&DnsQuery::new(reverse_name, RecordType::PTR))
            .await
            .ok()?;
        let message = Message::from_vec(&resolution.upstream_wire_data?).unwrap();
        match &message.answers.first()?.data {
            RData::PTR(ptr) => Some(ptr.0.to_string().trim_end_matches('.').to_string()),
            _ => None,
        }
    }
}

fn record(hostname: &str, domain: &str, ip: &str) -> LocalDnsRecord {
    LocalDnsRecord {
        hostname: hostname.to_string(),
        domain: Some(domain.to_string()),
        ip: ip.parse().unwrap(),
        record_type: LocalRecordType::A,
        ttl: Some(300),
    }
}

fn ip(value: &str) -> Option<IpAddr> {
    Some(value.parse().unwrap())
}

#[tokio::test]
async fn test_deleting_one_of_two_records_sharing_an_address_keeps_its_ptr() {
    let live = Live::with_records(&[
        record("nas", "lan", "10.0.0.5"),
        record("files", "lan", "10.0.0.5"),
    ])
    .await;

    live.delete.execute(1).await.unwrap();

    assert_eq!(
        live.ptr("5.0.0.10.in-addr.arpa").await.as_deref(),
        Some("nas.lan")
    );
}

#[tokio::test]
async fn test_moving_one_of_two_records_sharing_an_address_keeps_its_ptr() {
    let live = Live::with_records(&[
        record("nas", "lan", "10.0.0.5"),
        record("files", "lan", "10.0.0.5"),
    ])
    .await;

    live.update
        .execute(1, record("files", "lan", "10.0.0.6"))
        .await
        .unwrap();

    assert_eq!(
        live.ptr("5.0.0.10.in-addr.arpa").await.as_deref(),
        Some("nas.lan")
    );
    assert_eq!(
        live.ptr("6.0.0.10.in-addr.arpa").await.as_deref(),
        Some("files.lan")
    );
}

#[tokio::test]
async fn test_deleting_one_of_two_records_for_a_name_keeps_the_name_local() {
    let live = Live::with_records(&[
        record("nas", "lan", "10.0.0.5"),
        record("NAS", "lan", "10.0.0.6"),
    ])
    .await;

    live.delete.execute(1).await.unwrap();

    assert_eq!(live.address("nas.lan").await, ip("10.0.0.5"));
}

#[tokio::test]
async fn test_deleting_the_last_record_for_a_name_stops_answering_it() {
    let live = Live::with_records(&[record("nas", "lan", "10.0.0.5")]).await;

    live.delete.execute(0).await.unwrap();

    assert_eq!(live.address("nas.lan").await, None);
    assert_eq!(live.ptr("5.0.0.10.in-addr.arpa").await, None);
}

#[tokio::test]
async fn test_deleting_one_of_two_wildcards_for_a_suffix_keeps_the_wildcard() {
    let live = Live::with_records(&[
        record("*", "home.lan", "192.168.1.10"),
        record("*", "home.lan", "192.168.1.11"),
    ])
    .await;

    live.delete.execute(1).await.unwrap();

    assert_eq!(live.address("printer.home.lan").await, ip("192.168.1.10"));
}
