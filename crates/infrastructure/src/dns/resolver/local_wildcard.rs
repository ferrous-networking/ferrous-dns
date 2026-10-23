use async_trait::async_trait;
use dashmap::DashMap;
use ferrous_dns_application::ports::{
    DnsResolution, DnsResolver, WildcardRecordRegistry, EMPTY_CNAME_CHAIN,
};
use ferrous_dns_domain::{DnsQuery, DomainError, LocalDnsRecord, LocalRecordType, RecordType};
use rustc_hash::FxBuildHasher;
use std::borrow::Cow;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Concurrent index of wildcard suffix → answers. The key is the covered
/// suffix, lowercased and without the leading `*.`: `*.home.lan` is stored
/// under `home.lan`.
pub type WildcardMap = DashMap<Box<str>, WildcardAnswer, FxBuildHasher>;

/// What a wildcard answers with, one address per record type. A second record
/// for the same suffix and type overwrites the first, the same way an exact
/// record overwrites its permanent cache entry.
#[derive(Debug, Default, Clone, Copy)]
pub struct WildcardAnswer {
    a: Option<(IpAddr, u32)>,
    aaaa: Option<(IpAddr, u32)>,
}

impl WildcardAnswer {
    fn get(&self, record_type: RecordType) -> Option<(IpAddr, u32)> {
        match record_type {
            RecordType::A => self.a,
            RecordType::AAAA => self.aaaa,
            _ => None,
        }
    }

    fn set(&mut self, record_type: LocalRecordType, address: IpAddr, ttl: u32) {
        match record_type {
            LocalRecordType::A => self.a = Some((address, ttl)),
            LocalRecordType::AAAA => self.aaaa = Some((address, ttl)),
        }
    }

    fn clear(&mut self, record_type: LocalRecordType) {
        match record_type {
            LocalRecordType::A => self.a = None,
            LocalRecordType::AAAA => self.aaaa = None,
        }
    }

    fn is_empty(&self) -> bool {
        self.a.is_none() && self.aaaa.is_none()
    }
}

/// DNS resolver layer that answers queries covered by a wildcard local record.
///
/// It sits above the cache, so its answers are never stored under a concrete
/// name — a cache key is matched exactly and an expansion of `*.home.lan` could
/// not be found again for invalidation when the wildcard is deleted. The price
/// is one index probe per parent label of each query name.
pub struct LocalWildcardResolver {
    inner: Arc<dyn DnsResolver>,
    /// Live index of covered suffix → answers.
    map: Arc<WildcardMap>,
}

impl LocalWildcardResolver {
    /// Creates a resolver wrapping `inner` with an existing live index.
    pub fn new(inner: Arc<dyn DnsResolver>, map: Arc<WildcardMap>) -> Self {
        Self { inner, map }
    }

    /// Builds an index from the wildcard entries among the configured local
    /// records. Exact records are left to the permanent cache.
    pub fn map_from_local_records(
        records: &[LocalDnsRecord],
        default_domain: Option<&str>,
    ) -> Arc<WildcardMap> {
        let map: WildcardMap = DashMap::with_hasher(FxBuildHasher);

        for record in records.iter().filter(|r| r.is_wildcard()) {
            let Some(suffix) = record.wildcard_suffix(default_domain) else {
                warn!(
                    hostname = %record.hostname,
                    "Wildcard record has no domain to anchor it, skipping"
                );
                continue;
            };

            register_in(
                &map,
                &suffix,
                record.record_type,
                record.ip,
                record.ttl_or_default(),
            );
        }

        if !map.is_empty() {
            info!(count = map.len(), "Wildcard local DNS records loaded");
        }

        Arc::new(map)
    }

    /// Longest covering wildcard for `domain`, or `None` when no wildcard
    /// covers it. The walk starts at the query name's parent, so a name never
    /// matches a wildcard anchored on itself — `*.example.com` does not answer
    /// for `example.com` (RFC 4592 §2.1.1).
    fn lookup(&self, domain: &str) -> Option<WildcardAnswer> {
        let lowered = normalize(domain);
        let mut candidate = lowered.as_ref();

        while let Some((_, parent)) = candidate.split_once('.') {
            if let Some(entry) = self.map.get(parent) {
                return Some(*entry.value());
            }
            candidate = parent;
        }

        None
    }
}

/// Mutating handle on the live wildcard index, held by the CRUD use cases.
///
/// Separate from the resolver on purpose: the use cases only ever add and
/// remove entries, and building a resolver — which needs an inner resolver to
/// delegate to — just to reach its map would be wiring for nothing.
pub struct WildcardRegistry {
    map: Arc<WildcardMap>,
}

impl WildcardRegistry {
    pub fn new(map: Arc<WildcardMap>) -> Self {
        Self { map }
    }
}

impl WildcardRecordRegistry for WildcardRegistry {
    fn register(&self, suffix: &str, record_type: LocalRecordType, address: IpAddr, ttl: u32) {
        register_in(&self.map, suffix, record_type, address, ttl);
    }

    fn unregister(&self, suffix: &str, record_type: LocalRecordType) {
        let key = suffix.to_ascii_lowercase();

        let emptied = match self.map.get_mut(key.as_str()) {
            Some(mut entry) => {
                entry.clear(record_type);
                entry.is_empty()
            }
            None => return,
        };

        if emptied {
            self.map.remove(key.as_str());
        }
    }
}

#[async_trait]
impl DnsResolver for LocalWildcardResolver {
    fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        self.inner.try_cache(query)
    }

    fn try_cache_str(
        &self,
        domain: &str,
        record_type: RecordType,
        group_id: Option<i64>,
    ) -> Option<DnsResolution> {
        self.inner.try_cache_str(domain, record_type, group_id)
    }

    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        // No `map.is_empty()` shortcut: DashMap computes it by locking every
        // shard, which costs more than the per-label probes it would skip.
        let Some(answer) = self.lookup(&query.domain) else {
            return self.inner.resolve(query).await;
        };

        // An exact local record — or anything already cached for this precise
        // name — is the closer match and wins over the wildcard.
        if let Some(cached) = self.inner.try_cache(query) {
            if cached.has_response_data() {
                return Ok(cached);
            }
        }

        match answer.get(query.record_type) {
            Some((address, ttl)) => {
                debug!(
                    domain = %query.domain,
                    %address,
                    "LocalWildcardResolver: answered from a wildcard record"
                );
                Ok(local_answer(vec![address], Some(ttl)))
            }
            // The name is inside a covered subtree but the wildcard carries no
            // record of this type. That is NODATA — an empty NOERROR built by
            // the server from the client's own question — not a reason to ask
            // upstream and leak an internal name (RFC 4592 §2.2.1).
            None => {
                debug!(
                    domain = %query.domain,
                    record_type = %query.record_type,
                    "LocalWildcardResolver: NODATA from a wildcard record"
                );
                Ok(local_answer(Vec::new(), None))
            }
        }
    }
}

fn register_in(
    map: &WildcardMap,
    suffix: &str,
    record_type: LocalRecordType,
    address: IpAddr,
    ttl: u32,
) {
    if let Err(reason) = LocalDnsRecord::validate_address(record_type, address) {
        warn!(suffix, %reason, "Wildcard record skipped");
        return;
    }

    map.entry(Box::from(suffix.to_ascii_lowercase().as_str()))
        .or_default()
        .set(record_type, address, ttl);
}

fn local_answer(addresses: Vec<IpAddr>, ttl: Option<u32>) -> DnsResolution {
    DnsResolution {
        addresses: Arc::new(addresses),
        cache_hit: false,
        // Marks the answer as locally authoritative: it keeps the rebinding
        // guard from treating our own LAN address as an attack, and the query
        // log from reporting the answer as an upstream one.
        local_dns: true,
        local_nxdomain: false,
        upstream_nxdomain: false,
        coalesced: None,
        dnssec_status: None,
        cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
        upstream_server: None,
        upstream_pool: None,
        min_ttl: ttl,
        negative_soa_ttl: None,
        upstream_wire_data: None,
    }
}

fn normalize(domain: &str) -> Cow<'_, str> {
    if domain.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(domain.to_ascii_lowercase())
    } else {
        Cow::Borrowed(domain)
    }
}
