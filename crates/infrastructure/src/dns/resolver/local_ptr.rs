use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use ferrous_dns_application::ports::{
    DnsResolution, DnsResolver, PtrRecordRegistry, EMPTY_CNAME_CHAIN,
};
use ferrous_dns_domain::{DnsQuery, DomainError, LocalDnsRecord, PrivateIpFilter, RecordType};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::PTR;
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Concurrent map of IP address → (FQDN, TTL) used for PTR auto-generation.
pub type PtrMap = DashMap<IpAddr, (Arc<str>, u32), FxBuildHasher>;

/// DNS resolver layer that intercepts PTR queries and answers from local record mappings.
///
/// Non-PTR queries pass through to the inner resolver immediately with a single
/// `RecordType` comparison — zero overhead on the A/AAAA hot path.
pub struct LocalPtrResolver {
    inner: Arc<dyn DnsResolver>,
    /// Live mapping of IP address → (FQDN, TTL).
    map: Arc<PtrMap>,
}

impl LocalPtrResolver {
    /// Creates a resolver wrapping `inner` with an existing live PTR map.
    pub fn new(inner: Arc<dyn DnsResolver>, map: Arc<PtrMap>) -> Self {
        Self { inner, map }
    }

    /// Builds a PTR map from the exact records among the configured local
    /// records. When several share an address, the last one wins.
    pub fn map_from_local_records(
        records: &[LocalDnsRecord],
        default_domain: Option<&str>,
    ) -> Arc<PtrMap> {
        let map: PtrMap = DashMap::with_hasher(FxBuildHasher);

        // A wildcard covers a whole subtree, so there is no single name an
        // address could reverse to. Skip it rather than inventing one.
        for record in records.iter().filter(|r| !r.is_wildcard()) {
            let fqdn = record.fqdn(default_domain);
            map.insert(record.ip, (Arc::from(fqdn), record.ttl_or_default()));
        }

        info!(
            count = map.len(),
            "PTR auto-generation: preloaded local records at startup"
        );

        Arc::new(map)
    }
}

/// Mutating handle on the live PTR map, held by the CRUD use cases.
///
/// Separate from the resolver for the same reason as `WildcardRegistry`: the
/// use cases only add and remove entries and have no inner resolver to give.
pub struct PtrRegistry {
    map: Arc<PtrMap>,
}

impl PtrRegistry {
    pub fn new(map: Arc<PtrMap>) -> Self {
        Self { map }
    }
}

impl PtrRecordRegistry for PtrRegistry {
    fn register(&self, ip: IpAddr, fqdn: Arc<str>, ttl: u32) {
        self.map.insert(ip, (fqdn, ttl));
    }

    fn unregister(&self, ip: IpAddr) {
        self.map.remove(&ip);
    }
}

#[async_trait]
impl DnsResolver for LocalPtrResolver {
    fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        if query.record_type != RecordType::PTR {
            return self.inner.try_cache(query);
        }
        None
    }

    fn try_cache_str(
        &self,
        domain: &str,
        record_type: RecordType,
        group_id: Option<i64>,
    ) -> Option<DnsResolution> {
        if record_type != RecordType::PTR {
            return self.inner.try_cache_str(domain, record_type, group_id);
        }
        None
    }

    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        if query.record_type != RecordType::PTR {
            return self.inner.resolve(query).await;
        }

        let ip = match PrivateIpFilter::extract_ip_from_ptr(&query.domain) {
            Some(ip) => ip,
            None => return self.inner.resolve(query).await,
        };

        // Built inside the closure so the shard guard is gone before any await:
        // a register/unregister on that shard would otherwise block its thread.
        let local = self.map.get(&ip).and_then(|entry| {
            let (fqdn, ttl) = entry.value();
            debug!(
                domain = %query.domain,
                ip = %ip,
                ptr = %fqdn,
                "LocalPtrResolver: PTR answered from local records"
            );
            parse_ptr_target(fqdn)
                .and_then(|target| ptr_resolution(&query.domain, &[target], *ttl, true))
        });

        match local {
            Some(resolution) => Ok(resolution),
            None => self.inner.resolve(query).await,
        }
    }
}

fn parse_ptr_target(hostname: &str) -> Option<Name> {
    Name::from_str(hostname)
        .map_err(|e| {
            warn!(hostname = %hostname, error = %e, "PTR: failed to parse PTR hostname");
        })
        .ok()
}

/// An authoritative NOERROR answering the PTR query `owner` with `targets`,
/// echoing its question (RFC 1035 §4.1.2): stubs drop answers without one.
pub(super) fn ptr_resolution(
    owner: &str,
    targets: &[Name],
    ttl: u32,
    local_dns: bool,
) -> Option<DnsResolution> {
    let owner_name = Name::from_str(owner)
        .map_err(|e| {
            warn!(domain = %owner, error = %e, "PTR: failed to parse query name");
        })
        .ok()?;

    let mut message = Message::new(0, MessageType::Response, OpCode::Query);
    message.metadata.response_code = ResponseCode::NoError;
    message.metadata.authoritative = true;
    message.add_query(Query::query(
        owner_name.clone(),
        hickory_proto::rr::RecordType::PTR,
    ));
    for target in targets {
        message.add_answer(Record::from_rdata(
            owner_name.clone(),
            ttl,
            RData::PTR(PTR(target.clone())),
        ));
    }

    let mut buf = Vec::with_capacity(128);
    let mut encoder = BinEncoder::new(&mut buf);
    message
        .emit(&mut encoder)
        .map_err(|e| {
            warn!(domain = %owner, error = %e, "PTR: failed to serialize response");
        })
        .ok()?;

    Some(DnsResolution {
        addresses: Arc::new(Vec::new()),
        cache_hit: false,
        local_dns,
        local_nxdomain: false,
        upstream_nxdomain: false,
        coalesced: None,
        dnssec_status: None,
        cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
        upstream_server: None,
        upstream_pool: None,
        min_ttl: Some(ttl),
        negative_soa_ttl: None,
        upstream_wire_data: Some(Bytes::from(buf)),
    })
}
