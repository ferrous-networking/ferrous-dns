use async_trait::async_trait;
use bytes::Bytes;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, EMPTY_CNAME_CHAIN};
use ferrous_dns_domain::{
    DnsQuery, DnssecStatus, DomainError, Nat64Prefix, PrivateIpFilter, RecordType,
};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::PTR;
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, info};

/// DNS64 resolver layer (RFC 6147) — synthesizes AAAA answers for IPv6-only
/// clients from A records, embedding each IPv4 into a `/96` NAT64 prefix.
///
/// Placed **below** the cache so synthesized answers are cached as ordinary
/// positive entries and served consistently by the cache fast-path. Blocking
/// happens before the resolver, so blocked domains never reach this layer.
///
/// Non-AAAA/PTR queries pass straight through with a single `RecordType`
/// comparison — zero overhead on the hot path.
pub struct Dns64Resolver {
    inner: Arc<dyn DnsResolver>,
    /// `/96` NAT64 network address (last 32 bits zero).
    prefix: Ipv6Addr,
}

impl Dns64Resolver {
    pub fn new(inner: Arc<dyn DnsResolver>, prefix: Ipv6Addr) -> Self {
        info!(prefix = %prefix, "DNS64 synthesis layer enabled");
        Self { inner, prefix }
    }

    /// Forward synthesis: turn an `AAAA` NODATA into synthetic AAAA records.
    async fn resolve_aaaa(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        let res = self.inner.resolve(query).await?;

        // Only an empty answer is a synthesis candidate.
        if !res.addresses.is_empty() {
            return Ok(res);
        }

        // NODATA vs NXDOMAIN: `DnsResolution` carries no rcode, so inspect the
        // upstream wire (mirrors `DnssecResolver`). Only NOERROR qualifies.
        let is_nodata = res
            .upstream_wire_data
            .as_ref()
            .and_then(|bytes| Message::from_vec(bytes).ok())
            .map(|msg| msg.response_code() == ResponseCode::NoError)
            .unwrap_or(false);
        if !is_nodata {
            return Ok(res);
        }

        // Re-query A for the same name (down the inner stack: dnssec -> core).
        let a_query = DnsQuery::new(Arc::clone(&query.domain), RecordType::A);
        let Ok(a_res) = self.inner.resolve(&a_query).await else {
            return Ok(res); // no A either — keep the original NODATA
        };

        // Never synthesize from a DNSSEC-Bogus A record.
        if a_res.dnssec_status == Some(DnssecStatus::Bogus.as_str()) {
            return Ok(res);
        }

        // Embed each non-private IPv4 into the NAT64 prefix.
        let synth: Vec<IpAddr> = a_res
            .addresses
            .iter()
            .filter_map(|addr| match addr {
                IpAddr::V4(v4) if !PrivateIpFilter::is_private_ip(addr) => {
                    Some(IpAddr::V6(Nat64Prefix::synthesize(self.prefix, *v4)))
                }
                _ => None,
            })
            .collect();

        if synth.is_empty() {
            return Ok(res); // all-private (or no IPv4) — keep the original NODATA
        }

        debug!(
            domain = %query.domain,
            count = synth.len(),
            "DNS64: synthesized AAAA from A records"
        );

        Ok(DnsResolution {
            addresses: Arc::new(synth),
            cache_hit: false,
            local_dns: false,
            // Synthetic AAAA is unsigned — the AD bit must never be set.
            dnssec_status: None,
            cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
            upstream_server: a_res.upstream_server.clone(),
            upstream_pool: a_res.upstream_pool.clone(),
            min_ttl: a_res.min_ttl,
            negative_soa_ttl: None,
            upstream_wire_data: None,
        })
    }

    /// Reverse synthesis (RFC 6147 §5.3.1.2): a PTR query for an address inside
    /// the NAT64 prefix is answered from the embedded IPv4's `in-addr.arpa` PTR.
    async fn resolve_ptr(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        let embedded_v4 = match PrivateIpFilter::extract_ip_from_ptr(&query.domain) {
            Some(IpAddr::V6(v6)) => Nat64Prefix::extract_v4(self.prefix, v6),
            _ => None,
        };
        let Some(v4) = embedded_v4 else {
            return self.inner.resolve(query).await;
        };

        // Look up the IPv4's reverse name through the inner stack.
        let v4_arpa = ipv4_to_arpa(v4);
        let v4_query = DnsQuery::new(Arc::from(v4_arpa.as_str()), RecordType::PTR);
        let Ok(v4_res) = self.inner.resolve(&v4_query).await else {
            return self.inner.resolve(query).await;
        };

        let targets = ptr_targets_from_wire(v4_res.upstream_wire_data.as_deref());
        if targets.is_empty() {
            // No PTR for the embedded IPv4 — leave the ip6.arpa answer untouched.
            return self.inner.resolve(query).await;
        }

        debug!(
            domain = %query.domain,
            v4 = %v4,
            targets = targets.len(),
            "DNS64: reverse PTR synthesized from in-addr.arpa"
        );

        match build_ptr_response(&query.domain, &targets, v4_res.min_ttl.unwrap_or(0)) {
            Some(resolution) => Ok(resolution),
            None => self.inner.resolve(query).await,
        }
    }
}

#[async_trait]
impl DnsResolver for Dns64Resolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        match query.record_type {
            RecordType::AAAA => self.resolve_aaaa(query).await,
            RecordType::PTR => self.resolve_ptr(query).await,
            _ => self.inner.resolve(query).await,
        }
    }
}

/// `1.2.3.4` -> `4.3.2.1.in-addr.arpa`.
fn ipv4_to_arpa(v4: Ipv4Addr) -> String {
    let o = v4.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// Extracts the PTR target names from a parsed DNS response's answer section.
fn ptr_targets_from_wire(wire: Option<&[u8]>) -> Vec<Name> {
    let Some(bytes) = wire else {
        return Vec::new();
    };
    let Ok(msg) = Message::from_vec(bytes) else {
        return Vec::new();
    };
    msg.answers()
        .iter()
        .filter_map(|record| match record.data() {
            RData::PTR(ptr) => Some(ptr.0.clone()),
            _ => None,
        })
        .collect()
}

/// Builds a PTR response wire whose answer **owner is `owner_name`** (the
/// original `ip6.arpa` query name) carrying the resolved `targets`.
fn build_ptr_response(owner_name: &str, targets: &[Name], ttl: u32) -> Option<DnsResolution> {
    let owner = Name::from_str(owner_name).ok()?;

    let mut message = Message::new(0, MessageType::Response, OpCode::Query);
    message.set_response_code(ResponseCode::NoError);
    message.set_authoritative(true);
    for target in targets {
        message.add_answer(Record::from_rdata(
            owner.clone(),
            ttl,
            RData::PTR(PTR(target.clone())),
        ));
    }

    let mut buf = Vec::with_capacity(128);
    let mut encoder = BinEncoder::new(&mut buf);
    message.emit(&mut encoder).ok()?;

    Some(DnsResolution {
        addresses: Arc::new(Vec::new()),
        cache_hit: false,
        local_dns: false,
        dnssec_status: None,
        cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
        upstream_server: None,
        upstream_pool: None,
        min_ttl: Some(ttl),
        negative_soa_ttl: None,
        upstream_wire_data: Some(Bytes::from(buf)),
    })
}
