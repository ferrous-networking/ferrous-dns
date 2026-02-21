#![allow(dead_code)]
use ferrous_dns_domain::{BlockSource, DnsProtocol, DnsRecord, QueryLog, QuerySource, RecordType};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

pub struct QueryLogBuilder {
    domain: Arc<str>,
    record_type: RecordType,
    client_ip: IpAddr,
    blocked: bool,
    response_time_us: Option<u64>,
    cache_hit: bool,
    cache_refresh: bool,
    block_source: Option<BlockSource>,
    query_source: QuerySource,
}

impl QueryLogBuilder {
    pub fn new() -> Self {
        Self {
            domain: "example.com".into(),
            record_type: RecordType::A,
            client_ip: IpAddr::from_str("192.168.1.100").unwrap(),
            blocked: false,
            response_time_us: Some(10),
            cache_hit: false,
            cache_refresh: false,
            block_source: None,
            query_source: QuerySource::Client,
        }
    }

    pub fn domain(mut self, domain: &str) -> Self {
        self.domain = domain.into();
        self
    }

    pub fn record_type(mut self, record_type: RecordType) -> Self {
        self.record_type = record_type;
        self
    }

    pub fn blocked(mut self, blocked: bool) -> Self {
        self.blocked = blocked;
        self
    }

    pub fn cache_hit(mut self, cache_hit: bool) -> Self {
        self.cache_hit = cache_hit;
        self
    }

    pub fn response_time_us(mut self, us: u64) -> Self {
        self.response_time_us = Some(us);
        self
    }

    pub fn block_source(mut self, src: BlockSource) -> Self {
        self.block_source = Some(src);
        self
    }

    pub fn query_source(mut self, src: QuerySource) -> Self {
        self.query_source = src;
        self
    }

    pub fn build(self) -> QueryLog {
        QueryLog {
            id: None,
            domain: self.domain,
            record_type: self.record_type,
            client_ip: self.client_ip,
            blocked: self.blocked,
            response_time_us: self.response_time_us,
            cache_hit: self.cache_hit,
            cache_refresh: self.cache_refresh,
            dnssec_status: None,
            upstream_server: None,
            response_status: None,
            timestamp: None,
            query_source: self.query_source,
            group_id: None,
            block_source: self.block_source,
        }
    }
}

impl Default for QueryLogBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DnsRecordBuilder {
    domain: String,
    record_type: RecordType,
    address: IpAddr,
    ttl: u32,
}

impl DnsRecordBuilder {
    pub fn new() -> Self {
        Self {
            domain: "example.com".to_string(),
            record_type: RecordType::A,
            address: IpAddr::from_str("192.0.2.1").unwrap(),
            ttl: 300,
        }
    }

    pub fn domain(mut self, domain: &str) -> Self {
        self.domain = domain.to_string();
        self
    }

    pub fn record_type(mut self, record_type: RecordType) -> Self {
        self.record_type = record_type;
        self
    }

    pub fn address(mut self, address: &str) -> Self {
        self.address = IpAddr::from_str(address).expect("Invalid IP address");
        self
    }

    pub fn ttl(mut self, ttl: u32) -> Self {
        self.ttl = ttl;
        self
    }

    pub fn build(self) -> DnsRecord {
        DnsRecord::new(self.domain, self.record_type, self.address, self.ttl)
    }
}

impl Default for DnsRecordBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct DnsProtocolBuilder;

impl DnsProtocolBuilder {
    pub fn udp(addr: &str) -> DnsProtocol {
        let socket_addr = addr.parse::<SocketAddr>().expect("Invalid socket address");
        DnsProtocol::Udp { addr: socket_addr }
    }

    pub fn tls(addr: &str, hostname: &str) -> DnsProtocol {
        let socket_addr = addr.parse::<SocketAddr>().expect("Invalid socket address");
        DnsProtocol::Tls {
            addr: socket_addr,
            hostname: hostname.into(),
        }
    }

    pub fn google_dns() -> DnsProtocol {
        Self::udp("8.8.8.8:53")
    }

    pub fn cloudflare_tls() -> DnsProtocol {
        Self::tls("1.1.1.1:853", "one.one.one.one")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_log_builder() {
        let log = QueryLogBuilder::new()
            .domain("test.com")
            .record_type(RecordType::AAAA)
            .blocked(true)
            .build();

        assert_eq!(&*log.domain, "test.com");
        assert_eq!(log.record_type, RecordType::AAAA);
        assert!(log.blocked);
    }

    #[test]
    fn test_dns_record_builder() {
        let record = DnsRecordBuilder::new()
            .domain("test.com")
            .address("192.168.1.1")
            .ttl(600)
            .build();

        assert_eq!(record.domain, "test.com");
        assert_eq!(record.ttl, 600);
    }

    #[test]
    fn test_dns_protocol_builder() {
        let udp = DnsProtocolBuilder::google_dns();
        assert_eq!(udp.protocol_name(), "UDP");

        let tls = DnsProtocolBuilder::cloudflare_tls();
        assert_eq!(tls.protocol_name(), "TLS");
    }
}
