use crate::dns_record::RecordType;
use crate::ClientProtocol;
use std::net::IpAddr;
use std::sync::Arc;

/// RFC 7873 cookie option data (EDNS option code 10): an 8-byte client
/// cookie, optionally followed by an 8–32-byte server cookie. Stored inline,
/// so it costs no heap allocation.
#[derive(Debug, Clone, Copy)]
pub struct EdnsCookie {
    buf: [u8; 40],
    len: u8,
}

impl EdnsCookie {
    /// RFC 7873 §5.2.2: any other option length is a FORMERR.
    #[inline]
    pub const fn is_valid_len(len: usize) -> bool {
        matches!(len, 8 | 16..=40)
    }

    /// `None` when `data` has a length RFC 7873 does not allow.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if !Self::is_valid_len(data.len()) {
            return None;
        }
        let mut buf = [0u8; 40];
        buf[..data.len()].copy_from_slice(data);
        Some(Self {
            buf,
            len: data.len() as u8,
        })
    }

    // Tiny accessor read per query from other crates; keep it inlinable there.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

#[derive(Debug, Clone)]
pub struct DnsRequest {
    pub domain: Arc<str>,
    pub record_type: RecordType,
    pub client_ip: IpAddr,
    /// The query's EDNS COOKIE option (RFC 7873). Absent when the client sends
    /// no OPT record or no option code 10.
    pub edns_cookie: Option<EdnsCookie>,
    /// The client's CD (Checking Disabled) header bit (RFC 4035). When `true`,
    /// the client wants to perform its own DNSSEC validation, so the resolver
    /// must not enforce SERVFAIL on Bogus results for this query.
    pub checking_disabled: bool,
    /// Transport the query arrived on. `None` for requests built outside a
    /// client listener (internal resolution, tests).
    pub protocol: Option<ClientProtocol>,
    /// Client ID extracted from `/dns-query/<client_id>` for DoH requests.
    /// `None` for `/dns-query` without a path ID and for non-DoH transports.
    pub doh_client_id: Option<Arc<str>>,
}

impl DnsRequest {
    pub fn new(domain: impl Into<Arc<str>>, record_type: RecordType, client_ip: IpAddr) -> Self {
        Self {
            domain: domain.into(),
            record_type,
            client_ip,
            edns_cookie: None,
            checking_disabled: false,
            protocol: None,
            doh_client_id: None,
        }
    }

    pub fn with_cookie(mut self, cookie: EdnsCookie) -> Self {
        self.edns_cookie = Some(cookie);
        self
    }

    pub fn with_checking_disabled(mut self, cd: bool) -> Self {
        self.checking_disabled = cd;
        self
    }

    pub fn with_protocol(mut self, protocol: ClientProtocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    pub fn with_doh_client_id(mut self, client_id: impl Into<Arc<str>>) -> Self {
        self.doh_client_id = Some(client_id.into());
        self
    }
}
