use crate::dns_record::RecordType;
use std::net::IpAddr;
use std::sync::Arc;

/// RFC 7873 cookie option data (EDNS option code 10).
///
/// Contains the client cookie (8 bytes) optionally followed by a server
/// cookie (8–32 bytes). Maximum total size per RFC 7873 is 40 bytes.
/// Stored inline on the stack — zero heap allocation.
#[derive(Debug, Clone, Copy)]
pub struct EdnsCookie {
    buf: [u8; 40],
    len: u8,
}

impl EdnsCookie {
    /// Creates an `EdnsCookie` from a byte slice.
    ///
    /// Silently truncates input longer than 40 bytes; RFC 7873 §4 defines
    /// that as the maximum. Callers should validate the length before
    /// interpreting the contents.
    pub fn from_bytes(data: &[u8]) -> Self {
        let copy_len = data.len().min(40);
        let mut buf = [0u8; 40];
        buf[..copy_len].copy_from_slice(&data[..copy_len]);
        Self {
            buf,
            len: copy_len as u8,
        }
    }

    /// Returns the raw cookie bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    /// Returns the number of bytes stored.
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` when no bytes are stored.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Debug, Clone)]
pub struct DnsRequest {
    pub domain: Arc<str>,
    pub record_type: RecordType,
    pub client_ip: IpAddr,
    /// Raw bytes from the EDNS OPT option code 10 (DNS Cookie, RFC 7873).
    /// Contains the client cookie (8 bytes) optionally followed by a server
    /// cookie (8–32 bytes). Absent when the client sends no OPT record or
    /// does not include option code 10.
    /// Stored inline — zero heap allocation.
    pub edns_cookie: Option<EdnsCookie>,
}

impl DnsRequest {
    pub fn new(domain: impl Into<Arc<str>>, record_type: RecordType, client_ip: IpAddr) -> Self {
        Self {
            domain: domain.into(),
            record_type,
            client_ip,
            edns_cookie: None,
        }
    }

    /// Attaches raw EDNS cookie option data (option code 10) to this request.
    pub fn with_cookie(mut self, data: Vec<u8>) -> Self {
        self.edns_cookie = Some(EdnsCookie::from_bytes(&data));
        self
    }
}
