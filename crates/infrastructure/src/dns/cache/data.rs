use crate::dns::wire_response;
use bytes::Bytes;
use ferrous_dns_application::ports::DnsResolution;
use ferrous_dns_domain::DnssecStatus;
use std::net::IpAddr;
use std::ops::RangeInclusive;
use std::sync::Arc;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachedDnssecStatus {
    Unknown = 0,
    Secure = 1,
    Insecure = 2,
    Bogus = 3,
    Indeterminate = 4,
}

impl From<DnssecStatus> for CachedDnssecStatus {
    fn from(status: DnssecStatus) -> Self {
        match status {
            DnssecStatus::Secure => Self::Secure,
            DnssecStatus::Insecure => Self::Insecure,
            DnssecStatus::Bogus => Self::Bogus,
            DnssecStatus::Indeterminate => Self::Indeterminate,
        }
    }
}

impl CachedDnssecStatus {
    /// `Unknown` is an entry cached without a DNSSEC determination.
    pub fn to_domain(self) -> Option<DnssecStatus> {
        match self {
            Self::Unknown => None,
            Self::Secure => Some(DnssecStatus::Secure),
            Self::Insecure => Some(DnssecStatus::Insecure),
            Self::Bogus => Some(DnssecStatus::Bogus),
            Self::Indeterminate => Some(DnssecStatus::Indeterminate),
        }
    }
}

/// An A/AAAA answer, with the CNAME chain the upstream answered it through:
/// every hit checks that chain again (CNAME cloaking). `None` when the answer
/// had no chain.
#[derive(Clone, Debug)]
pub struct CachedAddresses {
    pub addresses: Arc<Vec<IpAddr>>,
    pub cname_chain: Option<Arc<[Arc<str>]>>,
}

impl CachedAddresses {
    pub fn new(addresses: Arc<Vec<IpAddr>>) -> Self {
        Self {
            addresses,
            cname_chain: None,
        }
    }

    pub fn with_cname_chain(mut self, chain: &Arc<[Arc<str>]>) -> Self {
        self.cname_chain = non_empty(chain);
        self
    }
}

/// An upstream DNS response for a non-A/AAAA record type (HTTPS, MX, TXT,
/// etc.), in [`wire_response::cache_form`], with the CNAME chain it came
/// through. [`CachedData`] holds it behind an `Arc`, so a cache record does
/// not grow by the chain.
#[derive(Debug)]
pub struct CachedWire {
    pub bytes: Bytes,
    pub cname_chain: Option<Arc<[Arc<str>]>>,
}

impl CachedWire {
    pub fn new(bytes: Bytes) -> Self {
        Self {
            bytes,
            cname_chain: None,
        }
    }

    pub fn with_cname_chain(mut self, chain: &Arc<[Arc<str>]>) -> Self {
        self.cname_chain = non_empty(chain);
        self
    }
}

fn non_empty(chain: &Arc<[Arc<str>]>) -> Option<Arc<[Arc<str>]>> {
    (!chain.is_empty()).then(|| Arc::clone(chain))
}

#[derive(Clone, Debug)]
pub enum CachedData {
    IpAddresses(CachedAddresses),

    CanonicalName(Arc<str>),

    WireData(Arc<CachedWire>),

    NegativeResponse,
}

impl CachedData {
    /// A wire answer with no CNAME chain.
    pub fn wire(bytes: Bytes) -> Self {
        Self::WireData(Arc::new(CachedWire::new(bytes)))
    }

    /// What the cache stores for an upstream `resolution`: its addresses if it
    /// has any, else its wire message, either with the CNAME chain it came
    /// through. `None` when it has neither.
    pub(crate) fn from_resolution(resolution: &DnsResolution) -> Option<Self> {
        if !resolution.addresses.is_empty() {
            return Some(Self::IpAddresses(
                CachedAddresses::new(Arc::clone(&resolution.addresses))
                    .with_cname_chain(&resolution.cname_chain),
            ));
        }
        resolution.upstream_wire_data.as_ref().map(|bytes| {
            Self::WireData(Arc::new(
                CachedWire::new(bytes.clone()).with_cname_chain(&resolution.cname_chain),
            ))
        })
    }

    /// The form the cache stores for an entry of `ttl` seconds: a wire answer
    /// re-sectioned by [`wire_response::cache_form`], its record TTLs clamped
    /// into `ttls`, anything else as is. `None` for a wire answer that does
    /// not re-section.
    pub(super) fn into_stored(self, ttl: u32, ttls: RangeInclusive<u32>) -> Option<Self> {
        match self {
            Self::WireData(wire) => {
                wire_response::cache_form(&wire.bytes, ttl, ttls).map(|bytes| {
                    Self::WireData(Arc::new(CachedWire {
                        bytes: Bytes::from(bytes),
                        cname_chain: wire.cname_chain.clone(),
                    }))
                })
            }
            data @ (Self::IpAddresses(_) | Self::CanonicalName(_) | Self::NegativeResponse) => {
                Some(data)
            }
        }
    }

    pub fn is_negative(&self) -> bool {
        matches!(self, CachedData::NegativeResponse)
    }

    pub fn as_ip_addresses(&self) -> Option<&Arc<Vec<IpAddr>>> {
        match self {
            CachedData::IpAddresses(entry) => Some(&entry.addresses),
            CachedData::CanonicalName(_)
            | CachedData::WireData(_)
            | CachedData::NegativeResponse => None,
        }
    }

    pub(super) fn as_cached_addresses(&self) -> Option<&CachedAddresses> {
        match self {
            CachedData::IpAddresses(entry) => Some(entry),
            CachedData::CanonicalName(_)
            | CachedData::WireData(_)
            | CachedData::NegativeResponse => None,
        }
    }

    pub fn as_canonical_name(&self) -> Option<&Arc<str>> {
        match self {
            CachedData::CanonicalName(name) => Some(name),
            CachedData::IpAddresses(_) | CachedData::WireData(_) | CachedData::NegativeResponse => {
                None
            }
        }
    }
}
