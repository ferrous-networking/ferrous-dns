use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

/// DNSSEC validation status (memory-optimized: 1 byte!)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnssecStatus {
    Unknown = 0,
    Secure = 1,
    Insecure = 2,
    Bogus = 3,
    Indeterminate = 4,
}

impl FromStr for DnssecStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "Secure" => Self::Secure,
            "Insecure" => Self::Insecure,
            "Bogus" => Self::Bogus,
            "Indeterminate" => Self::Indeterminate,
            _ => Self::Unknown,
        })
    }
}

impl DnssecStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Secure => "Secure",
            Self::Insecure => "Insecure",
            Self::Bogus => "Bogus",
            Self::Indeterminate => "Indeterminate",
        }
    }

    pub fn from_string(s: &str) -> Option<Self> {
        s.parse().ok()
    }

    pub fn from_option_string(opt: Option<String>) -> Self {
        opt.and_then(|s| s.parse().ok()).unwrap_or(Self::Unknown)
    }
}

/// Cached DNS data - supports different record types (ZERO-COPY with Arc!)
#[derive(Clone, Debug)]
pub enum CachedData {
    /// IP addresses (A, AAAA records) - Arc = zero-copy clone!
    IpAddresses(Arc<Vec<IpAddr>>),

    /// Canonical name (CNAME record) - Arc = zero-copy clone!
    CanonicalName(Arc<String>),

    /// Negative response (NXDOMAIN) - Cache non-existent domains!
    NegativeResponse,
}

impl CachedData {
    /// Check if data is empty
    pub fn is_empty(&self) -> bool {
        match self {
            CachedData::IpAddresses(addrs) => addrs.is_empty(),
            CachedData::CanonicalName(name) => name.is_empty(),
            CachedData::NegativeResponse => false, // Negative cache is valid data
        }
    }

    /// Check if this is a negative response
    pub fn is_negative(&self) -> bool {
        matches!(self, CachedData::NegativeResponse)
    }

    /// Get IP addresses if this is an IP record
    pub fn as_ip_addresses(&self) -> Option<&Arc<Vec<IpAddr>>> {
        match self {
            CachedData::IpAddresses(addrs) => Some(addrs),
            _ => None,
        }
    }

    /// Get canonical name if this is a CNAME record
    pub fn as_canonical_name(&self) -> Option<&Arc<String>> {
        match self {
            CachedData::CanonicalName(name) => Some(name),
            _ => None,
        }
    }
}
