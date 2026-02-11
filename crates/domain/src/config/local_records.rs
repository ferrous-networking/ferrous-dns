use serde::{Deserialize, Serialize};

/// Local DNS record for static hostname resolution
///
/// Provides static IP address mapping for local hostnames without requiring
/// a full DNS zone file. Records are cached permanently in memory for instant
/// resolution (<0.1ms) without database queries.
///
/// Use cases:
/// - Home network devices (NAS, printers, IoT)
/// - Development environments (local services, databases)
/// - Static server infrastructure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalDnsRecord {
    /// Hostname (e.g., "nas", "server", "printer")
    /// Will be combined with domain to form FQDN
    pub hostname: String,

    /// Optional domain override (e.g., "home.lan", "lab.local")
    /// If None, uses DnsConfig.local_domain
    /// If both None, uses hostname as-is
    #[serde(default)]
    pub domain: Option<String>,

    /// IP address (IPv4 or IPv6)
    /// Examples: "192.168.1.100", "10.0.0.50", "2001:db8::1"
    pub ip: String,

    /// Record type: "A" for IPv4, "AAAA" for IPv6
    pub record_type: String,

    /// Time-to-live in seconds (optional, default 300)
    /// Used for cache metadata, but local records never expire from cache
    #[serde(default)]
    pub ttl: Option<u32>,
}

impl LocalDnsRecord {
    /// Build fully qualified domain name from hostname and domain
    ///
    /// # Examples
    /// ```
    /// use ferrous_dns_domain::config::LocalDnsRecord;
    ///
    /// // With custom domain
    /// let record = LocalDnsRecord {
    ///     hostname: "nas".into(),
    ///     domain: Some("lab.local".into()),
    ///     ip: "192.168.1.100".into(),
    ///     record_type: "A".into(),
    ///     ttl: None,
    /// };
    /// assert_eq!(record.fqdn(&None), "nas.lab.local");
    ///
    /// // With default domain
    /// let record = LocalDnsRecord {
    ///     hostname: "server".into(),
    ///     domain: None,
    ///     ip: "192.168.1.101".into(),
    ///     record_type: "A".into(),
    ///     ttl: None,
    /// };
    /// assert_eq!(record.fqdn(&Some("home.lan".into())), "server.home.lan");
    ///
    /// // No domain
    /// let record = LocalDnsRecord {
    ///     hostname: "localhost".into(),
    ///     domain: None,
    ///     ip: "127.0.0.1".into(),
    ///     record_type: "A".into(),
    ///     ttl: None,
    /// };
    /// assert_eq!(record.fqdn(&None), "localhost");
    /// ```
    pub fn fqdn(&self, default_domain: &Option<String>) -> String {
        if let Some(ref domain) = self.domain {
            // Record has explicit domain
            format!("{}.{}", self.hostname, domain)
        } else if let Some(ref default) = default_domain {
            // Use default domain from config
            format!("{}.{}", self.hostname, default)
        } else {
            // No domain - use hostname as-is
            self.hostname.clone()
        }
    }

    /// Get TTL with default fallback
    pub fn ttl_or_default(&self) -> u32 {
        self.ttl.unwrap_or(300)
    }
}
