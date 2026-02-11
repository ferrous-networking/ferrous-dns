/// Configuration for DNS resolver
#[derive(Clone)]
pub struct ResolverConfig {
    /// Cache TTL in seconds (default: 3600)
    pub cache_ttl: u32,

    /// Query timeout in milliseconds
    pub query_timeout_ms: u64,

    /// Enable DNSSEC validation
    pub dnssec_enabled: bool,

    /// Server hostname (for logging)
    pub server_hostname: String,

    /// Query filters configuration
    pub filters: QueryFiltersConfig,

    /// Enable prefetching
    pub prefetch_enabled: bool,
}

/// Query filters configuration
#[derive(Clone)]
pub struct QueryFiltersConfig {
    /// Block reverse lookups (PTR) for private IP ranges
    pub block_private_ptr: bool,

    /// Block non-FQDN queries (queries without a domain)
    pub block_non_fqdn: bool,

    /// Local domain to append to non-FQDN queries
    pub local_domain: Option<String>,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        let server_hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "localhost".to_string());

        Self {
            cache_ttl: 3600,
            query_timeout_ms: 2000,
            dnssec_enabled: false,
            server_hostname,
            filters: QueryFiltersConfig::default(),
            prefetch_enabled: false,
        }
    }
}

impl Default for QueryFiltersConfig {
    fn default() -> Self {
        Self {
            block_private_ptr: true,
            block_non_fqdn: false,
            local_domain: None,
        }
    }
}

impl ResolverConfig {
    /// Create new configuration with custom timeout
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.query_timeout_ms = timeout_ms;
        self
    }

    /// Enable DNSSEC validation
    pub fn with_dnssec(mut self) -> Self {
        self.dnssec_enabled = true;
        self
    }

    /// Set cache TTL
    pub fn with_cache_ttl(mut self, ttl: u32) -> Self {
        self.cache_ttl = ttl;
        self
    }

    /// Configure query filters
    pub fn with_filters(mut self, filters: QueryFiltersConfig) -> Self {
        self.filters = filters;
        self
    }

    /// Enable prefetching
    pub fn with_prefetch(mut self) -> Self {
        self.prefetch_enabled = true;
        self
    }
}
