#[derive(Clone)]
pub struct ResolverConfig {
    pub cache_ttl: u32,

    pub query_timeout_ms: u64,

    pub dnssec_enabled: bool,

    pub server_hostname: String,

    pub filters: QueryFiltersConfig,

    pub prefetch_enabled: bool,
}

#[derive(Clone)]
pub struct QueryFiltersConfig {
    pub block_private_ptr: bool,

    pub block_non_fqdn: bool,

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
    pub fn with_timeout(mut self, timeout_ms: u64) -> Self {
        self.query_timeout_ms = timeout_ms;
        self
    }

    pub fn with_dnssec(mut self) -> Self {
        self.dnssec_enabled = true;
        self
    }

    pub fn with_cache_ttl(mut self, ttl: u32) -> Self {
        self.cache_ttl = ttl;
        self
    }

    pub fn with_filters(mut self, filters: QueryFiltersConfig) -> Self {
        self.filters = filters;
        self
    }

    pub fn with_prefetch(mut self) -> Self {
        self.prefetch_enabled = true;
        self
    }
}
