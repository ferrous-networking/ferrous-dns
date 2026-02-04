use crate::dns::cache::{CachedData, DnsCache, DnssecStatus};
use ferrous_dns_domain::RecordType;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Cache warmer - preloads popular domains at startup
pub struct CacheWarmer {
    resolver: Resolver<TokioConnectionProvider>,
    popular_domains: Vec<String>,
}

impl CacheWarmer {
    /// Create a new cache warmer with popular domains
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::google(),
            TokioConnectionProvider::default(),
        ).build();
        
        // Top 100 popular domains (simplified list)
        let popular_domains = vec![
            // Search & Social
            "google.com", "youtube.com", "facebook.com", "twitter.com", "x.com",
            "instagram.com", "linkedin.com", "reddit.com", "tiktok.com", "pinterest.com",
            
            // Tech & Cloud
            "amazon.com", "apple.com", "microsoft.com", "github.com", "stackoverflow.com",
            "cloudflare.com", "openai.com", "anthropic.com", "nvidia.com", "vercel.com",
            
            // Streaming & Media
            "netflix.com", "spotify.com", "twitch.tv", "discord.com", "vimeo.com",
            "soundcloud.com", "zoom.us", "slack.com", "notion.so", "figma.com",
            
            // News & Info
            "wikipedia.org", "medium.com", "cnn.com", "bbc.com", "nytimes.com",
            "theguardian.com", "reuters.com", "bloomberg.com", "wsj.com", "forbes.com",
            
            // E-commerce
            "ebay.com", "walmart.com", "target.com", "bestbuy.com", "etsy.com",
            "shopify.com", "aliexpress.com", "mercadolivre.com.br", "alibaba.com",
            
            // Developer & Tools
            "docker.com", "kubernetes.io", "python.org", "rust-lang.org", "nodejs.org",
            "golang.org", "mozilla.org", "chromium.org", "ubuntu.com", "archlinux.org",
            
            // CDN & Infrastructure
            "jsdelivr.net", "unpkg.com", "cdnjs.com", "fonts.googleapis.com",
            "ajax.googleapis.com", "code.jquery.com", "maxcdn.com", "akamai.com",
            
            // Analytics & Ads
            "google-analytics.com", "doubleclick.net", "googlesyndication.com",
            "googleadservices.com", "facebook.net", "scorecardresearch.com",
            
            // Misc Popular
            "wordpress.com", "wix.com", "squarespace.com", "paypal.com", "stripe.com",
            "mailchimp.com", "dropbox.com", "drive.google.com", "docs.google.com",
            "gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "protonmail.com",
        ].into_iter().map(String::from).collect();
        
        Ok(Self {
            resolver,
            popular_domains,
        })
    }
    
    /// Warm the cache with popular domains
    pub async fn warm(&self, cache: &Arc<DnsCache>, ttl: u32) -> Result<WarmingStats, Box<dyn std::error::Error>> {
        info!(
            domains = self.popular_domains.len(),
            "Starting cache warming with popular domains"
        );
        
        let start = std::time::Instant::now();
        let mut stats = WarmingStats::default();
        
        for domain in &self.popular_domains {
            // Resolve A record
            match self.resolver.ipv4_lookup(domain).await {
                Ok(lookup) => {
                    let addresses: Vec<IpAddr> = lookup.iter().map(|r| IpAddr::V4(r.0)).collect();
                    if !addresses.is_empty() {
                        cache.insert(
                            domain,
                            &RecordType::A,
                            CachedData::IpAddresses(Arc::new(addresses)),
                            ttl,
                            Some(DnssecStatus::Unknown),
                        );
                        stats.successful_a += 1;
                        debug!(domain = %domain, "Warmed A record");
                    }
                }
                Err(e) => {
                    // Check if it's NXDOMAIN
                    if e.to_string().contains("no records found") || e.to_string().contains("NX") {
                        // Cache negative response
                        cache.insert(
                            domain,
                            &RecordType::A,
                            CachedData::NegativeResponse,
                            300,  // 5 minutes TTL for NXDOMAIN
                            Some(DnssecStatus::Unknown),
                        );
                        stats.nxdomain += 1;
                        debug!(domain = %domain, "Cached NXDOMAIN");
                    } else {
                        stats.failed += 1;
                        warn!(domain = %domain, error = %e, "Failed to warm A record");
                    }
                }
            }
            
            // Resolve AAAA record
            match self.resolver.ipv6_lookup(domain).await {
                Ok(lookup) => {
                    let addresses: Vec<IpAddr> = lookup.iter().map(|r| IpAddr::V6(r.0)).collect();
                    if !addresses.is_empty() {
                        cache.insert(
                            domain,
                            &RecordType::AAAA,
                            CachedData::IpAddresses(Arc::new(addresses)),
                            ttl,
                            Some(DnssecStatus::Unknown),
                        );
                        stats.successful_aaaa += 1;
                        debug!(domain = %domain, "Warmed AAAA record");
                    }
                }
                Err(e) => {
                    if e.to_string().contains("no records found") || e.to_string().contains("NX") {
                        // Don't cache AAAA NXDOMAIN if A succeeded
                        debug!(domain = %domain, "No AAAA record (expected for IPv4-only domains)");
                    } else {
                        debug!(domain = %domain, error = %e, "Failed to warm AAAA record");
                    }
                }
            }
            
            // Small delay to avoid overwhelming upstream DNS
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
        
        stats.duration_ms = start.elapsed().as_millis() as u64;
        stats.total_domains = self.popular_domains.len() as u64;
        
        info!(
            total = stats.total_domains,
            successful_a = stats.successful_a,
            successful_aaaa = stats.successful_aaaa,
            nxdomain = stats.nxdomain,
            failed = stats.failed,
            duration_ms = stats.duration_ms,
            cache_size = cache.len(),
            "Cache warming complete"
        );
        
        Ok(stats)
    }
}

impl Default for CacheWarmer {
    fn default() -> Self {
        Self::new().expect("Failed to create cache warmer")
    }
}

#[derive(Debug, Default, Clone)]
pub struct WarmingStats {
    pub total_domains: u64,
    pub successful_a: u64,
    pub successful_aaaa: u64,
    pub nxdomain: u64,
    pub failed: u64,
    pub duration_ms: u64,
}

impl WarmingStats {
    pub fn hit_rate(&self) -> f64 {
        if self.total_domains == 0 {
            return 0.0;
        }
        ((self.successful_a + self.successful_aaaa) as f64 / (self.total_domains * 2) as f64) * 100.0
    }
}
