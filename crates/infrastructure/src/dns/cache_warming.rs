use crate::dns::cache::{CachedData, DnsCache, DnssecStatus};
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::RecordType;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct CacheWarmer {
    pool_manager: Arc<PoolManager>,
    popular_domains: Vec<String>,
}

impl CacheWarmer {
    pub fn new(pool_manager: Arc<PoolManager>) -> Self {
        let popular_domains = vec![
            "google.com",
            "youtube.com",
            "facebook.com",
            "twitter.com",
            "x.com",
            "instagram.com",
            "linkedin.com",
            "reddit.com",
            "tiktok.com",
            "pinterest.com",
            "amazon.com",
            "apple.com",
            "microsoft.com",
            "github.com",
            "stackoverflow.com",
            "cloudflare.com",
            "openai.com",
            "anthropic.com",
            "nvidia.com",
            "vercel.com",
            "netflix.com",
            "spotify.com",
            "twitch.tv",
            "discord.com",
            "vimeo.com",
            "soundcloud.com",
            "zoom.us",
            "slack.com",
            "notion.so",
            "figma.com",
            "wikipedia.org",
            "medium.com",
            "cnn.com",
            "bbc.com",
            "nytimes.com",
            "theguardian.com",
            "reuters.com",
            "bloomberg.com",
            "wsj.com",
            "forbes.com",
            "ebay.com",
            "walmart.com",
            "target.com",
            "bestbuy.com",
            "etsy.com",
            "shopify.com",
            "aliexpress.com",
            "mercadolivre.com.br",
            "alibaba.com",
            "docker.com",
            "kubernetes.io",
            "python.org",
            "rust-lang.org",
            "nodejs.org",
            "golang.org",
            "mozilla.org",
            "chromium.org",
            "ubuntu.com",
            "archlinux.org",
            "jsdelivr.net",
            "unpkg.com",
            "cdnjs.com",
            "fonts.googleapis.com",
            "ajax.googleapis.com",
            "code.jquery.com",
            "maxcdn.com",
            "akamai.com",
            "google-analytics.com",
            "doubleclick.net",
            "googlesyndication.com",
            "googleadservices.com",
            "facebook.net",
            "scorecardresearch.com",
            "wordpress.com",
            "wix.com",
            "squarespace.com",
            "paypal.com",
            "stripe.com",
            "mailchimp.com",
            "dropbox.com",
            "drive.google.com",
            "docs.google.com",
            "gmail.com",
            "outlook.com",
            "yahoo.com",
            "hotmail.com",
            "protonmail.com",
        ]
        .into_iter()
        .map(String::from)
        .collect();

        Self {
            pool_manager,
            popular_domains,
        }
    }

    pub async fn warm(&self, cache: &Arc<DnsCache>, ttl: u32, timeout_ms: u64) -> WarmingStats {
        info!(
            domains = self.popular_domains.len(),
            "Starting cache warming"
        );
        let start = std::time::Instant::now();
        let mut stats = WarmingStats::default();

        for domain in &self.popular_domains {
            match self
                .pool_manager
                .query(domain, &RecordType::A, timeout_ms)
                .await
            {
                Ok(result) => {
                    let addrs = result.response.addresses.clone();
                    if !addrs.is_empty() {
                        cache.insert(
                            domain,
                            RecordType::A,
                            CachedData::IpAddresses(Arc::new(addrs)),
                            ttl,
                            Some(DnssecStatus::Unknown),
                        );
                        stats.successful_a += 1;
                        debug!(domain = %domain, "Warmed A record");
                    } else if result.response.is_nxdomain() || result.response.is_nodata() {
                        cache.insert(
                            domain,
                            RecordType::A,
                            CachedData::NegativeResponse,
                            300,
                            Some(DnssecStatus::Unknown),
                        );
                        stats.nxdomain += 1;
                    }
                }
                Err(e) => {
                    stats.failed += 1;
                    warn!(domain = %domain, error = %e, "Failed to warm A");
                }
            }

            if let Ok(result) = self
                .pool_manager
                .query(domain, &RecordType::AAAA, timeout_ms)
                .await
            {
                let addrs = result.response.addresses.clone();
                if !addrs.is_empty() {
                    cache.insert(
                        domain,
                        RecordType::AAAA,
                        CachedData::IpAddresses(Arc::new(addrs)),
                        ttl,
                        Some(DnssecStatus::Unknown),
                    );
                    stats.successful_aaaa += 1;
                }
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }

        stats.duration_ms = start.elapsed().as_millis() as u64;
        stats.total_domains = self.popular_domains.len() as u64;

        info!(
            total = stats.total_domains,
            a = stats.successful_a,
            aaaa = stats.successful_aaaa,
            nxdomain = stats.nxdomain,
            failed = stats.failed,
            duration_ms = stats.duration_ms,
            cache_size = cache.len(),
            "Cache warming complete"
        );
        stats
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
        ((self.successful_a + self.successful_aaaa) as f64 / (self.total_domains * 2) as f64)
            * 100.0
    }
}
