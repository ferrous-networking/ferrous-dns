use ferrous_dns_domain::DomainError;
use std::time::Duration;
use tokio::time::Instant;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Fails a transfer that stops making progress. A limit on the whole transfer
/// scales with the link instead: HaGeZi TIF is 44 MB, which a 30-second cap cut
/// off below about 12 Mbit/s (issue #248).
const STALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Stops a server that trickles bytes forever. A rebuild holds its lock while
/// it downloads, so every filter change waits this long at worst.
const DOWNLOAD_TIME_LIMIT: Duration = Duration::from_secs(5 * 60);

/// Fetches the text of blocklist and allowlist sources.
pub struct ListDownloader {
    client: reqwest::Client,
}

impl ListDownloader {
    pub fn new() -> Result<Self, DomainError> {
        let client = reqwest::Client::builder()
            .user_agent("ferrous-dns/1.0 (blocklist-sync)")
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(STALL_TIMEOUT)
            .timeout(DOWNLOAD_TIME_LIMIT)
            .build()
            .map_err(|e| DomainError::BlockFilterCompileError(e.to_string()))?;
        Ok(Self { client })
    }

    pub async fn fetch(&self, url: &str) -> Result<String, DomainError> {
        let started = Instant::now();
        // reqwest reports a timeout while reading the body as "error decoding response body".
        let describe = |e: reqwest::Error| {
            if e.is_timeout() {
                format!("timed out after {}s", started.elapsed().as_secs())
            } else {
                e.to_string()
            }
        };

        let response =
            self.client.get(url).send().await.map_err(|e| {
                DomainError::BlockFilterFetchError(format!("{url}: {}", describe(e)))
            })?;

        if !response.status().is_success() {
            return Err(DomainError::BlockFilterFetchError(format!(
                "HTTP {} for {url}",
                response.status().as_u16()
            )));
        }

        response.text().await.map_err(|e| {
            DomainError::BlockFilterFetchError(format!("reading {url}: {}", describe(e)))
        })
    }
}
