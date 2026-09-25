use ferrous_dns_domain::DomainError;
use std::time::Duration;

const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Fetches the text of blocklist and allowlist sources.
pub struct ListDownloader {
    client: reqwest::Client,
}

impl ListDownloader {
    pub fn new() -> Result<Self, DomainError> {
        let client = reqwest::Client::builder()
            .user_agent("ferrous-dns/1.0 (blocklist-sync)")
            .timeout(DOWNLOAD_TIMEOUT)
            .build()
            .map_err(|e| DomainError::BlockFilterCompileError(e.to_string()))?;
        Ok(Self { client })
    }

    pub async fn fetch(&self, url: &str) -> Result<String, DomainError> {
        let response = self
            .client
            .get(url)
            .timeout(DOWNLOAD_TIMEOUT)
            .send()
            .await
            .map_err(|e| DomainError::BlockFilterFetchError(format!("{url}: {e}")))?;

        if !response.status().is_success() {
            return Err(DomainError::BlockFilterFetchError(format!(
                "HTTP {} for {url}",
                response.status().as_u16()
            )));
        }

        response
            .text()
            .await
            .map_err(|e| DomainError::BlockFilterFetchError(format!("reading {url}: {e}")))
    }
}
