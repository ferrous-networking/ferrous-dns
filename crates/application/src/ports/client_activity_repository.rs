use async_trait::async_trait;
use ferrous_dns_domain::DomainError;

/// Queries of one client, or of every other client, in one time bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientActivity {
    /// Bucket start in Unix seconds, a multiple of the bucket width.
    pub bucket: i64,
    /// `None` sums every client outside the requested set.
    pub client_ip: Option<String>,
    pub count: u64,
}

/// Per-client query counts over time, for Pi-hole's `GET /history/clients`.
#[async_trait]
pub trait ClientActivityRepository: Send + Sync {
    /// Client queries in the period, counted per `bucket_secs`-wide bucket.
    /// Each client in `clients` gets its own rows; all other clients share
    /// one row per bucket. Buckets without queries are omitted.
    async fn get_client_activity(
        &self,
        clients: &[String],
        bucket_secs: u32,
        period_hours: f32,
    ) -> Result<Vec<ClientActivity>, DomainError>;
}
