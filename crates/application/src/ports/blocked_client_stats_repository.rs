use async_trait::async_trait;
use ferrous_dns_domain::DomainError;

/// Ranks clients by their blocked queries, for Pi-hole's
/// `GET /stats/top_clients?blocked=true`.
#[async_trait]
pub trait BlockedClientStatsRepository: Send + Sync {
    /// Clients with blocked queries in the period as `(ip, hostname, blocked
    /// count)`, most blocked first.
    async fn get_top_blocked_clients(
        &self,
        limit: u32,
        period_hours: f32,
    ) -> Result<Vec<(String, Option<String>, u64)>, DomainError>;
}
