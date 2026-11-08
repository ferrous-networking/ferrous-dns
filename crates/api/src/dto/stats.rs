use ferrous_dns_domain::QueryStats;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::{IntoParams, ToSchema};

const TOP_TYPES_LIMIT: usize = 10;

#[derive(Deserialize, Debug, IntoParams)]
pub struct StatsQuery {
    #[serde(default = "crate::utils::default_period")]
    pub period: String,
}

pub type QuerySourceStats = HashMap<String, u64>;

#[derive(Serialize, Debug, Clone, Default, ToSchema)]
pub struct StatsResponse {
    pub queries_total: u64,
    pub queries_blocked: u64,
    pub queries_rate_limited: u64,
    pub queries_malware_detected: u64,
    pub queries_dnssec_bogus: u64,
    pub clients: u64,
    pub uptime: u64,
    /// Percentage of answered client queries served from cache, the same
    /// figure as `/cache/stats`. Blocked queries count in neither part.
    pub cache_hit_rate: f64,
    pub avg_query_time_ms: f64,
    pub avg_cache_time_ms: f64,
    pub avg_upstream_time_ms: f64,

    pub queries_by_type: HashMap<String, u64>,
    pub most_queried_type: Option<String>,
    pub record_type_distribution: Vec<TypeDistribution>,
    pub top_10_types: Vec<TopType>,
    pub source_stats: QuerySourceStats,
}

impl From<QueryStats> for StatsResponse {
    fn from(stats: QueryStats) -> Self {
        let top_10_types = stats
            .top_types(TOP_TYPES_LIMIT)
            .into_iter()
            .map(|(rt, count)| TopType {
                record_type: rt.as_str().to_string(),
                count,
            })
            .collect();

        Self {
            queries_total: stats.queries_total,
            queries_blocked: stats.queries_blocked,
            queries_rate_limited: stats.queries_rate_limited,
            queries_malware_detected: stats.queries_malware_detected,
            queries_dnssec_bogus: stats.queries_dnssec_bogus,
            clients: stats.unique_clients,
            uptime: stats.uptime_seconds,
            cache_hit_rate: stats.cache_hit_rate,
            avg_query_time_ms: stats.avg_query_time_ms,
            avg_cache_time_ms: stats.avg_cache_time_ms,
            avg_upstream_time_ms: stats.avg_upstream_time_ms,
            queries_by_type: stats
                .queries_by_type
                .iter()
                .map(|(rt, count)| (rt.as_str().to_string(), *count))
                .collect(),
            most_queried_type: stats.most_queried_type.map(|rt| rt.as_str().to_string()),
            record_type_distribution: stats
                .record_type_distribution
                .iter()
                .map(|(rt, pct)| TypeDistribution {
                    record_type: rt.as_str().to_string(),
                    percentage: *pct,
                })
                .collect(),
            top_10_types,
            source_stats: stats.source_stats,
        }
    }
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct TypeDistribution {
    pub record_type: String,
    pub percentage: f64,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct TopType {
    pub record_type: String,
    pub count: u64,
}
