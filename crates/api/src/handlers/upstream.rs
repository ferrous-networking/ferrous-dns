use axum::{extract::State, Json};
use ferrous_dns_application::ports::{AggregateStatus, IpFamily, UpstreamStatus};
use ferrous_dns_domain::UpstreamStrategy;
use serde::Serialize;
use std::collections::HashMap;

use crate::state::AppState;

/// Flat map response kept for backward compatibility.
#[derive(Debug, Serialize)]
pub struct UpstreamHealthResponse {
    pub servers: HashMap<String, String>,
}

pub async fn get_upstream_health(State(state): State<AppState>) -> Json<HashMap<String, String>> {
    let mut health_map = HashMap::new();

    for (server, status) in state.dns.upstream_health.get_all_upstream_status() {
        let status_str = match status {
            UpstreamStatus::Healthy => "Healthy",
            UpstreamStatus::Unhealthy => "Unhealthy",
            UpstreamStatus::Unknown => "Unknown",
        };
        health_map.insert(server, status_str.to_string());
    }

    Json(health_map)
}

/// Per-IP endpoint detail within a server group.
#[derive(Debug, Serialize)]
pub struct ResolvedEndpointResponse {
    pub address: String,
    pub family: String,
    pub status: String,
    pub latency_ms: Option<u64>,
    pub last_error: Option<String>,
    pub consecutive_failures: u16,
}

/// Grouped health response: one entry per configured upstream server.
#[derive(Debug, Serialize)]
pub struct UpstreamGroupResponse {
    pub address: String,
    pub status: String,
    pub resolved: Vec<ResolvedEndpointResponse>,
    pub pool_name: String,
    pub strategy: String,
}

pub async fn get_upstream_health_detail(
    State(state): State<AppState>,
) -> Json<Vec<UpstreamGroupResponse>> {
    let groups = state.dns.upstream_health.get_grouped_upstream_health();

    let response = groups
        .into_iter()
        .map(|g| UpstreamGroupResponse {
            address: g.address,
            status: match g.status {
                AggregateStatus::Healthy => "Healthy",
                AggregateStatus::Partial => "Partial",
                AggregateStatus::Unhealthy => "Unhealthy",
                AggregateStatus::Unknown => "Unknown",
            }
            .to_string(),
            pool_name: g.pool_name,
            strategy: match g.strategy {
                UpstreamStrategy::Parallel => "Parallel",
                UpstreamStrategy::Failover => "Failover",
                UpstreamStrategy::Balanced => "Balanced",
            }
            .to_string(),
            resolved: g
                .resolved
                .into_iter()
                .map(|r| ResolvedEndpointResponse {
                    address: r.address,
                    family: match r.family {
                        IpFamily::Ipv4 => "ipv4",
                        IpFamily::Ipv6 => "ipv6",
                        IpFamily::Unknown => "unknown",
                    }
                    .to_string(),
                    status: match r.status {
                        UpstreamStatus::Healthy => "Healthy",
                        UpstreamStatus::Unhealthy => "Unhealthy",
                        UpstreamStatus::Unknown => "Unknown",
                    }
                    .to_string(),
                    latency_ms: r.latency_ms,
                    last_error: r.last_error,
                    consecutive_failures: r.consecutive_failures,
                })
                .collect(),
        })
        .collect();

    Json(response)
}
