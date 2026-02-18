use axum::{extract::State, Json};
use ferrous_dns_infrastructure::dns::{HealthChecker, PoolManager};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

pub struct UpstreamState {
    pub pool_manager: Arc<PoolManager>,
    pub health_checker: Option<Arc<HealthChecker>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpstreamHealthResponse {
    pub servers: HashMap<String, String>,
}

pub async fn get_upstream_health(
    State(state): State<Arc<UpstreamState>>,
) -> Json<HashMap<String, String>> {
    let mut health_map = HashMap::new();

    if let Some(checker) = &state.health_checker {
        let all_protocols = state.pool_manager.get_all_protocols();

        for protocol in all_protocols {
            let status = checker.get_status(&protocol);
            let status_str = match status {
                ferrous_dns_infrastructure::dns::ServerStatus::Healthy => "Healthy",
                ferrous_dns_infrastructure::dns::ServerStatus::Unhealthy => "Unhealthy",
                ferrous_dns_infrastructure::dns::ServerStatus::Unknown => "Unknown",
            };
            health_map.insert(protocol.to_string(), status_str.to_string());
        }
    }

    Json(health_map)
}
