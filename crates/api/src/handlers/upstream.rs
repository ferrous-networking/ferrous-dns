use axum::{extract::State, Json};
use ferrous_dns_application::ports::UpstreamStatus;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::state::AppState;

#[derive(Debug, Serialize, Deserialize)]
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
