use super::{HealthChecker, PoolManager, ServerStatus};
use ferrous_dns_application::ports::{UpstreamHealthPort, UpstreamStatus};
use std::sync::Arc;

pub struct UpstreamHealthAdapter {
    pool_manager: Arc<PoolManager>,
    health_checker: Option<Arc<HealthChecker>>,
}

impl UpstreamHealthAdapter {
    pub fn new(pool_manager: Arc<PoolManager>, health_checker: Option<Arc<HealthChecker>>) -> Self {
        Self {
            pool_manager,
            health_checker,
        }
    }
}

impl UpstreamHealthPort for UpstreamHealthAdapter {
    fn get_all_upstream_status(&self) -> Vec<(String, UpstreamStatus)> {
        let Some(checker) = &self.health_checker else {
            return Vec::new();
        };

        self.pool_manager
            .get_all_arc_protocols()
            .into_iter()
            .map(|protocol| {
                let status = match checker.get_status(&protocol) {
                    ServerStatus::Healthy => UpstreamStatus::Healthy,
                    ServerStatus::Unhealthy => UpstreamStatus::Unhealthy,
                    ServerStatus::Unknown => UpstreamStatus::Unknown,
                };
                (protocol.to_string(), status)
            })
            .collect()
    }
}
