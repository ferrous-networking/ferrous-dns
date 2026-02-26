use std::sync::Arc;

/// A service blocked for a specific group.
pub struct BlockedService {
    pub id: Option<i64>,
    pub service_id: Arc<str>,
    pub group_id: i64,
    pub created_at: Option<String>,
}
