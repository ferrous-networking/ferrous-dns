use std::sync::Arc;

/// A user-defined custom service with associated domains.
pub struct CustomService {
    pub id: Option<i64>,
    pub service_id: Arc<str>,
    pub name: Arc<str>,
    pub category_name: Arc<str>,
    pub domains: Vec<Arc<str>>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}
