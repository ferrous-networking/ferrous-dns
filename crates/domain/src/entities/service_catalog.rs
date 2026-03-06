use std::sync::Arc;

/// Definition of a blockable service from the catalog (built-in or custom).
#[derive(Clone)]
pub struct ServiceDefinition {
    pub id: Arc<str>,
    pub name: Arc<str>,
    pub category_id: Arc<str>,
    pub category_name: Arc<str>,
    pub icon_svg: Arc<str>,
    pub rules: Vec<Arc<str>>,
    pub is_custom: bool,
}
