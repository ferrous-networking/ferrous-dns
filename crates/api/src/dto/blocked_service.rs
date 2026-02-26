use ferrous_dns_domain::{BlockedService, ServiceDefinition};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct ServiceDefinitionResponse {
    pub id: String,
    pub name: String,
    pub category_id: String,
    pub category_name: String,
    pub icon_svg: String,
    pub rules: Vec<String>,
    pub is_custom: bool,
}

impl ServiceDefinitionResponse {
    pub fn from_definition(d: &ServiceDefinition) -> Self {
        Self {
            id: d.id.to_string(),
            name: d.name.to_string(),
            category_id: d.category_id.to_string(),
            category_name: d.category_name.to_string(),
            icon_svg: d.icon_svg.to_string(),
            rules: d.rules.iter().map(|r| r.to_string()).collect(),
            is_custom: d.is_custom,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockedServiceResponse {
    pub id: i64,
    pub service_id: String,
    pub group_id: i64,
    pub created_at: Option<String>,
}

impl BlockedServiceResponse {
    pub fn from_entity(b: BlockedService) -> Self {
        Self {
            id: b.id.unwrap_or(0),
            service_id: b.service_id.to_string(),
            group_id: b.group_id,
            created_at: b.created_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BlockServiceRequest {
    pub service_id: String,
    pub group_id: i64,
}
