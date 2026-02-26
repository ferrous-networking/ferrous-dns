use ferrous_dns_domain::CustomService;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct CustomServiceResponse {
    pub id: i64,
    pub service_id: String,
    pub name: String,
    pub category_name: String,
    pub domains: Vec<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl CustomServiceResponse {
    pub fn from_entity(cs: CustomService) -> Self {
        Self {
            id: cs.id.unwrap_or(0),
            service_id: cs.service_id.to_string(),
            name: cs.name.to_string(),
            category_name: cs.category_name.to_string(),
            domains: cs.domains.iter().map(|d| d.to_string()).collect(),
            created_at: cs.created_at,
            updated_at: cs.updated_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateCustomServiceRequest {
    pub name: String,
    pub domains: Vec<String>,
    pub category_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateCustomServiceRequest {
    pub name: Option<String>,
    pub category_name: Option<String>,
    pub domains: Option<Vec<String>>,
}
