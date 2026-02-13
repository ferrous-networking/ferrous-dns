use ferrous_dns_domain::ClientSubnet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct ClientSubnetResponse {
    pub id: i64,
    pub subnet_cidr: String,
    pub group_id: i64,
    pub group_name: Option<String>,
    pub comment: Option<String>,
    pub created_at: Option<String>,
}

impl ClientSubnetResponse {
    pub fn from_subnet(subnet: ClientSubnet, group_name: Option<String>) -> Self {
        Self {
            id: subnet.id.unwrap_or(0),
            subnet_cidr: subnet.subnet_cidr.to_string(),
            group_id: subnet.group_id,
            group_name,
            comment: subnet.comment.as_ref().map(|s| s.to_string()),
            created_at: subnet.created_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateClientSubnetRequest {
    pub subnet_cidr: String,
    pub group_id: i64,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateManualClientRequest {
    pub ip_address: String,
    pub group_id: Option<i64>,
    pub hostname: Option<String>,
    pub mac_address: Option<String>,
}
