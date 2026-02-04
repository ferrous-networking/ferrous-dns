use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct HostnameResponse {
    pub hostname: String,
}
