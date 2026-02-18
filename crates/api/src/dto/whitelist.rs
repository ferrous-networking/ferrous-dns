use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct WhitelistResponse {
    pub domain: String,
    pub added_at: String,
}
