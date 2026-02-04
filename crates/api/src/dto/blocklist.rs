use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct BlocklistResponse {
    pub domain: String,
    pub added_at: String,
}
