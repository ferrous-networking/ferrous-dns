#[derive(Debug, Clone)]
pub struct BlockedDomain {
    pub id: Option<i64>,
    pub domain: String,
    pub added_at: Option<String>,
}

impl BlockedDomain {
    pub fn new(domain: String) -> Self {
        Self {
            id: None,
            domain,
            added_at: None,
        }
    }
}
