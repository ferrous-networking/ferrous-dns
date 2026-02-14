use serde::{Deserialize, Serialize};

#[derive(Deserialize, Debug)]
pub struct RateQuery {
    #[serde(default = "default_unit")]
    pub unit: String,
}

fn default_unit() -> String {
    "second".to_string()
}

#[derive(Serialize, Debug)]
pub struct QueryRateResponse {
    pub queries: u64,
    pub rate: String,
}
