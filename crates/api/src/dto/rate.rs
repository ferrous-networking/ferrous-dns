use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Deserialize, Debug, IntoParams)]
pub struct RateQuery {
    #[serde(default = "default_unit")]
    pub unit: String,
}

fn default_unit() -> String {
    "second".to_string()
}

#[derive(Serialize, Debug, ToSchema)]
pub struct QueryRateResponse {
    pub queries: u64,
    pub rate: String,
}
