//! Request and reply pieces shared by the Pi-hole v6 list endpoints
//! (`/domains`, `/groups`, `/clients`, `/lists`), as FTL's `api/list.c`
//! builds them.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// `processed` of a POST/PUT reply: which items were written and which failed.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct Processed {
    pub success: Vec<ProcessedItem>,
    pub errors: Vec<ProcessedError>,
}

/// An item that was written.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProcessedItem {
    pub item: String,
}

/// An item that could not be written, and why.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProcessedError {
    pub item: String,
    pub error: String,
}

/// The item of a POST: one string, or an array to write several at once.
#[derive(Debug, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum StringOrArray {
    One(String),
    Many(Vec<String>),
}

impl StringOrArray {
    pub fn into_items(self) -> Vec<String> {
        match self {
            Self::One(item) => vec![item],
            Self::Many(items) => items,
        }
    }
}

/// One entry of a `:batchDelete` body. `/domains` also needs `type` and
/// `kind`, `/lists` needs `type`; the other endpoints only read `item`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BatchDeleteItem {
    pub item: String,
    #[serde(rename = "type")]
    pub item_type: Option<String>,
    pub kind: Option<String>,
}
