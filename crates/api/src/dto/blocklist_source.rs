use ferrous_dns_domain::BlocklistSource;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistSourceResponse {
    pub id: i64,
    pub name: String,
    pub url: Option<String>,
    pub group_id: i64,
    pub comment: Option<String>,
    pub enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl BlocklistSourceResponse {
    pub fn from_source(source: BlocklistSource) -> Self {
        Self {
            id: source.id.unwrap_or(0),
            name: source.name.to_string(),
            url: source.url.as_ref().map(|s| s.to_string()),
            group_id: source.group_id,
            comment: source.comment.as_ref().map(|s| s.to_string()),
            enabled: source.enabled,
            created_at: source.created_at,
            updated_at: source.updated_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateBlocklistSourceRequest {
    pub name: String,
    pub url: Option<String>,
    pub group_id: Option<i64>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateBlocklistSourceRequest {
    pub name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_nullable_string")]
    pub url: Option<Option<String>>,
    pub group_id: Option<i64>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

fn deserialize_optional_nullable_string<'de, D>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let val: Option<serde_json::Value> = serde::Deserialize::deserialize(deserializer)?;

    match val {
        None => Ok(None),
        Some(serde_json::Value::Null) => Ok(Some(None)),
        Some(serde_json::Value::String(s)) => Ok(Some(Some(s))),
        Some(other) => Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::Other(&format!("{}", other)),
            &"string or null",
        )),
    }
}
