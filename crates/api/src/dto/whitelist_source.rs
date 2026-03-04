use ferrous_dns_domain::WhitelistSource;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhitelistSourceResponse {
    pub id: i64,
    pub name: String,
    pub url: Option<String>,
    pub group_ids: Vec<i64>,
    pub comment: Option<String>,
    pub enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl WhitelistSourceResponse {
    pub fn from_source(source: WhitelistSource) -> Self {
        Self {
            id: source.id.unwrap_or(0),
            name: source.name.to_string(),
            url: source.url.as_ref().map(|s| s.to_string()),
            group_ids: source.group_ids,
            comment: source.comment.as_ref().map(|s| s.to_string()),
            enabled: source.enabled,
            created_at: source.created_at,
            updated_at: source.updated_at,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateWhitelistSourceRequest {
    pub name: String,
    pub url: Option<String>,
    /// Legacy: single group_id. If group_ids is also present, group_ids takes precedence.
    pub group_id: Option<i64>,
    pub group_ids: Option<Vec<i64>>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

impl CreateWhitelistSourceRequest {
    /// Resolve the effective group_ids, preferring group_ids over legacy group_id.
    pub fn resolved_group_ids(&self, default_group_id: i64) -> Vec<i64> {
        if let Some(ref ids) = self.group_ids {
            if !ids.is_empty() {
                return ids.clone();
            }
        }
        if let Some(gid) = self.group_id {
            return vec![gid];
        }
        vec![default_group_id]
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateWhitelistSourceRequest {
    pub name: Option<String>,
    #[serde(default, deserialize_with = "deserialize_optional_nullable_string")]
    pub url: Option<Option<String>>,
    /// Legacy: single group_id. If group_ids is also present, group_ids takes precedence.
    pub group_id: Option<i64>,
    pub group_ids: Option<Vec<i64>>,
    pub comment: Option<String>,
    pub enabled: Option<bool>,
}

impl UpdateWhitelistSourceRequest {
    /// Resolve the effective group_ids update, preferring group_ids over legacy group_id.
    pub fn resolved_group_ids(&self) -> Option<Vec<i64>> {
        if let Some(ref ids) = self.group_ids {
            return Some(ids.clone());
        }
        self.group_id.map(|gid| vec![gid])
    }
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
