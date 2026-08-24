use crate::ports::{PagedQueryResult, QueryLogRepository};
use ferrous_dns_domain::query_log::{
    ClientProtocol, DnssecStatus, QueryCategory, QueryLog, QueryLogFilter,
};
use ferrous_dns_domain::{DomainError, RecordType};
use std::sync::Arc;

const MAX_LIMIT: u32 = 1_000;

/// Input for paginated query log fetching with optional filters.
///
/// All filter fields accept raw strings from the HTTP layer; the use case
/// validates and parses them into typed values before querying the repository.
#[derive(Debug, Default)]
pub struct PagedQueryInput<'a> {
    pub limit: u32,
    pub offset: u32,
    pub period_hours: f32,
    pub cursor: Option<i64>,
    pub domain: Option<&'a str>,
    pub category: Option<&'a str>,
    pub client: Option<&'a str>,
    pub record_type: Option<&'a str>,
    pub upstream: Option<&'a str>,
    pub dnssec_status: Option<&'a str>,
    /// `Some(true)` → only DNS64-synthesized answers; `Some(false)` → only
    /// non-synthesized; `None` → no filter.
    pub dns64: Option<bool>,
    /// Transport filter: `udp`, `tcp`, `dot`, `doh` or `doq`.
    pub protocol: Option<&'a str>,
}

/// Validates and normalises a DNSSEC status filter value to the casing stored
/// in the query log. Accepts the `any` sentinel (any validated row) and the
/// four outcome statuses, case-insensitively.
fn normalize_dnssec_status(value: &str) -> Result<String, String> {
    if value.eq_ignore_ascii_case("any") {
        return Ok("any".to_string());
    }
    value
        .parse::<DnssecStatus>()
        .map(|status| status.as_str().to_string())
}

pub struct GetRecentQueriesUseCase {
    repository: Arc<dyn QueryLogRepository>,
}

impl GetRecentQueriesUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(
        &self,
        limit: u32,
        period_hours: f32,
    ) -> Result<Vec<QueryLog>, DomainError> {
        self.repository
            .get_recent(limit.min(MAX_LIMIT), period_hours)
            .await
    }

    /// Fetches paginated queries with optional filters.
    ///
    /// String parameters are validated and parsed into typed filter values.
    /// Invalid `category` or `record_type` returns `DomainError::InvalidInput`.
    pub async fn execute_paged(
        &self,
        input: &PagedQueryInput<'_>,
    ) -> Result<PagedQueryResult, DomainError> {
        let parsed_category = input
            .category
            .filter(|c| !c.is_empty())
            .map(|c| c.parse::<QueryCategory>())
            .transpose()
            .map_err(DomainError::InvalidInput)?;

        let parsed_record_type = input
            .record_type
            .filter(|t| !t.is_empty())
            .map(|t| t.parse::<RecordType>())
            .transpose()
            .map_err(DomainError::InvalidInput)?;

        let parsed_dnssec_status = input
            .dnssec_status
            .filter(|s| !s.is_empty())
            .map(normalize_dnssec_status)
            .transpose()
            .map_err(DomainError::InvalidInput)?;

        let parsed_protocol = input
            .protocol
            .filter(|p| !p.is_empty())
            .map(|p| p.to_ascii_lowercase().parse::<ClientProtocol>())
            .transpose()
            .map_err(|e| DomainError::InvalidInput(e.to_string()))?;

        let filter = QueryLogFilter {
            domain: input.domain.filter(|d| !d.is_empty()).map(String::from),
            category: parsed_category,
            client: input.client.filter(|c| !c.is_empty()).map(String::from),
            record_type: parsed_record_type,
            upstream: input.upstream.filter(|u| !u.is_empty()).map(String::from),
            dnssec_status: parsed_dnssec_status,
            dns64_synthesized: input.dns64,
            protocol: parsed_protocol,
        };

        self.repository
            .get_recent_paged(
                input.limit.min(MAX_LIMIT),
                input.offset,
                input.period_hours,
                input.cursor,
                &filter,
            )
            .await
    }
}
