use crate::ports::{PagedQueryResult, QueryLogRepository};
use ferrous_dns_domain::query_log::{QueryCategory, QueryLog, QueryLogFilter};
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
    pub client_ip: Option<&'a str>,
    pub record_type: Option<&'a str>,
    pub upstream: Option<&'a str>,
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
    /// Invalid `client_ip` format returns `DomainError::InvalidInput`.
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

        let parsed_client_ip = input
            .client_ip
            .filter(|c| !c.is_empty())
            .map(|ip| {
                ip.parse::<std::net::IpAddr>()
                    .map_err(|e| DomainError::InvalidInput(e.to_string()))
            })
            .transpose()?;

        let filter = QueryLogFilter {
            domain: input.domain.filter(|d| !d.is_empty()).map(String::from),
            category: parsed_category,
            client_ip: parsed_client_ip,
            record_type: parsed_record_type,
            upstream: input.upstream.filter(|u| !u.is_empty()).map(String::from),
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
