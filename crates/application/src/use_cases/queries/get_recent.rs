use crate::ports::{PageAt, PagedQueryResult, QueryLogRepository};
use ferrous_dns_domain::entities::query_log::{
    ClientProtocol, DnssecStatusFilter, QueryCategory, QueryLog, QueryLogFilter, ReplyFilter,
};
use ferrous_dns_domain::{DomainError, RecordType};
use std::sync::Arc;

const MAX_LIMIT: u32 = 1_000;

/// Cap of a [`PageAt::Snapshot`] page: Pi-hole FTL's `API_QUERIES_MAX_ROWS`,
/// which also bounds its "every row" request.
const MAX_SNAPSHOT_LIMIT: u32 = 10_000;

/// Input for paginated query log fetching with optional filters.
///
/// String filter fields are raw values from the HTTP layer; the use case
/// validates and parses them into typed values before querying the repository.
#[derive(Debug, Default)]
pub struct PagedQueryInput<'a> {
    pub limit: u32,
    pub page: PageAt,
    pub period_hours: f32,
    pub domain: Option<&'a str>,
    pub category: Option<&'a str>,
    pub client: Option<&'a str>,
    pub record_type: Option<&'a str>,
    pub upstream: Option<&'a str>,
    pub dnssec_status: Option<DnssecStatusFilter>,
    /// `Some(true)` → only DNS64-synthesized answers; `Some(false)` → only
    /// non-synthesized; `None` → no filter.
    pub dns64: Option<bool>,
    /// Transport filter: `udp`, `tcp`, `dot`, `doh` or `doq`.
    pub protocol: Option<&'a str>,
    /// Only queries logged before this Unix time.
    pub until: Option<i64>,
    /// Record types left out.
    pub excluded_record_types: Vec<RecordType>,
    /// Only queries answered with this kind of reply.
    pub reply: Option<ReplyFilter>,
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
    /// A page is capped at 1000 rows, or 10000 for a [`PageAt::Snapshot`].
    pub async fn execute_paged(
        &self,
        input: &PagedQueryInput<'_>,
    ) -> Result<PagedQueryResult, DomainError> {
        let parsed_category = input
            .category
            .filter(|c| !c.is_empty())
            .map(|c| c.parse::<QueryCategory>())
            .transpose()?;

        let parsed_record_type = input
            .record_type
            .filter(|t| !t.is_empty())
            .map(|t| t.parse::<RecordType>())
            .transpose()?;

        let parsed_protocol = input
            .protocol
            .filter(|p| !p.is_empty())
            .map(|p| p.to_ascii_lowercase().parse::<ClientProtocol>())
            .transpose()?;

        let filter = QueryLogFilter {
            domain: input.domain.filter(|d| !d.is_empty()).map(String::from),
            category: parsed_category,
            client: input.client.filter(|c| !c.is_empty()).map(String::from),
            record_type: parsed_record_type,
            upstream: input.upstream.filter(|u| !u.is_empty()).map(String::from),
            dnssec_status: input.dnssec_status,
            dns64_synthesized: input.dns64,
            protocol: parsed_protocol,
            until: input.until,
            excluded_record_types: input.excluded_record_types.clone(),
            reply: input.reply,
        };

        let max_limit = match input.page {
            PageAt::Snapshot { .. } => MAX_SNAPSHOT_LIMIT,
            PageAt::Offset(_) | PageAt::Cursor(_) => MAX_LIMIT,
        };
        self.repository
            .get_recent_paged(
                input.limit.min(max_limit),
                input.page,
                input.period_hours,
                &filter,
            )
            .await
    }
}
