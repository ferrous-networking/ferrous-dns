use serde::Serialize;

/// HTTP response returned after a successful import operation.
#[derive(Debug, Clone, Serialize)]
pub struct ImportSummaryResponse {
    pub success: bool,
    pub summary: ImportSummaryDto,
    pub errors: Vec<String>,
}

/// Serializable summary of what was created or skipped during import.
#[derive(Debug, Clone, Serialize)]
pub struct ImportSummaryDto {
    pub config_updated: bool,
    pub groups_imported: usize,
    pub groups_skipped: usize,
    pub blocklist_sources_imported: usize,
    pub blocklist_sources_skipped: usize,
    pub local_records_imported: usize,
    pub local_records_skipped: usize,
}
