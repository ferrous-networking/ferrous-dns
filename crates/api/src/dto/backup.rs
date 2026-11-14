use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

#[derive(Deserialize, Debug, IntoParams)]
pub struct ImportQuery {
    /// Keep this server's ports, bind addresses, web TLS files and passkey
    /// origin instead of the backup's: for copying a setup to a second server.
    #[serde(default)]
    pub keep_host_settings: bool,
}

/// HTTP response returned after a successful import operation.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ImportSummaryResponse {
    pub success: bool,
    /// The restored config only applies after a restart.
    pub restart_required: bool,
    pub summary: ImportSummaryDto,
    pub errors: Vec<String>,
    /// Settings this server kept on where the backup had them off
    /// (authentication, the login lockout), and why. These do not make
    /// `success` false.
    pub warnings: Vec<String>,
}

/// Serializable summary of what was created or skipped during import.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ImportSummaryDto {
    pub config_updated: bool,
    pub groups_imported: usize,
    pub groups_skipped: usize,
    pub blocklist_sources_imported: usize,
    pub blocklist_sources_skipped: usize,
    pub local_records_imported: usize,
    pub local_records_skipped: usize,
}
