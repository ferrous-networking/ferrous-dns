use serde::Serialize;

/// Pi-hole v6 POST /api/action/* response.
#[derive(Debug, Serialize)]
pub struct ActionResponse {
    pub status: &'static str,
    pub message: String,
}
