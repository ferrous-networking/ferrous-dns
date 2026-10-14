use serde::Serialize;
use utoipa::ToSchema;

/// Pi-hole v6 GET /api/endpoints response.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct EndpointsResponse {
    pub endpoints: EndpointsByMethod,
}

/// Every served route, once under each method it answers.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct EndpointsByMethod {
    pub get: Vec<EndpointEntry>,
    pub post: Vec<EndpointEntry>,
    pub put: Vec<EndpointEntry>,
    pub patch: Vec<EndpointEntry>,
    pub delete: Vec<EndpointEntry>,
}

/// A route split as FTL's route table does: `/api/domains` + `/{type}/{kind}`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct EndpointEntry {
    pub uri: String,
    /// Path parameters after `uri`, empty when there are none.
    pub parameters: String,
}
