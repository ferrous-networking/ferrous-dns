use std::sync::Arc;

use axum::{Extension, Json};
use utoipa::openapi::path::Operation;
use utoipa::openapi::OpenApi;

use crate::dto::endpoints::{EndpointEntry, EndpointsByMethod, EndpointsResponse};

/// Where the router is mounted; FTL's URIs carry it.
const API_PREFIX: &str = "/api";

/// Pi-hole v6 GET /api/endpoints
///
/// Lists the routes of the served OpenAPI document, so the list cannot drift
/// from what the router answers. Routes kept out of the document stay out
/// here too: the `/history` alias of `/stats/history` and the `{*rest}`
/// routes that take a list or client address with slashes in it.
#[utoipa::path(
    get,
    path = "/endpoints",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Every route by HTTP method", body = EndpointsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_endpoints(
    Extension(endpoints): Extension<Arc<EndpointsResponse>>,
) -> Json<EndpointsResponse> {
    Json(endpoints.as_ref().clone())
}

/// Builds the `/endpoints` reply from the router's OpenAPI document.
pub(crate) fn list_endpoints(openapi: &OpenApi) -> EndpointsResponse {
    let mut by_method = EndpointsByMethod::default();
    for (path, item) in &openapi.paths.paths {
        let entry = || split_path(path);
        let methods: [(&Option<Operation>, &mut Vec<EndpointEntry>); 5] = [
            (&item.get, &mut by_method.get),
            (&item.post, &mut by_method.post),
            (&item.put, &mut by_method.put),
            (&item.patch, &mut by_method.patch),
            (&item.delete, &mut by_method.delete),
        ];
        for (operation, list) in methods {
            if operation.is_some() {
                list.push(entry());
            }
        }
    }
    EndpointsResponse {
        endpoints: by_method,
    }
}

/// `/domains/{type}/{kind}` becomes `/api/domains` + `/{type}/{kind}`, the
/// split of FTL's route table (api.c).
fn split_path(path: &str) -> EndpointEntry {
    let (uri, parameters) = path.find("/{").map_or((path, ""), |at| path.split_at(at));
    EndpointEntry {
        uri: format!("{API_PREFIX}{uri}"),
        parameters: parameters.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_path_moves_path_parameters_to_parameters() {
        let entry = split_path("/domains/{type}/{kind}/{domain}");
        assert_eq!(entry.uri, "/api/domains");
        assert_eq!(entry.parameters, "/{type}/{kind}/{domain}");

        let entry = split_path("/clients:batchDelete");
        assert_eq!(entry.uri, "/api/clients:batchDelete");
        assert_eq!(entry.parameters, "");
    }
}
