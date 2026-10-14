use axum::{
    body::Bytes,
    extract::{FromRequest, FromRequestParts, Path, Request},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
};
use serde::de::DeserializeOwned;
use serde_json::error::Category;

use crate::errors::pihole_error_response;

/// A JSON request body, read whatever its `Content-Type` says.
///
/// FTL parses every body as JSON without looking at the header, and Pi-hole
/// clients rely on it: Homarr posts `JSON.stringify(...)` through `fetch`,
/// which labels the body `text/plain`, where axum's `Json` answers 415.
/// A body that does not parse gets FTL's 400 `bad_request` envelope.
pub struct PiholeJson<T>(pub T);

impl<T, S> FromRequest<S> for PiholeJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?;
        if bytes.is_empty() {
            return Err(bad_request("No request body data", None));
        }
        serde_json::from_slice(&bytes).map(Self).map_err(|err| {
            let message = match err.classify() {
                Category::Data => "Invalid request body data",
                Category::Syntax | Category::Eof | Category::Io => {
                    "Invalid request body data (no valid JSON), error at hint"
                }
            };
            bad_request(message, Some(&err.to_string()))
        })
    }
}

fn bad_request(message: &str, hint: Option<&str>) -> Response {
    pihole_error_response(StatusCode::BAD_REQUEST, "bad_request", message, hint)
}

/// The item a URI names. FTL takes the rest of the URI as the last
/// parameter, so a list address or a client subnet keeps its slashes: the
/// router also matches `{item}/{*rest}`, and the pieces are joined back here.
pub struct UriItem(pub String);

impl<S> FromRequestParts<S> for UriItem
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Path(params) = Path::<Vec<(String, String)>>::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;
        let segments: Vec<String> = params.into_iter().map(|(_, value)| value).collect();
        Ok(Self(segments.join("/")))
    }
}
