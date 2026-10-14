use std::convert::Infallible;
use std::future::ready;

use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use ferrous_dns_domain::DomainError;
use futures::stream::{self, StreamExt};
use serde::Deserialize;
use tracing::error;

use crate::{dto::action::ActionResponse, errors::PiholeApiError, state::PiholeAppState};

/// The query string of `/action/gravity`, kept as text: FTL reads `color`
/// with get_bool_var(), which ignores a value other than true or false.
#[derive(Debug, Deserialize)]
pub struct GravityParams {
    pub color: Option<String>,
}

/// The step markers of pihole's COL_TABLE, colored only when FTL passes
/// `FORCE_COLOR` (`?color=true`).
struct Markers {
    info: &'static str,
    tick: &'static str,
    cross: &'static str,
}

impl Markers {
    fn new(color: bool) -> Self {
        if color {
            Self {
                info: "[i]",
                tick: "[\x1b[32m✓\x1b[0m]",
                cross: "[\x1b[91m✗\x1b[0m]",
            }
        } else {
            Self {
                info: "[i]",
                tick: "[✓]",
                cross: "[✗]",
            }
        }
    }
}

const GRAVITY_STEP: &str = "Downloading the blocklists and rebuilding the block filter";

fn gravity_started(m: &Markers) -> String {
    format!("  {} {GRAVITY_STEP}...\n", m.info)
}

/// The lines after the reload: its outcome and, as pihole -g ends, the
/// number of domains now blocked.
fn gravity_finished(m: &Markers, outcome: Option<usize>) -> String {
    match outcome {
        Some(domains) => format!(
            "  {} {GRAVITY_STEP}\n  {} Number of gravity domains: {domains}\n",
            m.tick, m.info
        ),
        None => format!("  {} Unable to rebuild the block filter\n", m.cross),
    }
}

/// Pi-hole v6 POST /api/action/gravity — download the blocklists again and
/// rebuild the block filter, streaming progress as `pihole -g` does.
///
/// FTL answers 200 before gravity runs and reports a failure in the text
/// only, so does this.
#[utoipa::path(
    post,
    path = "/action/gravity",
    tag = "pihole:action",
    params(
        ("color" = Option<bool>, Query, description = "Color the step markers with ANSI escape codes (default false)")
    ),
    responses(
        (status = 200, description = "Progress of the reload, streamed as plain text", body = String, content_type = "text/plain")
    ),
    security(("session_id" = []))
)]
pub async fn gravity(
    State(state): State<PiholeAppState>,
    Query(params): Query<GravityParams>,
) -> Response {
    let color = params
        .color
        .as_deref()
        .is_some_and(|c| c.eq_ignore_ascii_case("true"));
    let markers = Markers::new(color);
    let engine = state.blocking.block_filter_engine.clone();

    // Started before the reply so a client leaving early cannot cancel it.
    let reload = tokio::spawn(async move {
        engine.refresh_lists().await?;
        Ok::<_, DomainError>(engine.compiled_domain_count())
    });

    let started = gravity_started(&markers);
    let finished = async move {
        let outcome = match reload.await {
            Ok(Ok(domains)) => Some(domains),
            Ok(Err(err)) => {
                error!(error = %err, "Pi-hole gravity reload failed");
                None
            }
            Err(err) => {
                error!(error = %err, "Pi-hole gravity reload task failed");
                None
            }
        };
        gravity_finished(&markers, outcome)
    };
    let body = stream::once(ready(started))
        .chain(stream::once(finished))
        .map(Ok::<_, Infallible>);

    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        Body::from_stream(body),
    )
        .into_response()
}

/// Pi-hole v6 POST /api/action/restartdns — reload configuration.
///
/// Re-reads the config file like `POST /api/config/reload`: command-line
/// overrides re-applied, upstream pools hot-reloaded. No process restart.
#[utoipa::path(
    post,
    path = "/action/restartdns",
    tag = "pihole:action",
    responses(
        (status = 200, description = "Configuration reloaded", body = ActionResponse),
        (status = 500, description = "Reload failed")
    ),
    security(("session_id" = []))
)]
pub async fn restartdns(
    State(state): State<PiholeAppState>,
) -> Result<Json<ActionResponse>, PiholeApiError> {
    if let Some(reload) = state.system.reload_config.clone() {
        reload.execute().await?;
    }

    Ok(Json(ActionResponse::success()))
}

/// Pi-hole v6 POST /api/action/flush/logs — delete the stored queries.
///
/// FTL deletes every query stored up to now, not only the last 24 hours
/// (log.c flush_dnsmasq_log), and the history built from them; the minute
/// rollups go with the rows.
#[utoipa::path(
    post,
    path = "/action/flush/logs",
    tag = "pihole:action",
    responses(
        (status = 200, description = "Query logs flushed", body = ActionResponse),
        (status = 500, description = "Flush failed")
    ),
    security(("session_id" = []))
)]
pub async fn flush_logs(
    State(state): State<PiholeAppState>,
) -> Result<Json<ActionResponse>, PiholeApiError> {
    state.system.cleanup_query_logs.execute(0).await?;
    Ok(Json(ActionResponse::success()))
}

#[cfg(test)]
mod tests {
    use super::{gravity_finished, gravity_started, Markers};

    #[test]
    fn gravity_reports_the_domain_count_after_a_reload() {
        let m = Markers::new(false);
        assert_eq!(
            gravity_started(&m),
            "  [i] Downloading the blocklists and rebuilding the block filter...\n"
        );
        assert_eq!(
            gravity_finished(&m, Some(42)),
            "  [✓] Downloading the blocklists and rebuilding the block filter\n  \
             [i] Number of gravity domains: 42\n"
        );
    }

    #[test]
    fn gravity_reports_a_failed_reload_without_its_error_text() {
        assert_eq!(
            gravity_finished(&Markers::new(false), None),
            "  [✗] Unable to rebuild the block filter\n"
        );
        assert_eq!(
            gravity_finished(&Markers::new(true), None),
            "  [\x1b[91m✗\x1b[0m] Unable to rebuild the block filter\n"
        );
    }
}
