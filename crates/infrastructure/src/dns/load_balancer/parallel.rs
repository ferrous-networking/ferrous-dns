use super::query::{all_servers_failed, is_servfail, query_server};
use super::strategy::{QueryContext, UpstreamResult};
use ferrous_dns_domain::DomainError;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::time::Duration;
use tokio::time::timeout;

/// What a pair reports when both servers failed. It returns the second
/// error as before, except that one SERVFAIL next to another kind of failure
/// must not read as "every server answered SERVFAIL".
fn pair_failure(first: &DomainError, second: DomainError) -> DomainError {
    match (is_servfail(first), is_servfail(&second)) {
        (true, true) => DomainError::AllUpstreamsServfail,
        (false, true) => DomainError::TransportAllServersUnreachable,
        _ => second,
    }
}

/// Races every server, taking the first successful answer.
pub(super) async fn query(ctx: &QueryContext<'_>) -> Result<UpstreamResult, DomainError> {
    match ctx.servers {
        [] => Err(DomainError::TransportNoHealthyServers),
        [only] => query_server(ctx, only).await,
        [s0, s1] => {
            // Both futures stay on the stack (no FuturesUnordered allocation). An
            // error from whichever settles first (e.g. a rejected off-path forgery)
            // falls back to the other instead of failing the attempt.
            let race = async {
                let f0 = query_server(ctx, s0);
                let f1 = query_server(ctx, s1);
                tokio::pin!(f0, f1);

                // Re-polling a completed future panics, so remember which settled.
                let (first_idx, first) = tokio::select! {
                    r = &mut f0 => (0u8, r),
                    r = &mut f1 => (1u8, r),
                };
                match first {
                    Ok(r) => Ok(r),
                    Err(first_err) => {
                        let second = if first_idx == 0 {
                            (&mut f1).await
                        } else {
                            (&mut f0).await
                        };
                        second.map_err(|second_err| pair_failure(&first_err, second_err))
                    }
                }
            };

            timeout(Duration::from_millis(ctx.timeout_ms), race)
                .await
                .unwrap_or_else(|_| {
                    Err(DomainError::TransportTimeout {
                        server: "parallel(2 servers)".to_string(),
                    })
                })
        }
        servers => {
            let mut futs: FuturesUnordered<_> = servers
                .iter()
                .map(|protocol| query_server(ctx, protocol))
                .collect();

            let first_success = async {
                let mut all_servfail = true;
                while let Some(result) = futs.next().await {
                    match result {
                        Ok(_) => return result,
                        Err(e) => all_servfail &= is_servfail(&e),
                    }
                }
                Err(all_servers_failed(all_servfail))
            };

            timeout(Duration::from_millis(ctx.timeout_ms), first_success)
                .await
                .unwrap_or_else(|_| {
                    Err(DomainError::TransportTimeout {
                        server: format!("parallel({} servers)", servers.len()),
                    })
                })
        }
    }
}
