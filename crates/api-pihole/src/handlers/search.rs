use std::collections::BTreeSet;

use axum::extract::{Path, Query, State};
use axum::Json;
use ferrous_dns_domain::{
    AllowMatchKind, BlockMatchKind, DomainAction, FilterExplanation, RegexFilter,
};
use serde::Deserialize;

use crate::{
    crud::CrudError,
    dto::lists::ListType,
    dto::search::{
        SearchData, SearchDomainEntry, SearchGravityEntry, SearchParameters, SearchResponse,
        SearchResults, SearchResultsDomains, SearchResultsGravity,
    },
    handlers::{
        domains::{managed_to_entry, regex_to_entry},
        lists::{stored_lists, StoredList},
    },
    state::PiholeAppState,
};

/// search.c's default for `N`.
const DEFAULT_LIMIT: u32 = 20;

/// search.c's `MAX_SEARCH_RESULTS`.
const MAX_SEARCH_RESULTS: u32 = 10_000;

/// The query string, kept as text: FTL ignores a value it cannot parse and
/// keeps the default.
#[derive(Debug, Deserialize)]
pub struct SearchParams {
    pub partial: Option<String>,
    #[serde(rename = "N")]
    pub n: Option<String>,
    pub debug: Option<String>,
}

/// `true` or `false` in any case, as get_bool_var() reads them.
fn parse_bool(raw: Option<&str>) -> Option<bool> {
    match raw? {
        s if s.eq_ignore_ascii_case("true") => Some(true),
        s if s.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

/// The first `limit` rows and how many there were, as search_table() counts
/// every match but returns only the first `N` of each kind.
fn capped<T>(mut rows: Vec<T>, limit: u32) -> (Vec<T>, u64) {
    let count = rows.len() as u64;
    rows.truncate(limit as usize);
    (rows, count)
}

/// The regex filters of one action among `ids`, in table order.
fn regexes_among<'a>(
    regexes: &'a [RegexFilter],
    action: DomainAction,
    ids: &'a BTreeSet<i64>,
) -> impl Iterator<Item = &'a RegexFilter> {
    regexes
        .iter()
        .filter(move |r| r.action == action && r.id.is_some_and(|id| ids.contains(&id)))
}

/// The regex filters and lists that match the domain in any group. FTL
/// tests the domain against every loaded regex and the whole gravity table,
/// whichever groups they belong to.
#[derive(Default)]
struct FilterMatches {
    allow_regexes: BTreeSet<i64>,
    deny_regexes: BTreeSet<i64>,
    blocklists: BTreeSet<i64>,
    allowlists: BTreeSet<i64>,
}

impl FilterMatches {
    /// Matches without a database id (the manual block and allow lists and
    /// managed domains) name no row, so they are left out.
    fn add(&mut self, explanation: FilterExplanation) {
        for m in explanation.block_matches {
            let Some(id) = m.source_id else { continue };
            match m.kind {
                BlockMatchKind::Regex => self.deny_regexes.insert(id),
                BlockMatchKind::Blocklist => self.blocklists.insert(id),
                BlockMatchKind::Manual | BlockMatchKind::ManagedDomain => continue,
            };
        }
        for m in explanation.allow_reasons {
            let Some(id) = m.source_id else { continue };
            match m.kind {
                AllowMatchKind::Regex => self.allow_regexes.insert(id),
                AllowMatchKind::Allowlist => self.allowlists.insert(id),
            };
        }
    }
}

/// Pi-hole v6 GET /api/search/{domain}
///
/// Lists what holds the domain, as FTL's search.c does: exact domain-list
/// entries named by it (disabled ones included), the regex filters that
/// match it, and the block then allow lists that contain it. With
/// `partial=true`, exact entries and regex filters whose text contains the
/// domain are listed too.
///
/// Ferrous searches its compiled filter index rather than a gravity table,
/// so `partial` cannot apply to lists. A list's `domain` is the searched
/// domain, not the list line that matched it. `debug` is accepted and echoed,
/// but adds nothing.
#[utoipa::path(
    get,
    path = "/search/{domain}",
    tag = "pihole:search",
    params(
        ("domain" = String, Path, description = "Domain to search for"),
        ("partial" = Option<bool>, Query, description = "Also match entries containing the domain"),
        ("N" = Option<u32>, Query, description = "Maximum number of rows of each kind (default 20, at most 10000)"),
        ("debug" = Option<bool>, Query, description = "Accepted for compatibility; adds nothing")
    ),
    responses(
        (status = 200, description = "Domain-list entries and lists that hold the domain", body = SearchResponse),
        (status = 400, description = "N is above 10000")
    ),
    security(("session_id" = []))
)]
pub async fn search_domain(
    State(state): State<PiholeAppState>,
    Path(requested): Path<String>,
    Query(params): Query<SearchParams>,
) -> Result<Json<SearchResponse>, CrudError> {
    let partial = parse_bool(params.partial.as_deref()).unwrap_or(false);
    let debug = parse_bool(params.debug.as_deref()).unwrap_or(false);
    let limit = params
        .n
        .as_deref()
        .and_then(|n| n.parse::<u32>().ok())
        .unwrap_or(DEFAULT_LIMIT);
    if limit > MAX_SEARCH_RESULTS {
        return Err(CrudError::bad_request(
            "Invalid request: Requested too many results",
            Some(format!(
                "Requested {limit} number of results but hard upper limit is {MAX_SEARCH_RESULTS}"
            )),
        ));
    }

    // Search the name the DNS path would: no root dot, ASCII-lowercased.
    let domain = requested.trim_end_matches('.').to_ascii_lowercase();
    let is_named = |item: &str| {
        if partial {
            item.to_ascii_lowercase().contains(&domain)
        } else {
            item == domain
        }
    };

    let engine = &state.blocking.block_filter_engine;
    let mut matches = FilterMatches::default();
    for group in state.groups.get_groups.get_all().await? {
        if let Some(group_id) = group.id {
            matches.add(engine.explain(&domain, group_id));
        }
    }

    let mut managed = state.blocking.get_managed_domains.get_all().await?;
    managed.sort_by_key(|d| d.id);
    let exact = managed
        .iter()
        .filter(|d| is_named(&d.domain))
        .map(managed_to_entry)
        .collect::<Result<Vec<_>, _>>()?;

    // Regexes named by the search, then the allow and the deny regexes that
    // match, each in table order; a regex can appear twice, as in FTL.
    let mut regexes = state.blocking.get_regex_filters.get_all().await?;
    regexes.sort_by_key(|r| r.id);
    let named = regexes.iter().filter(|r| partial && is_named(&r.pattern));
    let regex = named
        .chain(regexes_among(
            &regexes,
            DomainAction::Allow,
            &matches.allow_regexes,
        ))
        .chain(regexes_among(
            &regexes,
            DomainAction::Deny,
            &matches.deny_regexes,
        ))
        .map(regex_to_entry)
        .collect::<Result<Vec<_>, _>>()?;

    let lists_holding = |lists: Vec<StoredList>, ids: &BTreeSet<i64>| -> Vec<SearchGravityEntry> {
        lists
            .iter()
            .filter(|l| ids.contains(&l.id))
            .map(|l| SearchGravityEntry {
                domain: domain.clone(),
                list: l.to_entry(),
            })
            .collect()
    };
    let blocklists = lists_holding(
        stored_lists(&state, Some(ListType::Block)).await?,
        &matches.blocklists,
    );
    let allowlists = lists_holding(
        stored_lists(&state, Some(ListType::Allow)).await?,
        &matches.allowlists,
    );

    let (exact, exact_count) = capped(exact, limit);
    let (regex, regex_count) = capped(regex, limit);
    // search.c searches gravity, then antigravity, each up to the limit.
    let (mut gravity, block_count) = capped(blocklists, limit);
    let (allow_gravity, allow_count) = capped(allowlists, limit);
    gravity.extend(allow_gravity);

    Ok(Json(SearchResponse {
        search: SearchData {
            domains: exact
                .into_iter()
                .chain(regex)
                .map(SearchDomainEntry::from)
                .collect(),
            gravity,
            results: SearchResults {
                domains: SearchResultsDomains {
                    exact: exact_count,
                    regex: regex_count,
                },
                gravity: SearchResultsGravity {
                    allow: allow_count,
                    block: block_count,
                },
                total: exact_count + regex_count + block_count + allow_count,
            },
            parameters: SearchParameters {
                n: limit,
                partial,
                domain: requested,
                debug,
            },
        },
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn booleans_are_read_in_any_case_and_anything_else_is_ignored() {
        assert_eq!(parse_bool(Some("TRUE")), Some(true));
        assert_eq!(parse_bool(Some("False")), Some(false));
        assert_eq!(parse_bool(Some("1")), None);
        assert_eq!(parse_bool(None), None);
    }

    #[test]
    fn capping_keeps_the_full_count() {
        assert_eq!(capped(vec![1, 2, 3], 2), (vec![1, 2], 3));
        assert_eq!(capped(vec![1], 0), (vec![], 1));
    }
}
