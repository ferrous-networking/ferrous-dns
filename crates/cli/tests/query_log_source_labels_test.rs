//! Issue #326: the Query Log labelled four kinds of block "Upstream", because
//! `formatSource` in `web/static/queries.js` had no branch for them. A blocked
//! row that reads "Upstream" looks resolved. Browserless JavaScript tests cover
//! localized output; this source check keeps every server block kind represented.

use ferrous_dns_domain::BlockSource;

const QUERIES_JS: &str = include_str!("../../../web/static/queries.js");

/// The body of `formatSource`, up to the `},` that closes it.
fn format_source_body() -> &'static str {
    let start = QUERIES_JS
        .find("formatSource(query) {")
        .expect("queries.js defines formatSource");
    let body = &QUERIES_JS[start..];
    let end = body
        .find("\n            },")
        .expect("formatSource ends with `},` at the object's indentation");
    &body[..end]
}

#[test]
fn test_query_log_labels_every_block_source() {
    let body = format_source_body();
    let unlabelled: Vec<&str> = BlockSource::ALL
        .iter()
        .map(BlockSource::to_str)
        .filter(|name| !body.contains(&format!("'{name}'")))
        .collect();

    assert!(
        unlabelled.is_empty(),
        "formatSource in web/static/queries.js has no label for {unlabelled:?}, \
         so those rows read \"Upstream\""
    );
}

/// A source added later, or a row the API sends without one, still has to
/// read as a block.
#[test]
fn test_query_log_labels_any_other_blocked_row_as_blocked() {
    assert!(
        format_source_body().contains(r#"if (query.blocked) return t("Blocked");"#),
        "formatSource must label any other blocked row \"Blocked\", not \"Upstream\""
    );
}
