//! Issue #271: the admin UI must load on a network without internet access.
//! Every script, stylesheet, font and image a page fetches has to be served by
//! the binary itself, so a page or stylesheet under `web/static` that points at
//! a third-party host fails here.

use std::fs;
use std::path::{Path, PathBuf};

const STATIC_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../web/static");

/// Tags whose `src`/`href` the browser fetches while loading the page. An
/// `<a href>` is only followed on click, so it may point anywhere.
const LOADING_TAGS: [&str; 7] = [
    "<script", "<link", "<img", "<iframe", "<source", "<video", "<audio",
];

fn web_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            web_files(&path, files);
        } else if matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("html" | "css")
        ) {
            files.push(path);
        }
    }
}

/// The value right after `prefix`, unquoted, up to the closing quote or `)`.
fn value_after(text: &str, prefix: &str) -> Vec<String> {
    text.match_indices(prefix)
        .map(|(start, _)| {
            let rest = text[start + prefix.len()..].trim_start();
            match rest.chars().next() {
                Some(quote @ ('"' | '\'')) => rest[1..].split(quote).next().unwrap_or(""),
                _ => rest.split([')', ';', ' ']).next().unwrap_or(""),
            }
            .to_string()
        })
        .collect()
}

/// Every URL the browser fetches on account of `path`: the `src`/`href` of
/// loading tags in HTML, and `url()`/`@import` targets in CSS.
fn fetched_urls(path: &Path) -> Vec<String> {
    let text = fs::read_to_string(path).unwrap();
    if path.extension().is_some_and(|ext| ext == "css") {
        let mut urls = value_after(&text, "url(");
        urls.extend(value_after(&text, "@import \""));
        urls.extend(value_after(&text, "@import '"));
        return urls;
    }
    let mut urls = Vec::new();
    for tag in LOADING_TAGS {
        for (start, _) in text.match_indices(tag) {
            let element = text[start..].split('>').next().unwrap_or("");
            for attribute in [" src=", "\nsrc=", " href=", "\nhref="] {
                urls.extend(value_after(element, attribute));
            }
        }
    }
    urls
}

fn all_fetched_urls() -> Vec<(String, String)> {
    let mut files = Vec::new();
    web_files(Path::new(STATIC_DIR), &mut files);
    files.sort();
    files
        .iter()
        .flat_map(|file| {
            let name = file.strip_prefix(STATIC_DIR).unwrap().display().to_string();
            fetched_urls(file)
                .into_iter()
                .map(move |url| (name.clone(), url))
        })
        .collect()
}

#[test]
fn test_web_assets_load_from_no_third_party_host() {
    let external: Vec<String> = all_fetched_urls()
        .into_iter()
        .filter(|(_, url)| {
            url.starts_with("http://") || url.starts_with("https://") || url.starts_with("//")
        })
        .map(|(file, url)| format!("{file}: {url}"))
        .collect();

    assert!(
        external.is_empty(),
        "web/static fetches from third-party hosts, which breaks the UI offline \
         (vendor the asset under web/static/vendor/ instead):\n{}",
        external.join("\n")
    );
}

#[test]
fn test_web_asset_references_resolve_to_files() {
    let missing: Vec<String> = all_fetched_urls()
        .into_iter()
        .filter_map(|(file, url)| {
            let relative = url.strip_prefix("/static/")?;
            let relative = relative.split(['?', '#']).next().unwrap_or(relative);
            let exists = Path::new(STATIC_DIR).join(relative).is_file();
            (!exists).then(|| format!("{file}: {url}"))
        })
        .collect();

    assert!(
        missing.is_empty(),
        "web/static references files that do not exist:\n{}",
        missing.join("\n")
    );
}
