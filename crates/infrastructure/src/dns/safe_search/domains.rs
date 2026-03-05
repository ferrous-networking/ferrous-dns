use ferrous_dns_domain::SafeSearchEngine;

/// CNAME target that enforces Safe Search for each engine.
///
/// For YouTube the target depends on the mode configured per group;
/// all other engines have a single fixed target.
pub const fn cname_target(engine: SafeSearchEngine, youtube_strict: bool) -> &'static str {
    match engine {
        SafeSearchEngine::Google => "forcesafesearch.google.com",
        SafeSearchEngine::Bing => "strict.bing.com",
        SafeSearchEngine::YouTube => {
            if youtube_strict {
                "restrict.youtube.com"
            } else {
                "restrictmoderate.youtube.com"
            }
        }
        SafeSearchEngine::DuckDuckGo => "safe.duckduckgo.com",
        SafeSearchEngine::Yandex => "familysearch.yandex.com",
        SafeSearchEngine::Brave => "forcesafe.search.brave.com",
        SafeSearchEngine::Ecosia => "strict-safe-search.ecosia.org",
    }
}

/// All domains that trigger Google Safe Search enforcement.
pub static GOOGLE_DOMAINS: &[&str] = &[
    "google.com",
    "www.google.com",
    "www.google.co.uk",
    "www.google.com.br",
    "www.google.de",
    "www.google.fr",
    "www.google.co.jp",
    "www.google.com.au",
    "www.google.co.in",
    "www.google.ca",
    "www.google.com.mx",
    "www.google.it",
    "www.google.es",
    "www.google.co.id",
    "www.google.com.ar",
    "www.google.com.tr",
    "www.google.pl",
    "www.google.com.sa",
    "www.google.nl",
    "www.google.com.eg",
    "www.google.com.pk",
    "www.google.com.ph",
    "www.google.com.ng",
    "www.google.com.ua",
    "www.google.com.tw",
    "www.google.com.hk",
    "www.google.co.th",
    "www.google.com.co",
    "www.google.com.pe",
    "www.google.com.vn",
    "www.google.co.za",
    "www.google.pt",
    "www.google.be",
    "www.google.at",
    "www.google.ch",
    "www.google.se",
    "www.google.no",
    "www.google.dk",
    "www.google.fi",
    "www.google.gr",
    "www.google.ro",
    "www.google.hu",
    "www.google.cz",
    "www.google.sk",
    "www.google.bg",
    "www.google.hr",
    "www.google.ie",
    "www.google.com.sg",
    "www.google.co.nz",
    "www.google.co.il",
    "www.google.ae",
    "images.google.com",
    "maps.google.com",
    "news.google.com",
];

pub static BING_DOMAINS: &[&str] = &["www.bing.com", "bing.com", "www2.bing.com"];

pub static YOUTUBE_DOMAINS: &[&str] = &[
    "youtube.com",
    "www.youtube.com",
    "m.youtube.com",
    "music.youtube.com",
    "youtubei.googleapis.com",
    "youtube.googleapis.com",
    "www.youtube-nocookie.com",
];

pub static DUCKDUCKGO_DOMAINS: &[&str] = &[
    "duckduckgo.com",
    "www.duckduckgo.com",
    "start.duckduckgo.com",
];

pub static YANDEX_DOMAINS: &[&str] = &[
    "yandex.com",
    "www.yandex.com",
    "yandex.ru",
    "www.yandex.ru",
    "yandex.kz",
    "www.yandex.kz",
    "yandex.by",
    "www.yandex.by",
];

pub static BRAVE_DOMAINS: &[&str] = &["search.brave.com"];

pub static ECOSIA_DOMAINS: &[&str] = &["www.ecosia.org"];

/// Returns the domain list for the given engine.
pub fn domains_for(engine: SafeSearchEngine) -> &'static [&'static str] {
    match engine {
        SafeSearchEngine::Google => GOOGLE_DOMAINS,
        SafeSearchEngine::Bing => BING_DOMAINS,
        SafeSearchEngine::YouTube => YOUTUBE_DOMAINS,
        SafeSearchEngine::DuckDuckGo => DUCKDUCKGO_DOMAINS,
        SafeSearchEngine::Yandex => YANDEX_DOMAINS,
        SafeSearchEngine::Brave => BRAVE_DOMAINS,
        SafeSearchEngine::Ecosia => ECOSIA_DOMAINS,
    }
}
