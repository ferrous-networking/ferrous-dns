//! Integration tests for the precedence of rules the operator wrote themselves,
//! driven through the public `BlockFilterEnginePort` surface.
//!
//! A manual rule is the highest-priority signal in the pipeline: it outranks the
//! global blocking toggle and every schedule override, and a manual *allow* is
//! reported as `FilterDecision::ExplicitAllow` so that the heuristic detectors in
//! `HandleDnsQueryUseCase` (tunneling, DGA, rebinding, NXDOMAIN hijack,
//! response-IP filtering) can skip the domain. Without that signal there is no
//! way to clear a false positive from those detectors short of editing the TOML
//! and restarting.
//!
//! A hit from a *downloaded* blocklist is deliberately not part of that tier and
//! still yields to the toggle and to schedules, which is what
//! `yields_to_the_blocking_toggle` pins down.

use ferrous_dns_application::ports::{BlockFilterEnginePort, FilterDecision, ScheduleStatePort};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::{BlockSource, GroupOverride};
use ferrous_dns_infrastructure::database::create_write_pool;
use ferrous_dns_infrastructure::dns::BlockFilterEngine;
use ferrous_dns_infrastructure::schedule::ScheduleStateStore;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// The seeded `groups` row is `id = 1, is_default = 1`.
const DEFAULT_GROUP_ID: i64 = 1;

/// Allowed by the global `whitelist` table.
const WHITELISTED: &str = "listed.allow-example.test";
/// Allowed by a `managed_domains` row with `action = 'allow'`.
const MANAGED_ALLOWED: &str = "managed.allow-example.test";
/// Allowed by a `regex_filters` row with `action = 'allow'`.
const REGEX_ALLOWED: &str = "regex-allowed.example.test";

/// Denied by the manual `blocklist` table.
const MANUAL_DENIED: &str = "manual.deny-example.test";
/// Denied by a `managed_domains` row with `action = 'deny'`.
const MANAGED_DENIED: &str = "managed.deny-example.test";

/// Denied by an imported blocklist source — the non-manual tier.
const DOWNLOAD_DENIED: &str = "downloaded.deny-example.test";

/// On the imported list *and* matched by a deny regex. The manual rule has to
/// win, or pausing blocking would release it.
const OVERLAPPING_DENIED: &str = "overlap.deny-example.test";

/// No rule of any kind names this one.
const UNRULED: &str = "nothing.knows-example.test";

const LIST: &str = "# manual-priority fixture\n\
downloaded.deny-example.test\n\
overlap.deny-example.test\n";

/// Serves a blocklist over HTTP for as long as it is alive. Blocklist sources
/// are fetched by URL, so this is the only way to get a rule into the index that
/// the operator did not type in themselves.
struct ListServer {
    url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for ListServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn serve_list(body: &'static str) -> ListServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stub list server");
    let addr = listener.local_addr().expect("stub list server address");

    // `BlockFilterEngine::new` compiles once in the background and `reload`
    // compiles again, so the server has to answer more than one request.
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut scratch = [0u8; 2048];
                let _ = stream.read(&mut scratch).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    ListServer {
        url: format!("http://{addr}/blocklist.txt"),
        handle,
    }
}

struct Harness {
    engine: Arc<BlockFilterEngine>,
    schedule: Arc<ScheduleStateStore>,
    _server: ListServer,
    _dir: tempfile::TempDir,
}

impl Harness {
    #[track_caller]
    fn check(&self, domain: &str) -> FilterDecision {
        self.engine.check(domain, DEFAULT_GROUP_ID)
    }
}

async fn seed_rules(pool: &SqlitePool, list_url: &str) {
    sqlx::query("INSERT INTO whitelist (domain) VALUES (?)")
        .bind(WHITELISTED)
        .execute(pool)
        .await
        .expect("seed whitelist row");

    sqlx::query("INSERT INTO blocklist (domain) VALUES (?)")
        .bind(MANUAL_DENIED)
        .execute(pool)
        .await
        .expect("seed manual blocklist row");

    for (name, domain, action) in [
        ("allow-fixture", MANAGED_ALLOWED, "allow"),
        ("deny-fixture", MANAGED_DENIED, "deny"),
    ] {
        sqlx::query(
            "INSERT INTO managed_domains
                 (name, domain, action, group_id, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, 1, '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z')",
        )
        .bind(name)
        .bind(domain)
        .bind(action)
        .bind(DEFAULT_GROUP_ID)
        .execute(pool)
        .await
        .expect("seed managed domain row");
    }

    sqlx::query(
        "INSERT INTO regex_filters
             (name, pattern, action, group_id, enabled, created_at, updated_at)
         VALUES ('allow-regex-fixture', ?, 'allow', ?, 1,
                 '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z')",
    )
    .bind(format!("^{}$", REGEX_ALLOWED.replace('.', "\\.")))
    .bind(DEFAULT_GROUP_ID)
    .execute(pool)
    .await
    .expect("seed allow regex row");

    sqlx::query(
        "INSERT INTO regex_filters
             (name, pattern, action, group_id, enabled, created_at, updated_at)
         VALUES ('deny-regex-fixture', ?, 'deny', ?, 1,
                 '2026-08-01T00:00:00Z', '2026-08-01T00:00:00Z')",
    )
    .bind(format!("^{}$", OVERLAPPING_DENIED.replace('.', "\\.")))
    .bind(DEFAULT_GROUP_ID)
    .execute(pool)
    .await
    .expect("seed deny regex row");

    sqlx::query(
        "INSERT INTO blocklist_sources (name, url, group_id, enabled)
         VALUES ('manual-priority-fixture', ?, ?, 1)",
    )
    .bind(list_url)
    .bind(DEFAULT_GROUP_ID)
    .execute(pool)
    .await
    .expect("seed blocklist source");

    // The group pivot is what grants the source's bit to the group mask;
    // without it every rule in the list compiles but matches no group.
    sqlx::query(
        "INSERT INTO blocklist_source_groups (source_id, group_id)
         SELECT id, ? FROM blocklist_sources WHERE name = 'manual-priority-fixture'",
    )
    .bind(DEFAULT_GROUP_ID)
    .execute(pool)
    .await
    .expect("assign source to the default group");
}

/// Builds a real engine over a fresh migrated temp DB carrying one rule of every
/// kind, so a single compiled index can answer every precedence question.
async fn build_harness() -> Harness {
    let server = serve_list(LIST).await;

    let dir = tempfile::tempdir().expect("tempdir");
    let url = format!("sqlite:{}", dir.path().join("test.db").display());
    let pool = create_write_pool(&url, &DatabaseConfig::default())
        .await
        .expect("create pool + run migrations");

    seed_rules(&pool, &server.url).await;

    let schedule = Arc::new(ScheduleStateStore::new());
    let engine = BlockFilterEngine::new(
        pool,
        DEFAULT_GROUP_ID,
        Arc::clone(&schedule) as Arc<dyn ScheduleStatePort>,
        true,
    )
    .await
    .expect("build engine");

    // `new` kicks compilation off in a background task, so the index is still
    // empty on return. `reload` compiles inline and awaits it, which makes the
    // index deterministically ready here without sleeping.
    engine.reload().await.expect("compile block index");

    Harness {
        engine,
        schedule,
        _server: server,
        _dir: dir,
    }
}

#[tokio::test]
async fn every_manual_allow_source_reports_an_explicit_allow() {
    let h = build_harness().await;

    for (domain, source) in [
        (WHITELISTED, "the global whitelist table"),
        (MANAGED_ALLOWED, "an allow-type managed domain"),
        (REGEX_ALLOWED, "an allow-type regex filter"),
    ] {
        assert_eq!(
            h.check(domain),
            FilterDecision::ExplicitAllow,
            "{source} must report an explicit allow, not a plain one — the \
             heuristic detectors key their exemption off the difference"
        );
    }

    assert_eq!(
        h.check(UNRULED),
        FilterDecision::Allow,
        "a domain no rule names must be a plain allow, otherwise every domain \
         would be exempt from the detectors"
    );
}

#[tokio::test]
async fn manual_rules_apply_with_no_override_in_force() {
    let h = build_harness().await;

    assert_eq!(
        h.check(MANUAL_DENIED),
        FilterDecision::Block(BlockSource::Blocklist),
        "a manual blocklist entry must be blocked"
    );
    assert_eq!(
        h.check(MANAGED_DENIED),
        FilterDecision::Block(BlockSource::ManagedDomain),
        "a deny-type managed domain must be blocked"
    );
    assert_eq!(
        h.check(DOWNLOAD_DENIED),
        FilterDecision::Block(BlockSource::Blocklist),
        "an imported list entry must be blocked"
    );
}

/// A domain covered by both a downloaded list and a deny regex used to come back
/// as a plain list block, because the regex scan ran only after the list lookup
/// missed. Pausing blocking then released it, discarding the manual rule.
#[tokio::test]
async fn a_deny_regex_outranks_the_list_it_overlaps() {
    let h = build_harness().await;

    assert_eq!(
        h.check(OVERLAPPING_DENIED),
        FilterDecision::Block(BlockSource::RegexFilter),
        "the manual regex must be the reported source, not the imported list"
    );

    h.engine.set_blocking_enabled(false);
    assert_eq!(
        h.check(OVERLAPPING_DENIED),
        FilterDecision::Block(BlockSource::RegexFilter),
        "pausing blocking must not release a domain a deny regex names, even \
         though an imported list also covers it"
    );
}

#[tokio::test]
async fn manual_deny_survives_the_global_blocking_toggle() {
    let h = build_harness().await;
    h.engine.set_blocking_enabled(false);

    assert_eq!(
        h.check(MANUAL_DENIED),
        FilterDecision::Block(BlockSource::Blocklist),
        "pausing blocking must not release a domain the operator denied by hand"
    );
    assert_eq!(
        h.check(MANAGED_DENIED),
        FilterDecision::Block(BlockSource::ManagedDomain),
        "pausing blocking must not release a deny-type managed domain"
    );
    assert_eq!(
        h.check(DOWNLOAD_DENIED),
        FilterDecision::Allow,
        "a downloaded list entry is not a manual rule and must yield to the toggle"
    );
    assert_eq!(h.check(UNRULED), FilterDecision::Allow);
}

#[tokio::test]
async fn manual_deny_survives_a_scheduled_allow_all() {
    let h = build_harness().await;
    h.schedule.set(DEFAULT_GROUP_ID, GroupOverride::AllowAll);

    assert_eq!(
        h.check(MANUAL_DENIED),
        FilterDecision::Block(BlockSource::Blocklist),
        "a scheduled bypass must not release a domain the operator denied by hand"
    );
    assert_eq!(
        h.check(MANAGED_DENIED),
        FilterDecision::Block(BlockSource::ManagedDomain),
        "a scheduled bypass must not release a deny-type managed domain"
    );
    assert_eq!(
        h.check(DOWNLOAD_DENIED),
        FilterDecision::Allow,
        "a downloaded list entry must still yield to the bypass window"
    );
}

#[tokio::test]
async fn manual_allow_survives_a_scheduled_block_all() {
    let h = build_harness().await;
    h.schedule.set(DEFAULT_GROUP_ID, GroupOverride::BlockAll);

    for domain in [WHITELISTED, MANAGED_ALLOWED, REGEX_ALLOWED] {
        assert_eq!(
            h.check(domain),
            FilterDecision::ExplicitAllow,
            "{domain}: a block-everything schedule must not override an explicit allow"
        );
    }

    assert_eq!(
        h.check(UNRULED),
        FilterDecision::Block(BlockSource::Schedule),
        "the schedule must still block everything it was not overruled on"
    );
}

/// A bypass window that has lapsed must not leave the group permanently allowed
/// through a stale memoized verdict, and must not swallow manual rules either.
#[tokio::test]
async fn an_expired_timed_bypass_falls_back_to_the_compiled_rules() {
    let h = build_harness().await;

    h.schedule
        .set(DEFAULT_GROUP_ID, GroupOverride::TimedBypassUntil(u64::MAX));
    assert_eq!(
        h.check(DOWNLOAD_DENIED),
        FilterDecision::Allow,
        "an active bypass releases non-manual rules"
    );

    h.schedule
        .set(DEFAULT_GROUP_ID, GroupOverride::TimedBypassUntil(0));
    assert_eq!(
        h.check(DOWNLOAD_DENIED),
        FilterDecision::Block(BlockSource::Blocklist),
        "once the bypass lapses the imported rule applies again"
    );
    assert_eq!(
        h.check(WHITELISTED),
        FilterDecision::ExplicitAllow,
        "a lapsed bypass must not downgrade an explicit allow"
    );
}
