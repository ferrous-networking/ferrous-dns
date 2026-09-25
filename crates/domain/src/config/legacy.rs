//! Load-time normalisation of values that earlier releases accepted.
//!
//! Earlier releases loaded some values this one rejects: most sat on a
//! disabled feature or were ignored at runtime, and some zeros quietly broke
//! the component they sized. Refusing them would keep an upgraded server (and
//! with it the network's DNS) from starting, so a file load rewrites each one
//! with a warning naming the key: to what those releases effectively ran with
//! where that is harmless, else to the default. A value those releases failed
//! to start or panicked with is left for the typed parse or
//! [`Config::validate`] to reject. The API never goes through this pass, so it
//! keeps rejecting every value handled here.
//!
//! Strings the typed parse would refuse are fixed in the parsed document
//! ([`normalize_document`]); numbers once it is typed ([`normalize_values`]).

use std::fmt::Display;
use std::str::FromStr;

use chrono::{TimeDelta, Utc};
use toml::{Table, Value};
use tracing::warn;

use super::auth::expiry_from_now;
use super::cache_eviction::CacheEvictionStrategy;
use super::dns::DnsConfig;
use super::dns_cookies::{parse_server_secret, DnsCookiesConfig};
use super::encrypted_dns::EncryptedDnsConfig;
use super::root::Config;
use super::server::parse_bind_host;
use crate::DnsProtocol;

/// Rewrites, in the parsed file `doc`, each string value the typed parse
/// would reject but earlier releases ran with.
pub(super) fn normalize_document(doc: &mut Table) {
    ignore_unused_bind_hosts(doc);
    ignore_unused_cookie_secret(doc);
    default_unknown_eviction_strategy(doc);
    disable_unparseable_local_dns_server(doc);
    drop_hostless_upstreams(doc);
}

/// Replaces with its default each number [`Config::validate`] would reject
/// but earlier releases ran with. Zeros those releases panicked on (a
/// zero-period timer or channel, a zero-connection pool, a zero acquire
/// timeout, an invalid shard count) are kept for `validate` to reject unless
/// the feature using them is off.
pub(super) fn normalize_values(config: &mut Config) {
    let defaults = Config::default();
    let (dns, default_dns) = (&mut config.dns, &defaults.dns);

    default_if(
        "dns.query_timeout",
        &mut dns.query_timeout,
        default_dns.query_timeout,
        |&secs| secs == 0 || secs.checked_mul(1000).is_none(),
    );
    default_if(
        "dns.cache_max_entries",
        &mut dns.cache_max_entries,
        default_dns.cache_max_entries,
        is_zero,
    );
    default_if(
        "dns.cache_eviction_sample_size",
        &mut dns.cache_eviction_sample_size,
        default_dns.cache_eviction_sample_size,
        is_zero,
    );
    // Older releases ran compaction only with the cache and optimistic refresh on.
    if !(dns.cache_enabled && dns.cache_optimistic_refresh) {
        default_if(
            "dns.cache_compaction_interval",
            &mut dns.cache_compaction_interval,
            default_dns.cache_compaction_interval,
            is_zero,
        );
    }
    if !dns.cache_enabled {
        for (key, shards, default) in [
            (
                "dns.cache_shard_amount",
                &mut dns.cache_shard_amount,
                default_dns.cache_shard_amount,
            ),
            (
                "dns.cache_inflight_shards",
                &mut dns.cache_inflight_shards,
                default_dns.cache_inflight_shards,
            ),
        ] {
            default_if(key, shards, default, |&n| n < 2 || !n.is_power_of_two());
        }
        let max_ttl = dns.cache_max_ttl;
        default_if(
            "dns.cache_min_ttl",
            &mut dns.cache_min_ttl,
            default_dns.cache_min_ttl,
            |&min| min > max_ttl,
        );
    }
    default_if(
        "dns.health_check.timeout",
        &mut dns.health_check.timeout,
        default_dns.health_check.timeout,
        is_zero,
    );

    let (rate, default_rate) = (&mut dns.rate_limit, &default_dns.rate_limit);
    default_if(
        "dns.rate_limit.queries_per_second",
        &mut rate.queries_per_second,
        default_rate.queries_per_second,
        is_zero,
    );
    default_if(
        "dns.rate_limit.burst_size",
        &mut rate.burst_size,
        default_rate.burst_size,
        is_zero,
    );
    default_if(
        "dns.rate_limit.stale_entry_ttl_secs",
        &mut rate.stale_entry_ttl_secs,
        default_rate.stale_entry_ttl_secs,
        is_zero,
    );
    default_if(
        "dns.tunneling_detection.stale_entry_ttl_secs",
        &mut dns.tunneling_detection.stale_entry_ttl_secs,
        default_dns.tunneling_detection.stale_entry_ttl_secs,
        is_zero,
    );
    default_if(
        "dns.dga_detection.stale_entry_ttl_secs",
        &mut dns.dga_detection.stale_entry_ttl_secs,
        default_dns.dga_detection.stale_entry_ttl_secs,
        is_zero,
    );

    let (hijack, default_hijack) = (&mut dns.nxdomain_hijack, &default_dns.nxdomain_hijack);
    if !hijack.enabled {
        default_if(
            "dns.nxdomain_hijack.probe_interval_secs",
            &mut hijack.probe_interval_secs,
            default_hijack.probe_interval_secs,
            is_zero,
        );
    }
    default_if(
        "dns.nxdomain_hijack.probe_timeout_ms",
        &mut hijack.probe_timeout_ms,
        default_hijack.probe_timeout_ms,
        is_zero,
    );
    default_if(
        "dns.nxdomain_hijack.hijack_ip_ttl_secs",
        &mut hijack.hijack_ip_ttl_secs,
        default_hijack.hijack_ip_ttl_secs,
        is_zero,
    );

    let (ip_filter, default_ip_filter) =
        (&mut dns.response_ip_filter, &default_dns.response_ip_filter);
    default_if(
        "dns.response_ip_filter.refresh_interval_secs",
        &mut ip_filter.refresh_interval_secs,
        default_ip_filter.refresh_interval_secs,
        is_zero,
    );
    default_if(
        "dns.response_ip_filter.ip_ttl_secs",
        &mut ip_filter.ip_ttl_secs,
        default_ip_filter.ip_ttl_secs,
        is_zero,
    );

    default_if(
        "database.query_log_max_batch_size",
        &mut config.database.query_log_max_batch_size,
        defaults.database.query_log_max_batch_size,
        is_zero,
    );

    let (auth, default_auth) = (&mut config.auth, &defaults.auth);
    // A lifetime past year 9999 made older releases store an expiry that the
    // hourly cleanup deleted; one chrono cannot add panicked at login instead.
    let unusable_ttl = |secs: i64| secs <= 0 || (expiry_from_now(secs).is_none() && addable(secs));
    default_if(
        "auth.session_ttl_hours",
        &mut auth.session_ttl_hours,
        default_auth.session_ttl_hours,
        |&hours| unusable_ttl(i64::from(hours) * 3_600),
    );
    default_if(
        "auth.remember_me_days",
        &mut auth.remember_me_days,
        default_auth.remember_me_days,
        |&days| unusable_ttl(i64::from(days) * 86_400),
    );
    default_if(
        "auth.mfa_challenge_ttl_secs",
        &mut auth.mfa_challenge_ttl_secs,
        default_auth.mfa_challenge_ttl_secs,
        |&secs| unusable_ttl(secs),
    );
    default_if(
        "auth.login_rate_limit_window_secs",
        &mut auth.login_rate_limit_window_secs,
        default_auth.login_rate_limit_window_secs,
        is_zero,
    );
}

fn is_zero<T: Default + PartialEq>(value: &T) -> bool {
    *value == T::default()
}

/// Whether chrono can add `secs` to now at all.
fn addable(secs: i64) -> bool {
    TimeDelta::try_seconds(secs)
        .and_then(|ttl| Utc::now().checked_add_signed(ttl))
        .is_some()
}

/// Sets `value` to `default`, with a warning, when `invalid` holds for it.
fn default_if<T: Copy + Display>(
    key: &str,
    value: &mut T,
    default: T,
    invalid: impl FnOnce(&T) -> bool,
) {
    if invalid(value) {
        warn!(
            key,
            value = %value,
            default = %default,
            "Invalid config value: using the default"
        );
        *value = default;
    }
}

/// A listener's own bind address is read only while that listener runs (the
/// dedicated DoH one also needs `doh_port`), so older releases ignored a
/// hostname there. A running listener still fails to load: they failed too.
fn ignore_unused_bind_hosts(doc: &mut Table) {
    let defaults = EncryptedDnsConfig::default();
    let dot = flag(
        doc,
        "server.encrypted_dns.dot_enabled",
        defaults.dot_enabled,
    );
    let doq = flag(
        doc,
        "server.encrypted_dns.doq_enabled",
        defaults.doq_enabled,
    );
    let doh = flag(
        doc,
        "server.encrypted_dns.doh_enabled",
        defaults.doh_enabled,
    ) && get(doc, "server.encrypted_dns.doh_port").is_some();
    for (key, listener_runs) in [
        ("server.encrypted_dns.dot_bind_address", dot),
        ("server.encrypted_dns.doq_bind_address", doq),
        ("server.encrypted_dns.doh_bind_address", doh),
    ] {
        if !listener_runs {
            replace_invalid(
                doc,
                key,
                |host| parse_bind_host(host).is_ok(),
                None,
                Logged::Value,
                "ignoring it because its listener is disabled",
            );
        }
    }
}

/// Older releases read the secret only when cookies are on, and panicked on a
/// malformed one then; so it is ignored only while cookies are off.
fn ignore_unused_cookie_secret(doc: &mut Table) {
    let enabled = DnsCookiesConfig::default().enabled;
    if !flag(doc, "dns.dns_cookies.enabled", enabled) {
        replace_invalid(
            doc,
            "dns.dns_cookies.server_secret",
            |secret| parse_server_secret(secret).is_ok(),
            None,
            Logged::Redacted,
            "ignoring it because DNS cookies are disabled",
        );
    }
}

/// Older releases ran every name but `lfu` and `lfu-k` as `hit_rate`.
fn default_unknown_eviction_strategy(doc: &mut Table) {
    let hit_rate = CacheEvictionStrategy::HitRate.as_str();
    replace_invalid(
        doc,
        "dns.cache_eviction_strategy",
        |name| CacheEvictionStrategy::from_str(name).is_ok(),
        Some(Value::String(hit_rate.to_string())),
        Logged::Value,
        "using hit_rate, the strategy older releases ran for it",
    );
}

/// Older releases started with a hostname here but every query to it failed.
fn disable_unparseable_local_dns_server(doc: &mut Table) {
    replace_invalid(
        doc,
        "dns.local_dns_server",
        |server| DnsConfig::parse_local_dns_server(server).is_ok(),
        None,
        Logged::Value,
        "disabling local forwarding; set the router's IP address or IP:port to enable it",
    );
}

/// Older releases started with an upstream whose host was empty or a broken
/// IPv6 literal (`doq://:853`), and every query to it failed. It is dropped,
/// and so is a pool it leaves without servers.
fn drop_hostless_upstreams(doc: &mut Table) {
    let Some(dns) = doc.get_mut("dns").and_then(Value::as_table_mut) else {
        return;
    };
    if let Some(servers) = dns
        .get_mut("upstream_servers")
        .and_then(Value::as_array_mut)
    {
        drop_hostless("dns.upstream_servers", servers);
    }
    let Some(pools) = dns.get_mut("pools").and_then(Value::as_array_mut) else {
        return;
    };
    pools.retain_mut(|pool| {
        let Some(servers) = pool.get_mut("servers").and_then(Value::as_array_mut) else {
            return true;
        };
        if !drop_hostless("dns.pools.servers", servers) || !servers.is_empty() {
            return true;
        }
        let name = pool.get("name").and_then(Value::as_str).unwrap_or_default();
        warn!(
            key = "dns.pools",
            value = name,
            "Invalid config value: dropping the pool, which has no usable upstream left"
        );
        false
    });
}

/// Removes each server [`is_hostless_upstream`] matches; whether any went.
fn drop_hostless(key: &str, servers: &mut Vec<Value>) -> bool {
    let before = servers.len();
    servers.retain(|server| match server.as_str() {
        Some(server) if is_hostless_upstream(server) => {
            warn!(
                key,
                value = server,
                "Invalid config value: dropping the upstream, which has no usable host"
            );
            false
        }
        _ => true,
    });
    servers.len() != before
}

/// Older releases took any `HOST:PORT` after these schemes, an empty host included.
fn is_hostless_upstream(server: &str) -> bool {
    let Some((scheme, rest)) = server.split_once("://") else {
        return false;
    };
    matches!(scheme, "udp" | "tcp" | "tls" | "doq")
        && rest
            .rsplit_once(':')
            .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
        && server.parse::<DnsProtocol>().is_err()
}

/// Whether a rewritten value may appear in the warning.
#[derive(Clone, Copy)]
enum Logged {
    Value,
    Redacted,
}

/// Replaces the string at dotted `key` when `is_valid` refuses it: with
/// `replacement`, or by removing it so the field takes its default.
fn replace_invalid(
    doc: &mut Table,
    key: &str,
    is_valid: impl Fn(&str) -> bool,
    replacement: Option<Value>,
    logged: Logged,
    instead: &str,
) {
    let Some((section, leaf)) = parent_mut(doc, key) else {
        return;
    };
    let Some(value) = section.get(leaf).and_then(Value::as_str) else {
        return;
    };
    if is_valid(value) {
        return;
    }
    match logged {
        Logged::Value => warn!(key, value, "Invalid config value: {instead}"),
        Logged::Redacted => warn!(key, "Invalid config value: {instead}"),
    }
    match replacement {
        Some(replacement) => section.insert(leaf.to_string(), replacement),
        None => section.remove(leaf),
    };
}

/// The boolean at dotted `key`, or `default` when it is absent. A value of
/// another type is left for the typed parse to reject.
fn flag(doc: &Table, key: &str, default: bool) -> bool {
    get(doc, key).and_then(Value::as_bool).unwrap_or(default)
}

fn get<'a>(doc: &'a Table, key: &str) -> Option<&'a Value> {
    let mut parts = key.split('.');
    let leaf = parts.next_back()?;
    parts
        .try_fold(doc, |table, part| table.get(part)?.as_table())?
        .get(leaf)
}

/// The table holding dotted `key`, and the key's last segment.
fn parent_mut<'a, 'k>(doc: &'a mut Table, key: &'k str) -> Option<(&'a mut Table, &'k str)> {
    let mut parts = key.split('.');
    let leaf = parts.next_back()?;
    let section = parts.try_fold(doc, |table, part| table.get_mut(part)?.as_table_mut())?;
    Some((section, leaf))
}
