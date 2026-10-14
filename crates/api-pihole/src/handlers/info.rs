use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;

use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, Method, Version};
use axum::response::Response;
use axum::{Extension, Json};
use ferrous_dns_domain::{Config, DomainAction, DomainError};

use crate::{
    crud::delete_reply,
    dto::info::{
        AllowedDenied, CacheMetrics, ClientInfoResponse, ComponentVersion, CountResponse,
        DatabaseInfoResponse, DhcpMetrics, DnsMetrics, DnsmasqMetrics, DockerVersion, FtlClients,
        FtlComponentVersion, FtlDatabaseInfo, FtlInfo, FtlInfoResponse, FtlLocalVersion,
        HostInfoResponse, HttpHeader, LocalVersion, LoginInfoResponse, MessagesResponse, Metrics,
        MetricsResponse, RemoteVersion, ReplyMetrics, SensorsInfo, SensorsResponse,
        SystemInfoResponse, TotalEnabled, VersionComponents, VersionResponse,
    },
    errors::PiholeApiError,
    host,
    state::PiholeAppState,
};

use super::stats::STATS_PERIOD_HOURS;

/// Pi-hole v6 GET /api/info/login
///
/// Public, as in FTL: clients such as Homarr probe it to tell Pi-hole v6
/// from v5, which has no such route. Ferrous does not track a failed DNS
/// listener, so `dns` is always true.
#[utoipa::path(
    get,
    path = "/info/login",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Login page info", body = LoginInfoResponse)
    ),
    security()
)]
pub async fn get_login_info(State(state): State<PiholeAppState>) -> Json<LoginInfoResponse> {
    Json(LoginInfoResponse {
        dns: true,
        https_port: state.system.https_port,
    })
}

/// Pi-hole v6 GET /api/info/client
///
/// Public, as in FTL: the caller's address, HTTP version, method and
/// headers, as the server received them.
#[utoipa::path(
    get,
    path = "/info/client",
    tag = "pihole:info",
    responses(
        (status = 200, description = "The request as received", body = ClientInfoResponse)
    ),
    security()
)]
pub async fn get_client_info(
    connect_info: Option<Extension<ConnectInfo<SocketAddr>>>,
    method: Method,
    version: Version,
    headers: HeaderMap,
) -> Json<ClientInfoResponse> {
    let remote_addr = connect_info.map_or(Ipv4Addr::UNSPECIFIED.into(), |info| info.0 .0.ip());
    Json(ClientInfoResponse {
        remote_addr: remote_addr.to_string(),
        http_version: http_version(version).to_string(),
        method: method.to_string(),
        headers: headers
            .iter()
            .map(|(name, value)| HttpHeader {
                name: name.to_string(),
                value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
            })
            .collect(),
    })
}

/// The version as CivetWeb reports it, without the `HTTP/` prefix.
fn http_version(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_2 => "2",
        Version::HTTP_3 => "3",
        _ => "1.1",
    }
}

/// Pi-hole v6 GET /api/info/messages
///
/// FTL's diagnosis messages report dnsmasq and gravity warnings; Ferrous
/// raises none, so the list is empty. A list that failed to download shows
/// in the `status` of `/lists` instead.
#[utoipa::path(
    get,
    path = "/info/messages",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Diagnosis messages, always none", body = MessagesResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_messages() -> Json<MessagesResponse> {
    Json(MessagesResponse {
        messages: Vec::new(),
    })
}

/// Pi-hole v6 GET /api/info/sensors
///
/// Every hwmon chip with its temperatures, and the CPU's picked out, as FTL
/// reads them from `/sys/class/hwmon`.
#[utoipa::path(
    get,
    path = "/info/sensors",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Temperature sensors", body = SensorsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_sensors() -> Result<Json<SensorsResponse>, PiholeApiError> {
    let list = tokio::task::spawn_blocking(host::read_hwmon)
        .await
        .map_err(|e| DomainError::IoError(e.to_string()))?;
    Ok(Json(SensorsResponse {
        sensors: SensorsInfo {
            cpu_temp: host::cpu_temp(&list),
            list,
            hot_limit: host::HOT_LIMIT,
            unit: host::TEMPERATURE_UNIT,
        },
    }))
}

/// Pi-hole v6 GET /api/info/messages/count
#[utoipa::path(
    get,
    path = "/info/messages/count",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Number of diagnosis messages, always 0", body = CountResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_messages_count() -> Json<CountResponse> {
    Json(CountResponse { count: 0 })
}

/// Pi-hole v6 DELETE /api/info/messages/{ids}
///
/// There is never a message to delete, so this is FTL's 404 with `{}` for
/// ids that name none.
#[utoipa::path(
    delete,
    path = "/info/messages/{ids}",
    tag = "pihole:info",
    params(("ids" = String, Path, description = "Message id, or comma-separated ids")),
    responses(
        (status = 404, description = "No such message")
    ),
    security(("session_id" = []))
)]
pub async fn delete_messages(Path(_ids): Path<String>) -> Response {
    delete_reply(0)
}

/// Pi-hole v6 GET /api/info/version
#[utoipa::path(
    get,
    path = "/info/version",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Version info", body = VersionResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: version_components(),
    })
}

/// Ferrous's version as each Pi-hole component; `/padd` embeds it too.
pub(crate) fn version_components() -> VersionComponents {
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    let hash = option_env!("GIT_HASH").map(str::to_owned);
    let component = || ComponentVersion {
        local: LocalVersion {
            branch: "main".to_string(),
            version: version.clone(),
            hash: hash.clone(),
        },
        remote: RemoteVersion {
            version: version.clone(),
            hash: hash.clone(),
        },
    };
    VersionComponents {
        core: component(),
        web: component(),
        ftl: FtlComponentVersion {
            local: FtlLocalVersion {
                branch: "main".to_string(),
                version: version.clone(),
                hash: hash.clone(),
                date: None,
            },
            remote: RemoteVersion {
                version: version.clone(),
                hash: hash.clone(),
            },
        },
        docker: DockerVersion {
            local: None,
            remote: None,
        },
    }
}

/// Pi-hole v6 GET /api/info/ftl
#[utoipa::path(
    get,
    path = "/info/ftl",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Resolver process info and configuration counts", body = FtlInfoResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_ftl_info(
    State(state): State<PiholeAppState>,
) -> Result<Json<FtlInfoResponse>, PiholeApiError> {
    let (groups, blocklists, allowlists, domains, regexes, clients, query_frequency) = tokio::try_join!(
        state.groups.get_groups.get_all(),
        state.lists.get_blocklist_sources.get_all(),
        state.lists.get_whitelist_sources.get_all(),
        state.blocking.get_managed_domains.get_all(),
        state.blocking.get_regex_filters.get_all(),
        state.clients.get_clients.get_stats(),
        super::stats::query_frequency(&state),
    )?;
    let mem_percent = tokio::task::spawn_blocking(host::read_process_mem_percent)
        .await
        .map_err(|e| DomainError::IoError(e.to_string()))?;

    Ok(Json(FtlInfoResponse {
        ftl: FtlInfo {
            database: FtlDatabaseInfo {
                gravity: state.blocking.block_filter_engine.compiled_domain_count() as u64,
                antigravity: 0,
                groups: groups.len() as u64,
                lists: (blocklists.len() + allowlists.len()) as u64,
                clients: clients.total_clients,
                domains: count_by_action(domains.iter().map(|d| (d.action, d.enabled))),
                regex: count_by_action(regexes.iter().map(|r| (r.action, r.enabled))),
            },
            privacy_level: 0,
            query_frequency,
            clients: FtlClients {
                total: clients.total_clients,
                active: clients.active_24h,
            },
            pid: std::process::id(),
            uptime: state.system.process_start.elapsed().as_millis() as u64,
            mem_percent,
            cpu_percent: 0.0,
            allow_destructive: true,
            dnsmasq: dnsmasq_metrics(&state),
        },
    }))
}

/// The dnsmasq counters Ferrous's cache has an equivalent for: entries
/// inserted, and live entries freed before their expiry.
fn dnsmasq_metrics(state: &PiholeAppState) -> DnsmasqMetrics {
    let cache = state.system.dns_cache.cache_metrics_snapshot();
    DnsmasqMetrics {
        dns_cache_inserted: cache.insertions,
        dns_cache_live_freed: cache.evictions,
        ..DnsmasqMetrics::default()
    }
}

/// dnsmasq's `cache-size`: the configured capacity, 0 with the cache off.
pub(crate) fn cache_capacity(config: &Config) -> u64 {
    if config.dns.cache_enabled {
        config.dns.cache_max_entries as u64
    } else {
        0
    }
}

/// Pi-hole v6 GET /api/info/metrics
///
/// dnsmasq's cache and reply counters and its DHCP counters (info.c
/// api_info_metrics). The cache figures come from Ferrous's cache; the
/// per-type content, the reply counters and DHCP have no equivalent and stay
/// empty or 0.
#[utoipa::path(
    get,
    path = "/info/metrics",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Cache, reply and DHCP counters", body = MetricsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_metrics(State(state): State<PiholeAppState>) -> Json<MetricsResponse> {
    let size = cache_capacity(&*state.system.config.read().await);
    let cache = state.system.dns_cache.cache_metrics_snapshot();
    Json(MetricsResponse {
        metrics: Metrics {
            dns: DnsMetrics {
                cache: CacheMetrics {
                    size,
                    inserted: cache.insertions,
                    evicted: cache.evictions,
                    expired: cache.lazy_deletions,
                    immortal: 0,
                    content: Vec::new(),
                },
                replies: ReplyMetrics::default(),
            },
            dhcp: DhcpMetrics::default(),
        },
    })
}

/// Tallies `(action, enabled)` pairs into FTL's allowed/denied totals.
fn count_by_action(entries: impl Iterator<Item = (DomainAction, bool)>) -> AllowedDenied {
    let mut allowed = TotalEnabled::default();
    let mut denied = TotalEnabled::default();
    for (action, enabled) in entries {
        let counts = match action {
            DomainAction::Allow => &mut allowed,
            DomainAction::Deny => &mut denied,
        };
        counts.total += 1;
        counts.enabled += u64::from(enabled);
    }
    AllowedDenied { allowed, denied }
}

/// Pi-hole v6 GET /api/info/system
#[utoipa::path(
    get,
    path = "/info/system",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Host uptime, memory (kB), processes and load", body = SystemInfoResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_system_info() -> Result<Json<SystemInfoResponse>, PiholeApiError> {
    let system = tokio::task::spawn_blocking(host::read_system)
        .await
        .map_err(|e| DomainError::IoError(e.to_string()))?;
    Ok(Json(SystemInfoResponse { system }))
}

/// Pi-hole v6 GET /api/info/host
#[utoipa::path(
    get,
    path = "/info/host",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Kernel uname, device model and DMI identifiers", body = HostInfoResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_host_info() -> Result<Json<HostInfoResponse>, PiholeApiError> {
    let host = tokio::task::spawn_blocking(host::read_host)
        .await
        .map_err(|e| DomainError::IoError(e.to_string()))?;
    Ok(Json(HostInfoResponse { host }))
}

/// Pi-hole v6 GET /api/info/database
#[utoipa::path(
    get,
    path = "/info/database",
    tag = "pihole:info",
    responses(
        (status = 200, description = "Database file and stored query counts", body = DatabaseInfoResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_database_info(
    State(state): State<PiholeAppState>,
) -> Result<Json<DatabaseInfoResponse>, PiholeApiError> {
    let path = PathBuf::from(&state.system.config.read().await.database.path);
    let file = tokio::task::spawn_blocking(move || host::read_database_file(&path))
        .await
        .map_err(|e| DomainError::IoError(e.to_string()))?;
    let storage = state
        .query
        .get_query_log_storage
        .execute(STATS_PERIOD_HOURS)
        .await?;

    Ok(Json(DatabaseInfoResponse {
        size: file.size,
        file_type: file.file_type.to_string(),
        mode: file.mode,
        atime: file.atime,
        mtime: file.mtime,
        ctime: file.ctime,
        owner: file.owner,
        queries: storage.recent_queries,
        earliest_timestamp: storage.recent_earliest,
        queries_disk: storage.stored_queries,
        earliest_timestamp_disk: storage.stored_earliest,
        sqlite_version: storage.sqlite_version,
    }))
}
