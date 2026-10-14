use std::path::PathBuf;

use axum::extract::State;
use axum::Json;
use ferrous_dns_domain::{DomainAction, DomainError};

use crate::{
    dto::info::{
        AllowedDenied, ComponentVersion, DatabaseInfoResponse, DnsmasqMetrics, DockerVersion,
        FtlClients, FtlComponentVersion, FtlDatabaseInfo, FtlInfo, FtlInfoResponse,
        FtlLocalVersion, HostInfoResponse, LocalVersion, LoginInfoResponse, RemoteVersion,
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
    Json(VersionResponse {
        version: VersionComponents {
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
        },
    })
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
    let (groups, blocklists, allowlists, domains, regexes, clients) = tokio::try_join!(
        state.groups.get_groups.get_all(),
        state.lists.get_blocklist_sources.get_all(),
        state.lists.get_whitelist_sources.get_all(),
        state.blocking.get_managed_domains.get_all(),
        state.blocking.get_regex_filters.get_all(),
        state.clients.get_clients.get_stats(),
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
            query_frequency: 0.0,
            clients: FtlClients {
                total: clients.total_clients,
                active: clients.active_24h,
            },
            pid: std::process::id(),
            uptime: state.system.process_start.elapsed().as_millis() as u64,
            mem_percent,
            cpu_percent: 0.0,
            allow_destructive: true,
            dnsmasq: DnsmasqMetrics::default(),
        },
    }))
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
