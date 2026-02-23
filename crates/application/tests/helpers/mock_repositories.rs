#![allow(dead_code)]
#![allow(unused_imports)]

use async_trait::async_trait;
use ferrous_dns_application::ports::{
    BlockFilterEnginePort, BlocklistRepository, BlocklistSourceRepository, ClientRepository,
    DnsResolution, DnsResolver, FilterDecision, GroupRepository, ManagedDomainRepository,
    QueryLogRepository, TimeGranularity, WhitelistRepository, WhitelistSourceRepository,
};
use ferrous_dns_domain::{
    blocklist::BlockedDomain, BlockSource, BlocklistSource, Client, ClientStats, DnsQuery,
    DomainAction, DomainError, Group, ManagedDomain, QueryLog, QueryStats, RecordType,
    WhitelistSource, WhitelistedDomain,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct MockDnsResolver {
    responses: Arc<RwLock<HashMap<String, DnsResolution>>>,
    should_fail: Arc<RwLock<bool>>,
    cache_responses: Arc<std::sync::RwLock<HashMap<String, DnsResolution>>>,
    error_responses: Arc<std::sync::RwLock<HashMap<String, DomainError>>>,
}

impl MockDnsResolver {
    pub fn new() -> Self {
        Self {
            responses: Arc::new(RwLock::new(HashMap::new())),
            should_fail: Arc::new(RwLock::new(false)),
            cache_responses: Arc::new(std::sync::RwLock::new(HashMap::new())),
            error_responses: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    pub fn set_cached_response(&self, domain: &str, resolution: DnsResolution) {
        self.cache_responses
            .write()
            .unwrap()
            .insert(domain.to_string(), resolution);
    }

    pub async fn set_response_error(&self, domain: &str, error: DomainError) {
        self.error_responses
            .write()
            .unwrap()
            .insert(domain.to_string(), error);
    }

    pub async fn set_response(&self, domain: &str, resolution: DnsResolution) {
        self.responses
            .write()
            .await
            .insert(domain.to_string(), resolution);
    }

    pub async fn set_responses(&self, responses: Vec<(&str, DnsResolution)>) {
        let mut map = self.responses.write().await;
        for (domain, resolution) in responses {
            map.insert(domain.to_string(), resolution);
        }
    }

    pub async fn set_should_fail(&self, should_fail: bool) {
        *self.should_fail.write().await = should_fail;
    }

    pub async fn clear(&self) {
        self.responses.write().await.clear();
    }
}

impl Default for MockDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DnsResolver for MockDnsResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        if *self.should_fail.read().await {
            return Err(DomainError::InvalidDomainName(
                "Mock resolver failed".to_string(),
            ));
        }

        if let Some(err) = self
            .error_responses
            .read()
            .unwrap()
            .get(query.domain.as_ref())
            .cloned()
        {
            return Err(err);
        }

        let responses = self.responses.read().await;
        responses
            .get(query.domain.as_ref())
            .cloned()
            .ok_or_else(|| {
                DomainError::InvalidDomainName(format!("No mock response for {}", query.domain))
            })
    }

    fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        self.cache_responses
            .read()
            .unwrap()
            .get(query.domain.as_ref())
            .cloned()
    }
}

#[derive(Clone)]
pub struct MockBlocklistRepository {
    blocked_domains: Arc<RwLock<Vec<BlockedDomain>>>,
}

impl MockBlocklistRepository {
    pub fn new() -> Self {
        Self {
            blocked_domains: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn with_blocked_domains(domains: Vec<&str>) -> Self {
        let blocked = domains
            .into_iter()
            .map(|d| BlockedDomain {
                domain: d.to_string(),
                id: None,
                added_at: None,
            })
            .collect();

        Self {
            blocked_domains: Arc::new(RwLock::new(blocked)),
        }
    }

    pub async fn add_blocked_domains(&self, domains: Vec<&str>) {
        let mut blocked = self.blocked_domains.write().await;
        for domain in domains {
            blocked.push(BlockedDomain {
                domain: domain.to_string(),
                id: None,
                added_at: None,
            });
        }
    }

    pub async fn clear(&self) {
        self.blocked_domains.write().await.clear();
    }

    pub async fn count(&self) -> usize {
        self.blocked_domains.read().await.len()
    }
}

impl Default for MockBlocklistRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlocklistRepository for MockBlocklistRepository {
    async fn get_all(&self) -> Result<Vec<BlockedDomain>, DomainError> {
        Ok(self.blocked_domains.read().await.clone())
    }

    async fn add_domain(&self, domain: &BlockedDomain) -> Result<(), DomainError> {
        self.blocked_domains.write().await.push(domain.clone());
        Ok(())
    }

    async fn remove_domain(&self, domain: &str) -> Result<(), DomainError> {
        let mut domains = self.blocked_domains.write().await;
        domains.retain(|d| d.domain != domain);
        Ok(())
    }

    async fn is_blocked(&self, domain: &str) -> Result<bool, DomainError> {
        let domains = self.blocked_domains.read().await;
        Ok(domains.iter().any(|d| d.domain == domain))
    }
}

#[derive(Clone)]
pub struct MockQueryLogRepository {
    logs: Arc<RwLock<Vec<QueryLog>>>,
    sync_logs: Arc<std::sync::Mutex<Vec<QueryLog>>>,
}

impl MockQueryLogRepository {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(RwLock::new(Vec::new())),
            sync_logs: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    pub fn sync_log_count(&self) -> usize {
        self.sync_logs.lock().unwrap().len()
    }

    pub fn get_sync_logs(&self) -> Vec<QueryLog> {
        self.sync_logs.lock().unwrap().clone()
    }

    pub async fn get_all_logs(&self) -> Vec<QueryLog> {
        self.logs.read().await.clone()
    }

    pub async fn count(&self) -> usize {
        self.logs.read().await.len()
    }

    pub async fn get_blocked_logs(&self) -> Vec<QueryLog> {
        self.logs
            .read()
            .await
            .iter()
            .filter(|log| log.blocked)
            .cloned()
            .collect()
    }

    pub async fn get_cache_hits(&self) -> Vec<QueryLog> {
        self.logs
            .read()
            .await
            .iter()
            .filter(|log| log.cache_hit)
            .cloned()
            .collect()
    }

    pub async fn clear(&self) {
        self.logs.write().await.clear();
    }
}

impl Default for MockQueryLogRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl QueryLogRepository for MockQueryLogRepository {
    async fn log_query(&self, query: &QueryLog) -> Result<(), DomainError> {
        self.logs.write().await.push(query.clone());
        Ok(())
    }

    fn log_query_sync(&self, query: &QueryLog) -> Result<(), DomainError> {
        self.sync_logs.lock().unwrap().push(query.clone());
        Ok(())
    }

    async fn get_recent(
        &self,
        limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<QueryLog>, DomainError> {
        let logs = self.logs.read().await;
        let start = logs.len().saturating_sub(limit as usize);
        Ok(logs[start..].to_vec())
    }

    async fn get_recent_paged(
        &self,
        limit: u32,
        offset: u32,
        period_hours: f32,
        _cursor: Option<i64>,
    ) -> Result<(Vec<QueryLog>, u64, Option<i64>), DomainError> {
        let all = self.get_recent(limit + offset, period_hours).await?;
        let total = all.len() as u64;
        let start = (offset as usize).min(all.len());
        let end = (start + limit as usize).min(all.len());
        let page = all[start..end].to_vec();
        let next_cursor = if end < all.len() {
            page.last().and_then(|q| q.id)
        } else {
            None
        };
        Ok((page, total, next_cursor))
    }

    async fn get_stats(&self, _period_hours: f32) -> Result<QueryStats, DomainError> {
        let logs = self.logs.read().await;
        let queries_total = logs.len() as u64;
        let queries_blocked = logs.iter().filter(|l| l.blocked).count() as u64;
        let queries_cache_hits = logs.iter().filter(|l| l.cache_hit).count() as u64;
        let queries_upstream = logs.iter().filter(|l| !l.cache_hit && !l.blocked).count() as u64;
        let queries_blocked_by_blocklist = logs
            .iter()
            .filter(|l| l.block_source == Some(BlockSource::Blocklist))
            .count() as u64;
        let queries_blocked_by_managed_domain = logs
            .iter()
            .filter(|l| l.block_source == Some(BlockSource::ManagedDomain))
            .count() as u64;
        let queries_blocked_by_regex_filter = logs
            .iter()
            .filter(|l| l.block_source == Some(BlockSource::RegexFilter))
            .count() as u64;
        let queries_blocked_by_cname_cloaking = logs
            .iter()
            .filter(|l| l.block_source == Some(BlockSource::CnameCloaking))
            .count() as u64;

        Ok(QueryStats {
            queries_total,
            queries_blocked,
            unique_clients: 0,
            uptime_seconds: 0,
            cache_hit_rate: 0.0,
            avg_query_time_ms: 0.0,
            avg_cache_time_ms: 0.0,
            avg_upstream_time_ms: 0.0,
            queries_cache_hits,
            queries_upstream,
            queries_blocked_by_blocklist,
            queries_blocked_by_managed_domain,
            queries_blocked_by_regex_filter,
            queries_blocked_by_cname_cloaking,
            queries_local_dns: 0,
            queries_by_type: HashMap::new(),
            most_queried_type: None,
            record_type_distribution: Vec::new(),
        })
    }

    async fn get_timeline(
        &self,
        _period_hours: u32,
        _granularity: TimeGranularity,
    ) -> Result<Vec<ferrous_dns_application::ports::TimelineBucket>, DomainError> {
        Ok(Vec::new())
    }

    async fn count_queries_since(&self, _seconds_ago: i64) -> Result<u64, DomainError> {
        let logs = self.logs.read().await;
        Ok(logs.len() as u64)
    }

    async fn get_cache_stats(
        &self,
        _period_hours: f32,
    ) -> Result<ferrous_dns_application::ports::CacheStats, DomainError> {
        let logs = self.logs.read().await;
        let total_hits = logs
            .iter()
            .filter(|l| l.cache_hit && !l.cache_refresh)
            .count() as u64;
        let total_misses = logs
            .iter()
            .filter(|l| !l.cache_hit && !l.cache_refresh && !l.blocked)
            .count() as u64;
        let total_refreshes = logs.iter().filter(|l| l.cache_refresh).count() as u64;
        let total_queries = total_hits + total_misses;

        let hit_rate = if total_queries > 0 {
            (total_hits as f64 / total_queries as f64) * 100.0
        } else {
            0.0
        };

        let refresh_rate = if total_hits > 0 {
            (total_refreshes as f64 / total_hits as f64) * 100.0
        } else {
            0.0
        };

        Ok(ferrous_dns_application::ports::CacheStats {
            total_hits,
            total_misses,
            total_refreshes,
            hit_rate,
            refresh_rate,
        })
    }

    async fn delete_older_than(&self, _days: u32) -> Result<u64, DomainError> {
        Ok(0)
    }
}

#[derive(Clone)]
pub struct MockClientRepository {
    clients: Arc<RwLock<HashMap<i64, Client>>>,
    next_id: Arc<RwLock<i64>>,
}

impl MockClientRepository {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(RwLock::new(1)),
        }
    }

    pub async fn with_clients(clients: Vec<Client>) -> Self {
        let mut map = HashMap::new();
        let mut max_id = 0i64;
        for mut client in clients {
            let id = client.id.unwrap_or_else(|| {
                max_id += 1;
                max_id
            });
            client.id = Some(id);
            map.insert(id, client);
            if id > max_id {
                max_id = id;
            }
        }

        Self {
            clients: Arc::new(RwLock::new(map)),
            next_id: Arc::new(RwLock::new(max_id + 1)),
        }
    }

    pub async fn count(&self) -> usize {
        self.clients.read().await.len()
    }

    pub async fn clear(&self) {
        self.clients.write().await.clear();
        *self.next_id.write().await = 1;
    }

    pub async fn get_all_clients(&self) -> Vec<Client> {
        self.clients.read().await.values().cloned().collect()
    }
}

impl Default for MockClientRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ClientRepository for MockClientRepository {
    async fn get_or_create(&self, ip_address: IpAddr) -> Result<Client, DomainError> {
        let mut clients = self.clients.write().await;

        if let Some(client) = clients.values().find(|c| c.ip_address == ip_address) {
            return Ok(client.clone());
        }

        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let now = chrono::Utc::now().to_rfc3339();
        let client = Client {
            id: Some(id),
            ip_address,
            mac_address: None,
            hostname: None,
            first_seen: Some(now.clone()),
            last_seen: Some(now),
            query_count: 0,
            last_mac_update: None,
            last_hostname_update: None,
            group_id: Some(1),
        };

        clients.insert(id, client.clone());
        Ok(client)
    }

    async fn update_last_seen(&self, ip_address: IpAddr) -> Result<(), DomainError> {
        let mut clients = self.clients.write().await;

        if let Some(client) = clients.values_mut().find(|c| c.ip_address == ip_address) {
            client.last_seen = Some(chrono::Utc::now().to_rfc3339());
            client.query_count += 1;
            return Ok(());
        }

        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let now = chrono::Utc::now().to_rfc3339();
        let client = Client {
            id: Some(id),
            ip_address,
            mac_address: None,
            hostname: None,
            first_seen: Some(now.clone()),
            last_seen: Some(now),
            query_count: 1,
            last_mac_update: None,
            last_hostname_update: None,
            group_id: Some(1),
        };

        clients.insert(id, client);
        Ok(())
    }

    async fn update_mac_address(&self, ip_address: IpAddr, mac: String) -> Result<(), DomainError> {
        let mut clients = self.clients.write().await;

        if let Some(client) = clients.values_mut().find(|c| c.ip_address == ip_address) {
            client.mac_address = Some(Arc::from(mac));
            client.last_mac_update = Some(chrono::Utc::now().to_rfc3339());
            Ok(())
        } else {
            Err(DomainError::ClientNotFound(format!(
                "Client with IP {} not found",
                ip_address
            )))
        }
    }

    async fn batch_update_mac_addresses(
        &self,
        updates: Vec<(IpAddr, String)>,
    ) -> Result<u64, DomainError> {
        let mut count = 0u64;
        for (ip, mac) in updates {
            if self.update_mac_address(ip, mac).await.is_ok() {
                count += 1;
            }
        }
        Ok(count)
    }

    async fn update_hostname(
        &self,
        ip_address: IpAddr,
        hostname: String,
    ) -> Result<(), DomainError> {
        let mut clients = self.clients.write().await;

        if let Some(client) = clients.values_mut().find(|c| c.ip_address == ip_address) {
            client.hostname = Some(Arc::from(hostname));
            client.last_hostname_update = Some(chrono::Utc::now().to_rfc3339());
            Ok(())
        } else {
            Err(DomainError::ClientNotFound(format!(
                "Client with IP {} not found",
                ip_address
            )))
        }
    }

    async fn get_all(&self, limit: u32, offset: u32) -> Result<Vec<Client>, DomainError> {
        let clients = self.clients.read().await;
        let mut all: Vec<Client> = clients.values().cloned().collect();
        all.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));

        let start = offset as usize;
        let end = (start + limit as usize).min(all.len());
        Ok(all[start..end].to_vec())
    }

    async fn get_active(&self, days: u32, limit: u32) -> Result<Vec<Client>, DomainError> {
        let clients = self.clients.read().await;
        let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
        let cutoff_str = cutoff.to_rfc3339();

        let mut active: Vec<Client> = clients
            .values()
            .filter(|c| {
                c.last_seen
                    .as_ref()
                    .map(|ls| ls.as_str() > cutoff_str.as_str())
                    .unwrap_or(false)
            })
            .cloned()
            .collect();

        active.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        active.truncate(limit as usize);
        Ok(active)
    }

    async fn get_stats(&self) -> Result<ClientStats, DomainError> {
        let clients = self.clients.read().await;
        let total_clients = clients.len() as u64;
        let with_mac = clients.values().filter(|c| c.mac_address.is_some()).count() as u64;
        let with_hostname = clients.values().filter(|c| c.hostname.is_some()).count() as u64;

        let cutoff_24h = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
        let cutoff_7d = (chrono::Utc::now() - chrono::Duration::days(7)).to_rfc3339();

        let active_24h = clients
            .values()
            .filter(|c| {
                c.last_seen
                    .as_ref()
                    .map(|ls| ls.as_str() > cutoff_24h.as_str())
                    .unwrap_or(false)
            })
            .count() as u64;

        let active_7d = clients
            .values()
            .filter(|c| {
                c.last_seen
                    .as_ref()
                    .map(|ls| ls.as_str() > cutoff_7d.as_str())
                    .unwrap_or(false)
            })
            .count() as u64;

        Ok(ClientStats {
            total_clients,
            with_mac,
            with_hostname,
            active_24h,
            active_7d,
        })
    }

    async fn delete_older_than(&self, days: u32) -> Result<u64, DomainError> {
        let mut clients = self.clients.write().await;
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(days as i64)).to_rfc3339();

        let to_remove: Vec<i64> = clients
            .iter()
            .filter(|(_, c)| {
                c.last_seen
                    .as_ref()
                    .map(|ls| ls.as_str() < cutoff.as_str())
                    .unwrap_or(true)
            })
            .map(|(id, _)| *id)
            .collect();

        let count = to_remove.len() as u64;
        for id in to_remove {
            clients.remove(&id);
        }

        Ok(count)
    }

    async fn get_needs_mac_update(&self, limit: u32) -> Result<Vec<Client>, DomainError> {
        let clients = self.clients.read().await;
        let needs_update: Vec<Client> = clients
            .values()
            .filter(|c| c.mac_address.is_none())
            .take(limit as usize)
            .cloned()
            .collect();
        Ok(needs_update)
    }

    async fn get_needs_hostname_update(&self, limit: u32) -> Result<Vec<Client>, DomainError> {
        let clients = self.clients.read().await;
        let needs_update: Vec<Client> = clients
            .values()
            .filter(|c| c.hostname.is_none())
            .take(limit as usize)
            .cloned()
            .collect();
        Ok(needs_update)
    }

    async fn get_by_id(&self, id: i64) -> Result<Option<Client>, DomainError> {
        let clients = self.clients.read().await;
        Ok(clients.get(&id).cloned())
    }

    async fn assign_group(&self, client_id: i64, group_id: i64) -> Result<(), DomainError> {
        let mut clients = self.clients.write().await;

        if let Some(client) = clients.get_mut(&client_id) {
            client.group_id = Some(group_id);
            Ok(())
        } else {
            Err(DomainError::ClientNotFound(format!(
                "Client {} not found",
                client_id
            )))
        }
    }

    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let mut clients = self.clients.write().await;

        if clients.remove(&id).is_some() {
            Ok(())
        } else {
            Err(DomainError::ClientNotFound(format!(
                "Client {} not found",
                id
            )))
        }
    }
}

#[derive(Clone)]
pub struct MockBlocklistSourceRepository {
    sources: Arc<RwLock<Vec<BlocklistSource>>>,
    next_id: Arc<RwLock<i64>>,
}

impl MockBlocklistSourceRepository {
    pub fn new() -> Self {
        Self {
            sources: Arc::new(RwLock::new(Vec::new())),
            next_id: Arc::new(RwLock::new(1)),
        }
    }

    pub async fn get_all_sources(&self) -> Vec<BlocklistSource> {
        self.sources.read().await.clone()
    }

    pub async fn count(&self) -> usize {
        self.sources.read().await.len()
    }
}

impl Default for MockBlocklistSourceRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlocklistSourceRepository for MockBlocklistSourceRepository {
    async fn create(
        &self,
        name: String,
        url: Option<String>,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<BlocklistSource, DomainError> {
        let mut sources = self.sources.write().await;

        if sources.iter().any(|s| s.name.as_ref() == name.as_str()) {
            return Err(DomainError::InvalidBlocklistSource(format!(
                "Blocklist source '{}' already exists",
                name
            )));
        }

        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let source = BlocklistSource {
            id: Some(id),
            name: Arc::from(name.as_str()),
            url: url.as_deref().map(Arc::from),
            group_id,
            comment: comment.as_deref().map(Arc::from),
            enabled,
            created_at: Some("2026-01-01 00:00:00".to_string()),
            updated_at: Some("2026-01-01 00:00:00".to_string()),
        };

        sources.push(source.clone());
        Ok(source)
    }

    async fn get_by_id(&self, id: i64) -> Result<Option<BlocklistSource>, DomainError> {
        let sources = self.sources.read().await;
        Ok(sources.iter().find(|s| s.id == Some(id)).cloned())
    }

    async fn get_all(&self) -> Result<Vec<BlocklistSource>, DomainError> {
        Ok(self.sources.read().await.clone())
    }

    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        url: Option<Option<String>>,
        group_id: Option<i64>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<BlocklistSource, DomainError> {
        let mut sources = self.sources.write().await;

        let source = sources
            .iter_mut()
            .find(|s| s.id == Some(id))
            .ok_or(DomainError::BlocklistSourceNotFound(id))?;

        if let Some(n) = name {
            source.name = Arc::from(n.as_str());
        }
        if let Some(u_opt) = url {
            source.url = u_opt.as_deref().map(Arc::from);
        }
        if let Some(gid) = group_id {
            source.group_id = gid;
        }
        if let Some(c) = comment {
            source.comment = Some(Arc::from(c.as_str()));
        }
        if let Some(e) = enabled {
            source.enabled = e;
        }

        Ok(source.clone())
    }

    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let mut sources = self.sources.write().await;
        let len_before = sources.len();
        sources.retain(|s| s.id != Some(id));
        if sources.len() == len_before {
            return Err(DomainError::BlocklistSourceNotFound(id));
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct MockGroupRepository {
    groups: Arc<RwLock<Vec<Group>>>,
    next_id: Arc<RwLock<i64>>,
}

impl MockGroupRepository {
    pub fn new() -> Self {
        let protected = Group::new(
            Some(1),
            Arc::from("Protected"),
            true,
            Some(Arc::from("Default group")),
            true,
        );
        Self {
            groups: Arc::new(RwLock::new(vec![protected])),
            next_id: Arc::new(RwLock::new(2)),
        }
    }

    pub fn empty() -> Self {
        Self {
            groups: Arc::new(RwLock::new(Vec::new())),
            next_id: Arc::new(RwLock::new(1)),
        }
    }
}

impl Default for MockGroupRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GroupRepository for MockGroupRepository {
    async fn create(&self, name: String, comment: Option<String>) -> Result<Group, DomainError> {
        let mut groups = self.groups.write().await;
        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let group = Group::new(
            Some(id),
            Arc::from(name.as_str()),
            true,
            comment.as_deref().map(Arc::from),
            false,
        );
        groups.push(group.clone());
        Ok(group)
    }

    async fn get_by_id(&self, id: i64) -> Result<Option<Group>, DomainError> {
        let groups = self.groups.read().await;
        Ok(groups.iter().find(|g| g.id == Some(id)).cloned())
    }

    async fn get_by_name(&self, name: &str) -> Result<Option<Group>, DomainError> {
        let groups = self.groups.read().await;
        Ok(groups.iter().find(|g| g.name.as_ref() == name).cloned())
    }

    async fn get_all(&self) -> Result<Vec<Group>, DomainError> {
        Ok(self.groups.read().await.clone())
    }

    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        enabled: Option<bool>,
        comment: Option<String>,
    ) -> Result<Group, DomainError> {
        let mut groups = self.groups.write().await;
        let group = groups
            .iter_mut()
            .find(|g| g.id == Some(id))
            .ok_or(DomainError::GroupNotFound(id))?;

        if let Some(n) = name {
            group.name = Arc::from(n.as_str());
        }
        if let Some(e) = enabled {
            group.enabled = e;
        }
        if let Some(c) = comment {
            group.comment = Some(Arc::from(c.as_str()));
        }
        Ok(group.clone())
    }

    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let mut groups = self.groups.write().await;
        let len_before = groups.len();
        groups.retain(|g| g.id != Some(id));
        if groups.len() == len_before {
            return Err(DomainError::GroupNotFound(id));
        }
        Ok(())
    }

    async fn get_clients_in_group(
        &self,
        _group_id: i64,
    ) -> Result<Vec<ferrous_dns_domain::Client>, DomainError> {
        Ok(Vec::new())
    }

    async fn count_clients_in_group(&self, _group_id: i64) -> Result<u64, DomainError> {
        Ok(0)
    }
}

#[derive(Clone)]
pub struct MockWhitelistRepository {
    whitelisted_domains: Arc<RwLock<Vec<WhitelistedDomain>>>,
}

impl MockWhitelistRepository {
    pub fn new() -> Self {
        Self {
            whitelisted_domains: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn with_whitelisted_domains(domains: Vec<&str>) -> Self {
        let whitelisted = domains
            .into_iter()
            .map(|d| WhitelistedDomain {
                domain: d.to_string(),
                id: None,
                added_at: None,
            })
            .collect();

        Self {
            whitelisted_domains: Arc::new(RwLock::new(whitelisted)),
        }
    }

    pub async fn add_whitelisted_domains(&self, domains: Vec<&str>) {
        let mut whitelisted = self.whitelisted_domains.write().await;
        for domain in domains {
            whitelisted.push(WhitelistedDomain {
                domain: domain.to_string(),
                id: None,
                added_at: None,
            });
        }
    }

    pub async fn clear(&self) {
        self.whitelisted_domains.write().await.clear();
    }

    pub async fn count(&self) -> usize {
        self.whitelisted_domains.read().await.len()
    }
}

impl Default for MockWhitelistRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WhitelistRepository for MockWhitelistRepository {
    async fn get_all(&self) -> Result<Vec<WhitelistedDomain>, DomainError> {
        Ok(self.whitelisted_domains.read().await.clone())
    }

    async fn add_domain(&self, domain: &WhitelistedDomain) -> Result<(), DomainError> {
        self.whitelisted_domains.write().await.push(domain.clone());
        Ok(())
    }

    async fn remove_domain(&self, domain: &str) -> Result<(), DomainError> {
        let mut domains = self.whitelisted_domains.write().await;
        domains.retain(|d| d.domain != domain);
        Ok(())
    }

    async fn is_whitelisted(&self, domain: &str) -> Result<bool, DomainError> {
        let domains = self.whitelisted_domains.read().await;
        Ok(domains.iter().any(|d| d.domain == domain))
    }
}

#[derive(Clone)]
pub struct MockWhitelistSourceRepository {
    sources: Arc<RwLock<Vec<WhitelistSource>>>,
    next_id: Arc<RwLock<i64>>,
}

impl MockWhitelistSourceRepository {
    pub fn new() -> Self {
        Self {
            sources: Arc::new(RwLock::new(Vec::new())),
            next_id: Arc::new(RwLock::new(1)),
        }
    }

    pub async fn get_all_sources(&self) -> Vec<WhitelistSource> {
        self.sources.read().await.clone()
    }

    pub async fn count(&self) -> usize {
        self.sources.read().await.len()
    }
}

impl Default for MockWhitelistSourceRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl WhitelistSourceRepository for MockWhitelistSourceRepository {
    async fn create(
        &self,
        name: String,
        url: Option<String>,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<WhitelistSource, DomainError> {
        let mut sources = self.sources.write().await;

        if sources.iter().any(|s| s.name.as_ref() == name.as_str()) {
            return Err(DomainError::InvalidWhitelistSource(format!(
                "Whitelist source '{}' already exists",
                name
            )));
        }

        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let source = WhitelistSource {
            id: Some(id),
            name: Arc::from(name.as_str()),
            url: url.as_deref().map(Arc::from),
            group_id,
            comment: comment.as_deref().map(Arc::from),
            enabled,
            created_at: Some("2026-01-01 00:00:00".to_string()),
            updated_at: Some("2026-01-01 00:00:00".to_string()),
        };

        sources.push(source.clone());
        Ok(source)
    }

    async fn get_by_id(&self, id: i64) -> Result<Option<WhitelistSource>, DomainError> {
        let sources = self.sources.read().await;
        Ok(sources.iter().find(|s| s.id == Some(id)).cloned())
    }

    async fn get_all(&self) -> Result<Vec<WhitelistSource>, DomainError> {
        Ok(self.sources.read().await.clone())
    }

    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        url: Option<Option<String>>,
        group_id: Option<i64>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<WhitelistSource, DomainError> {
        let mut sources = self.sources.write().await;

        let source = sources
            .iter_mut()
            .find(|s| s.id == Some(id))
            .ok_or(DomainError::WhitelistSourceNotFound(id))?;

        if let Some(n) = name {
            source.name = Arc::from(n.as_str());
        }
        if let Some(u_opt) = url {
            source.url = u_opt.as_deref().map(Arc::from);
        }
        if let Some(gid) = group_id {
            source.group_id = gid;
        }
        if let Some(c) = comment {
            source.comment = Some(Arc::from(c.as_str()));
        }
        if let Some(e) = enabled {
            source.enabled = e;
        }

        Ok(source.clone())
    }

    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let mut sources = self.sources.write().await;
        let len_before = sources.len();
        sources.retain(|s| s.id != Some(id));
        if sources.len() == len_before {
            return Err(DomainError::WhitelistSourceNotFound(id));
        }
        Ok(())
    }
}

pub struct DnsResolutionBuilder {
    addresses: Vec<IpAddr>,
    cache_hit: bool,
    dnssec_status: Option<&'static str>,
    cname_chain: Vec<Arc<str>>,
    upstream_server: Option<String>,
}

impl DnsResolutionBuilder {
    pub fn new() -> Self {
        Self {
            addresses: vec![IpAddr::from_str("93.184.216.34").unwrap()],
            cache_hit: false,
            dnssec_status: None,
            cname_chain: vec![],
            upstream_server: None,
        }
    }

    pub fn with_address(mut self, addr: &str) -> Self {
        self.addresses = vec![IpAddr::from_str(addr).unwrap()];
        self
    }

    pub fn cache_hit(mut self) -> Self {
        self.cache_hit = true;
        self
    }

    pub fn cache_miss(mut self) -> Self {
        self.cache_hit = false;
        self
    }

    pub fn with_dnssec(mut self, status: &'static str) -> Self {
        self.dnssec_status = Some(status);
        self
    }

    pub fn with_upstream(mut self, server: &str) -> Self {
        self.upstream_server = Some(server.to_string());
        self
    }

    pub fn with_cname_chain(mut self, chain: Vec<&str>) -> Self {
        self.cname_chain = chain.into_iter().map(Arc::from).collect();
        self
    }

    pub fn build(self) -> DnsResolution {
        DnsResolution {
            addresses: std::sync::Arc::new(self.addresses),
            cache_hit: self.cache_hit,
            local_dns: false,
            dnssec_status: self.dnssec_status,
            cname_chain: self.cname_chain,
            upstream_server: self.upstream_server,
            min_ttl: None,
            authority_records: vec![],
        }
    }
}

impl Default for DnsResolutionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_dns_resolver() {
        let resolver = MockDnsResolver::new();

        let resolution = DnsResolutionBuilder::new()
            .with_address("1.1.1.1")
            .cache_hit()
            .build();

        resolver.set_response("example.com", resolution).await;

        let query = DnsQuery {
            domain: "example.com".into(),
            record_type: RecordType::A,
        };

        let result = resolver.resolve(&query).await;
        assert!(result.is_ok());
        assert!(result.unwrap().cache_hit);
    }

    #[tokio::test]
    async fn test_mock_blocklist() {
        let blocklist =
            MockBlocklistRepository::with_blocked_domains(vec!["ads.com", "tracker.com"]);

        assert!(blocklist.is_blocked("ads.com").await.unwrap());
        assert!(!blocklist.is_blocked("google.com").await.unwrap());

        assert_eq!(blocklist.count().await, 2);
    }

    #[tokio::test]
    async fn test_mock_query_log() {
        let log_repo = MockQueryLogRepository::new();

        let log = QueryLog {
            id: None,
            domain: "test.com".into(),
            record_type: RecordType::A,
            client_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            client_hostname: None,
            blocked: false,
            response_time_us: Some(10),
            cache_hit: true,
            cache_refresh: false,
            dnssec_status: None,
            upstream_server: None,
            response_status: None,
            timestamp: None,
            query_source: Default::default(),
            group_id: None,
            block_source: None,
        };

        log_repo.log_query(&log).await.unwrap();

        assert_eq!(log_repo.count().await, 1);
        assert_eq!(log_repo.get_cache_hits().await.len(), 1);
    }
}

// ── MockManagedDomainRepository ────────────────────────────────────────────────

#[derive(Clone)]
pub struct MockManagedDomainRepository {
    domains: Arc<RwLock<Vec<ManagedDomain>>>,
    next_id: Arc<RwLock<i64>>,
}

impl MockManagedDomainRepository {
    pub fn new() -> Self {
        Self {
            domains: Arc::new(RwLock::new(Vec::new())),
            next_id: Arc::new(RwLock::new(1)),
        }
    }

    pub async fn count(&self) -> usize {
        self.domains.read().await.len()
    }

    pub async fn get_all_domains(&self) -> Vec<ManagedDomain> {
        self.domains.read().await.clone()
    }
}

impl Default for MockManagedDomainRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ManagedDomainRepository for MockManagedDomainRepository {
    async fn create(
        &self,
        name: String,
        domain: String,
        action: DomainAction,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<ManagedDomain, DomainError> {
        let mut domains = self.domains.write().await;

        if domains.iter().any(|d| d.name.as_ref() == name.as_str()) {
            return Err(DomainError::InvalidManagedDomain(format!(
                "Managed domain '{}' already exists",
                name
            )));
        }

        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;

        let managed = ManagedDomain {
            id: Some(id),
            name: Arc::from(name.as_str()),
            domain: Arc::from(domain.as_str()),
            action,
            group_id,
            comment: comment.as_deref().map(Arc::from),
            enabled,
            created_at: Some("2026-01-01 00:00:00".to_string()),
            updated_at: Some("2026-01-01 00:00:00".to_string()),
        };

        domains.push(managed.clone());
        Ok(managed)
    }

    async fn get_by_id(&self, id: i64) -> Result<Option<ManagedDomain>, DomainError> {
        let domains = self.domains.read().await;
        Ok(domains.iter().find(|d| d.id == Some(id)).cloned())
    }

    async fn get_all(&self) -> Result<Vec<ManagedDomain>, DomainError> {
        Ok(self.domains.read().await.clone())
    }

    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        domain: Option<String>,
        action: Option<DomainAction>,
        group_id: Option<i64>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<ManagedDomain, DomainError> {
        let mut domains = self.domains.write().await;

        let managed = domains
            .iter_mut()
            .find(|d| d.id == Some(id))
            .ok_or(DomainError::ManagedDomainNotFound(id))?;

        if let Some(n) = name {
            managed.name = Arc::from(n.as_str());
        }
        if let Some(d) = domain {
            managed.domain = Arc::from(d.as_str());
        }
        if let Some(a) = action {
            managed.action = a;
        }
        if let Some(gid) = group_id {
            managed.group_id = gid;
        }
        if let Some(c) = comment {
            managed.comment = Some(Arc::from(c.as_str()));
        }
        if let Some(e) = enabled {
            managed.enabled = e;
        }

        Ok(managed.clone())
    }

    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let mut domains = self.domains.write().await;
        let len_before = domains.len();
        domains.retain(|d| d.id != Some(id));
        if domains.len() == len_before {
            return Err(DomainError::ManagedDomainNotFound(id));
        }
        Ok(())
    }
}

// ── MockBlockFilterEngine ──────────────────────────────────────────────────────

#[derive(Clone)]
pub struct MockBlockFilterEngine {
    reload_count: Arc<RwLock<u32>>,
    should_fail_reload: Arc<RwLock<bool>>,
    blocked_domains: Arc<std::sync::RwLock<HashSet<String>>>,
}

impl MockBlockFilterEngine {
    pub fn new() -> Self {
        Self {
            reload_count: Arc::new(RwLock::new(0)),
            should_fail_reload: Arc::new(RwLock::new(false)),
            blocked_domains: Arc::new(std::sync::RwLock::new(HashSet::new())),
        }
    }

    pub async fn reload_count(&self) -> u32 {
        *self.reload_count.read().await
    }

    pub async fn set_should_fail_reload(&self, fail: bool) {
        *self.should_fail_reload.write().await = fail;
    }

    pub fn block_domain(&self, domain: &str) {
        self.blocked_domains
            .write()
            .unwrap()
            .insert(domain.to_string());
    }
}

impl Default for MockBlockFilterEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlockFilterEnginePort for MockBlockFilterEngine {
    fn resolve_group(&self, _ip: IpAddr) -> i64 {
        1
    }

    fn check(&self, domain: &str, _group_id: i64) -> FilterDecision {
        if self.blocked_domains.read().unwrap().contains(domain) {
            return FilterDecision::Block(BlockSource::Blocklist);
        }
        FilterDecision::Allow
    }

    async fn reload(&self) -> Result<(), DomainError> {
        if *self.should_fail_reload.read().await {
            return Err(DomainError::DatabaseError("Mock reload failed".to_string()));
        }
        *self.reload_count.write().await += 1;
        Ok(())
    }

    async fn load_client_groups(&self) -> Result<(), DomainError> {
        Ok(())
    }

    fn compiled_domain_count(&self) -> usize {
        0
    }
}
