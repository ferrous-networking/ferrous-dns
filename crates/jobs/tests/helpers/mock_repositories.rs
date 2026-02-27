#![allow(dead_code)]

use async_trait::async_trait;
use ferrous_dns_application::ports::{
    ArpReader, ArpTable, CacheCompactionOutcome, CacheMaintenancePort, CacheRefreshOutcome,
    CacheStats, ClientRepository, HostnameResolver, QueryLogRepository, TimeGranularity,
    TimelineBucket,
};
use ferrous_dns_domain::{Client, ClientStats, DomainError, QueryLog, QueryStats, RecordType};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct MockArpReader {
    table: Arc<RwLock<ArpTable>>,
    call_count: Arc<AtomicU64>,
    should_fail: Arc<RwLock<bool>>,
}

impl MockArpReader {
    pub fn new() -> Self {
        Self {
            table: Arc::new(RwLock::new(HashMap::new())),
            call_count: Arc::new(AtomicU64::new(0)),
            should_fail: Arc::new(RwLock::new(false)),
        }
    }

    pub fn with_entries(entries: Vec<(&str, &str)>) -> Self {
        let mut table = HashMap::new();
        for (ip, mac) in entries {
            table.insert(ip.parse().unwrap(), mac.to_string());
        }
        Self {
            table: Arc::new(RwLock::new(table)),
            call_count: Arc::new(AtomicU64::new(0)),
            should_fail: Arc::new(RwLock::new(false)),
        }
    }

    pub fn call_count(&self) -> u64 {
        self.call_count.load(Ordering::Relaxed)
    }

    pub async fn set_should_fail(&self, fail: bool) {
        *self.should_fail.write().await = fail;
    }

    pub async fn add_entry(&self, ip: &str, mac: &str) {
        self.table
            .write()
            .await
            .insert(ip.parse().unwrap(), mac.to_string());
    }
}

#[async_trait]
impl ArpReader for MockArpReader {
    async fn read_arp_table(&self) -> Result<ArpTable, DomainError> {
        self.call_count.fetch_add(1, Ordering::Relaxed);
        if *self.should_fail.read().await {
            return Err(DomainError::IoError("ARP read failed".to_string()));
        }
        Ok(self.table.read().await.clone())
    }
}

pub struct MockHostnameResolver {
    responses: Arc<RwLock<HashMap<IpAddr, Option<String>>>>,
    call_count: Arc<AtomicU64>,
    should_fail: Arc<RwLock<bool>>,
}

impl MockHostnameResolver {
    pub fn new() -> Self {
        Self {
            responses: Arc::new(RwLock::new(HashMap::new())),
            call_count: Arc::new(AtomicU64::new(0)),
            should_fail: Arc::new(RwLock::new(false)),
        }
    }

    pub async fn set_response(&self, ip: &str, hostname: Option<&str>) {
        self.responses
            .write()
            .await
            .insert(ip.parse().unwrap(), hostname.map(|h| h.to_string()));
    }

    pub fn call_count(&self) -> u64 {
        self.call_count.load(Ordering::Relaxed)
    }

    pub async fn set_should_fail(&self, fail: bool) {
        *self.should_fail.write().await = fail;
    }
}

#[async_trait]
impl HostnameResolver for MockHostnameResolver {
    async fn resolve_hostname(&self, ip: IpAddr) -> Result<Option<String>, DomainError> {
        self.call_count.fetch_add(1, Ordering::Relaxed);
        if *self.should_fail.read().await {
            return Err(DomainError::IoError(
                "Hostname resolution failed".to_string(),
            ));
        }
        Ok(self
            .responses
            .read()
            .await
            .get(&ip)
            .cloned()
            .unwrap_or(None))
    }
}

pub struct MockClientRepository {
    clients: Arc<RwLock<HashMap<i64, Client>>>,
    next_id: Arc<RwLock<i64>>,
    mac_updates: Arc<AtomicU64>,
    hostname_updates: Arc<AtomicU64>,
}

impl MockClientRepository {
    pub fn new() -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            next_id: Arc::new(RwLock::new(1)),
            mac_updates: Arc::new(AtomicU64::new(0)),
            hostname_updates: Arc::new(AtomicU64::new(0)),
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
            if id > max_id {
                max_id = id;
            }
            map.insert(id, client);
        }
        Self {
            clients: Arc::new(RwLock::new(map)),
            next_id: Arc::new(RwLock::new(max_id + 1)),
            mac_updates: Arc::new(AtomicU64::new(0)),
            hostname_updates: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn count(&self) -> usize {
        self.clients.read().await.len()
    }

    pub fn mac_update_count(&self) -> u64 {
        self.mac_updates.load(Ordering::Relaxed)
    }

    pub fn hostname_update_count(&self) -> u64 {
        self.hostname_updates.load(Ordering::Relaxed)
    }

    pub async fn get_client_by_ip(&self, ip: &str) -> Option<Client> {
        let ip: IpAddr = ip.parse().unwrap();
        self.clients
            .read()
            .await
            .values()
            .find(|c| c.ip_address == ip)
            .cloned()
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn past_rfc3339(days_ago: i64) -> String {
    (chrono::Utc::now() - chrono::Duration::days(days_ago)).to_rfc3339()
}

pub fn make_client(id: i64, ip: &str) -> Client {
    let now = now_rfc3339();
    Client {
        id: Some(id),
        ip_address: ip.parse().unwrap(),
        mac_address: None,
        hostname: None,
        first_seen: Some(now.clone()),
        last_seen: Some(now),
        query_count: 1,
        last_mac_update: None,
        last_hostname_update: None,
        group_id: Some(1),
    }
}

pub fn make_old_client(id: i64, ip: &str, days_old: i64) -> Client {
    let old = past_rfc3339(days_old);
    Client {
        id: Some(id),
        ip_address: ip.parse().unwrap(),
        mac_address: None,
        hostname: None,
        first_seen: Some(old.clone()),
        last_seen: Some(old),
        query_count: 1,
        last_mac_update: None,
        last_hostname_update: None,
        group_id: Some(1),
    }
}

#[async_trait]
impl ClientRepository for MockClientRepository {
    async fn get_or_create(&self, ip_address: IpAddr) -> Result<Client, DomainError> {
        let mut clients = self.clients.write().await;
        if let Some(c) = clients.values().find(|c| c.ip_address == ip_address) {
            return Ok(c.clone());
        }
        let mut next_id = self.next_id.write().await;
        let id = *next_id;
        *next_id += 1;
        let now = now_rfc3339();
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
        if let Some(c) = clients.values_mut().find(|c| c.ip_address == ip_address) {
            c.last_seen = Some(now_rfc3339());
            c.query_count += 1;
        }
        Ok(())
    }

    async fn update_mac_address(&self, ip_address: IpAddr, mac: String) -> Result<(), DomainError> {
        let mut clients = self.clients.write().await;
        if let Some(c) = clients.values_mut().find(|c| c.ip_address == ip_address) {
            c.mac_address = Some(Arc::from(mac));
            c.last_mac_update = Some(chrono::Utc::now().timestamp());
            self.mac_updates.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err(DomainError::ClientNotFound(format!(
                "Client {} not found",
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
        if let Some(c) = clients.values_mut().find(|c| c.ip_address == ip_address) {
            c.hostname = Some(Arc::from(hostname));
            c.last_hostname_update = Some(chrono::Utc::now().timestamp());
            self.hostname_updates.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err(DomainError::ClientNotFound(format!(
                "Client {} not found",
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

    async fn get_active(&self, _days: u32, _limit: u32) -> Result<Vec<Client>, DomainError> {
        Ok(Vec::new())
    }

    async fn get_stats(&self) -> Result<ClientStats, DomainError> {
        let clients = self.clients.read().await;
        Ok(ClientStats {
            total_clients: clients.len() as u64,
            with_mac: clients.values().filter(|c| c.mac_address.is_some()).count() as u64,
            with_hostname: clients.values().filter(|c| c.hostname.is_some()).count() as u64,
            active_24h: 0,
            active_7d: 0,
        })
    }

    async fn count_active_since(&self, _hours: f32) -> Result<u64, DomainError> {
        Ok(0)
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
        Ok(clients
            .values()
            .filter(|c| c.mac_address.is_none())
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn get_needs_hostname_update(&self, limit: u32) -> Result<Vec<Client>, DomainError> {
        let clients = self.clients.read().await;
        Ok(clients
            .values()
            .filter(|c| c.hostname.is_none())
            .take(limit as usize)
            .cloned()
            .collect())
    }

    async fn get_by_id(&self, id: i64) -> Result<Option<Client>, DomainError> {
        Ok(self.clients.read().await.get(&id).cloned())
    }

    async fn assign_group(&self, client_id: i64, group_id: i64) -> Result<(), DomainError> {
        let mut clients = self.clients.write().await;
        if let Some(c) = clients.get_mut(&client_id) {
            c.group_id = Some(group_id);
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

pub struct MockQueryLogRepository {
    logs: Arc<RwLock<Vec<(QueryLog, String)>>>,
    delete_count: Arc<AtomicU64>,
}

impl MockQueryLogRepository {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(RwLock::new(Vec::new())),
            delete_count: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn count(&self) -> usize {
        self.logs.read().await.len()
    }

    pub fn delete_count(&self) -> u64 {
        self.delete_count.load(Ordering::Relaxed)
    }

    pub async fn add_log_at(&self, ip: &str, timestamp: &str) {
        let log = QueryLog {
            id: None,
            domain: "test.example.com".into(),
            record_type: RecordType::A,
            client_ip: ip.parse().unwrap(),
            client_hostname: None,
            blocked: false,
            response_time_us: Some(10),
            cache_hit: false,
            cache_refresh: false,
            dnssec_status: None,
            upstream_server: None,
            upstream_pool: None,
            response_status: None,
            timestamp: Some(timestamp.to_string()),
            query_source: Default::default(),
            group_id: None,
            block_source: None,
        };
        self.logs.write().await.push((log, timestamp.to_string()));
    }

    pub async fn add_recent_log(&self, ip: &str) {
        let ts = chrono::Utc::now().to_rfc3339();
        self.add_log_at(ip, &ts).await;
    }

    pub async fn add_old_log(&self, ip: &str, days_old: i64) {
        let ts = (chrono::Utc::now() - chrono::Duration::days(days_old)).to_rfc3339();
        self.add_log_at(ip, &ts).await;
    }
}

#[async_trait]
impl QueryLogRepository for MockQueryLogRepository {
    async fn log_query(&self, query: &QueryLog) -> Result<(), DomainError> {
        let ts = chrono::Utc::now().to_rfc3339();
        self.logs.write().await.push((query.clone(), ts));
        Ok(())
    }

    async fn get_recent(
        &self,
        limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<QueryLog>, DomainError> {
        let logs = self.logs.read().await;
        let start = logs.len().saturating_sub(limit as usize);
        Ok(logs[start..].iter().map(|(l, _)| l.clone()).collect())
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
        Ok(QueryStats {
            queries_total: logs.len() as u64,
            queries_blocked: logs.iter().filter(|(l, _)| l.blocked).count() as u64,
            unique_clients: 0,
            uptime_seconds: 0,
            cache_hit_rate: 0.0,
            avg_query_time_ms: 0.0,
            avg_cache_time_ms: 0.0,
            avg_upstream_time_ms: 0.0,
            source_stats: HashMap::new(),
            queries_by_type: HashMap::new(),
            most_queried_type: None,
            record_type_distribution: Vec::new(),
        })
    }

    async fn get_timeline(
        &self,
        _period_hours: u32,
        _granularity: TimeGranularity,
    ) -> Result<Vec<TimelineBucket>, DomainError> {
        Ok(Vec::new())
    }

    async fn count_queries_since(&self, _seconds_ago: i64) -> Result<u64, DomainError> {
        Ok(self.logs.read().await.len() as u64)
    }

    async fn get_cache_stats(&self, _period_hours: f32) -> Result<CacheStats, DomainError> {
        Ok(CacheStats {
            total_hits: 0,
            total_misses: 0,
            total_refreshes: 0,
            hit_rate: 0.0,
            refresh_rate: 0.0,
        })
    }

    async fn delete_older_than(&self, days: u32) -> Result<u64, DomainError> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(days as i64)).to_rfc3339();
        let mut logs = self.logs.write().await;
        let before = logs.len();
        logs.retain(|(_, ts)| ts.as_str() >= cutoff.as_str());
        let deleted = (before - logs.len()) as u64;
        self.delete_count.fetch_add(deleted, Ordering::Relaxed);
        Ok(deleted)
    }
}

pub struct MockCacheMaintenancePort {
    refresh_call_count: Arc<AtomicU64>,
    compaction_call_count: Arc<AtomicU64>,
    should_fail_refresh: Arc<RwLock<bool>>,
    should_fail_compaction: Arc<RwLock<bool>>,
    refresh_outcome: Arc<RwLock<CacheRefreshOutcome>>,
    compaction_outcome: Arc<RwLock<CacheCompactionOutcome>>,
}

impl MockCacheMaintenancePort {
    pub fn new() -> Self {
        Self {
            refresh_call_count: Arc::new(AtomicU64::new(0)),
            compaction_call_count: Arc::new(AtomicU64::new(0)),
            should_fail_refresh: Arc::new(RwLock::new(false)),
            should_fail_compaction: Arc::new(RwLock::new(false)),
            refresh_outcome: Arc::new(RwLock::new(CacheRefreshOutcome::default())),
            compaction_outcome: Arc::new(RwLock::new(CacheCompactionOutcome::default())),
        }
    }

    pub fn with_refresh_outcome(mut self, outcome: CacheRefreshOutcome) -> Self {
        self.refresh_outcome = Arc::new(RwLock::new(outcome));
        self
    }

    pub fn with_compaction_outcome(mut self, outcome: CacheCompactionOutcome) -> Self {
        self.compaction_outcome = Arc::new(RwLock::new(outcome));
        self
    }

    pub fn refresh_call_count(&self) -> u64 {
        self.refresh_call_count.load(Ordering::Relaxed)
    }

    pub fn compaction_call_count(&self) -> u64 {
        self.compaction_call_count.load(Ordering::Relaxed)
    }

    pub async fn set_should_fail_refresh(&self, fail: bool) {
        *self.should_fail_refresh.write().await = fail;
    }

    pub async fn set_should_fail_compaction(&self, fail: bool) {
        *self.should_fail_compaction.write().await = fail;
    }
}

#[async_trait]
impl CacheMaintenancePort for MockCacheMaintenancePort {
    async fn run_refresh_cycle(&self) -> Result<CacheRefreshOutcome, DomainError> {
        self.refresh_call_count.fetch_add(1, Ordering::Relaxed);
        if *self.should_fail_refresh.read().await {
            return Err(DomainError::IoError("mock refresh failure".into()));
        }
        Ok(self.refresh_outcome.read().await.clone())
    }

    async fn run_compaction_cycle(&self) -> Result<CacheCompactionOutcome, DomainError> {
        self.compaction_call_count.fetch_add(1, Ordering::Relaxed);
        if *self.should_fail_compaction.read().await {
            return Err(DomainError::IoError("mock compaction failure".into()));
        }
        Ok(self.compaction_outcome.read().await.clone())
    }
}
