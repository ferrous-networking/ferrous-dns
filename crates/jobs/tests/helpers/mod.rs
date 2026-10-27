use async_trait::async_trait;
use ferrous_dns_application::ports::ClientRepository;
use ferrous_dns_domain::{Client, ClientStats, DomainError, HostnameSource};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct MockClientRepository {
    clients: RwLock<HashMap<i64, Client>>,
    next_id: RwLock<i64>,
}

impl MockClientRepository {
    pub async fn with_clients(clients: Vec<Client>) -> Self {
        let mut map = HashMap::new();
        let mut max_id = 0i64;
        for mut client in clients {
            let id = client.id.unwrap_or(max_id + 1);
            client.id = Some(id);
            max_id = max_id.max(id);
            map.insert(id, client);
        }
        Self {
            clients: RwLock::new(map),
            next_id: RwLock::new(max_id + 1),
        }
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

pub fn make_client(id: i64, ip: &str) -> Client {
    let now = chrono::Utc::now().to_rfc3339();
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
        comment: None,
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
        let client = make_client(*next_id, &ip_address.to_string());
        clients.insert(*next_id, client.clone());
        *next_id += 1;
        Ok(client)
    }

    async fn update_last_seen(&self, ip_address: IpAddr) -> Result<(), DomainError> {
        let mut clients = self.clients.write().await;
        if let Some(c) = clients.values_mut().find(|c| c.ip_address == ip_address) {
            c.last_seen = Some(chrono::Utc::now().to_rfc3339());
            c.query_count += 1;
        }
        Ok(())
    }

    async fn update_mac_address(&self, ip_address: IpAddr, mac: String) -> Result<(), DomainError> {
        let mut clients = self.clients.write().await;
        let c = clients
            .values_mut()
            .find(|c| c.ip_address == ip_address)
            .ok_or_else(|| DomainError::ClientNotFound(format!("Client {ip_address} not found")))?;
        c.mac_address = Some(Arc::from(mac));
        c.last_mac_update = Some(chrono::Utc::now().timestamp());
        Ok(())
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
        _source: HostnameSource,
    ) -> Result<(), DomainError> {
        let mut clients = self.clients.write().await;
        let c = clients
            .values_mut()
            .find(|c| c.ip_address == ip_address)
            .ok_or_else(|| DomainError::ClientNotFound(format!("Client {ip_address} not found")))?;
        c.hostname = Some(Arc::from(hostname));
        c.last_hostname_update = Some(chrono::Utc::now().timestamp());
        Ok(())
    }

    async fn get_all(&self, limit: u32, offset: u32) -> Result<Vec<Client>, DomainError> {
        let clients = self.clients.read().await;
        let mut all: Vec<Client> = clients.values().cloned().collect();
        all.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        Ok(all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
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
        let before = clients.len();
        clients.retain(|_, c| {
            c.last_seen
                .as_deref()
                .is_some_and(|ls| ls >= cutoff.as_str())
        });
        Ok((before - clients.len()) as u64)
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

    async fn get_by_ip(&self, ip_address: IpAddr) -> Result<Option<Client>, DomainError> {
        Ok(self
            .clients
            .read()
            .await
            .values()
            .find(|c| c.ip_address == ip_address)
            .cloned())
    }

    async fn assign_group(&self, client_id: i64, group_id: i64) -> Result<(), DomainError> {
        let mut clients = self.clients.write().await;
        let c = clients
            .get_mut(&client_id)
            .ok_or_else(|| DomainError::ClientNotFound(format!("Client {client_id} not found")))?;
        c.group_id = Some(group_id);
        Ok(())
    }

    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        self.clients
            .write()
            .await
            .remove(&id)
            .map(|_| ())
            .ok_or_else(|| DomainError::ClientNotFound(format!("Client {id} not found")))
    }

    async fn set_comment(&self, id: i64, comment: Option<String>) -> Result<(), DomainError> {
        let mut clients = self.clients.write().await;
        let client = clients
            .get_mut(&id)
            .ok_or_else(|| DomainError::ClientNotFound(format!("Client {id} not found")))?;
        client.comment = comment.map(Arc::from);
        Ok(())
    }
}
