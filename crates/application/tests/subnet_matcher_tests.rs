use async_trait::async_trait;
use ferrous_dns_application::ports::ClientSubnetRepository;
use ferrous_dns_application::services::SubnetMatcherService;
use ferrous_dns_domain::{ClientSubnet, DomainError};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

// Mock repository for testing
struct MockClientSubnetRepository {
    subnets: Arc<Mutex<Vec<ClientSubnet>>>,
}

impl MockClientSubnetRepository {
    fn new() -> Self {
        Self {
            subnets: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn add_subnet(&self, cidr: &str, group_id: i64) {
        let mut subnet = ClientSubnet::new(cidr.to_string(), group_id, None);
        subnet.id = Some(1); // Mock ID
        self.subnets.lock().unwrap().push(subnet);
    }
}

#[async_trait]
impl ClientSubnetRepository for MockClientSubnetRepository {
    async fn create(
        &self,
        subnet_cidr: String,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<ClientSubnet, DomainError> {
        let mut subnet = ClientSubnet::new(subnet_cidr, group_id, comment);
        subnet.id = Some(1);
        self.subnets.lock().unwrap().push(subnet.clone());
        Ok(subnet)
    }

    async fn get_by_id(&self, _id: i64) -> Result<Option<ClientSubnet>, DomainError> {
        Ok(None)
    }

    async fn get_all(&self) -> Result<Vec<ClientSubnet>, DomainError> {
        Ok(self.subnets.lock().unwrap().clone())
    }

    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        self.subnets.lock().unwrap().retain(|s| s.id != Some(id));
        Ok(())
    }

    async fn exists(&self, _subnet_cidr: &str) -> Result<bool, DomainError> {
        Ok(false)
    }
}

#[tokio::test]
async fn test_subnet_matcher_empty_cache() {
    let repo = Arc::new(MockClientSubnetRepository::new());
    let matcher = SubnetMatcherService::new(repo);

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let result = matcher.find_group_for_ip(ip).await;

    assert!(result.is_none());
}

#[tokio::test]
async fn test_subnet_matcher_single_subnet() {
    let repo = Arc::new(MockClientSubnetRepository::new());
    repo.add_subnet("192.168.1.0/24", 1);

    let matcher = SubnetMatcherService::new(repo);
    matcher.refresh().await.unwrap();

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    let result = matcher.find_group_for_ip(ip).await;

    assert_eq!(result, Some(1));
}

#[tokio::test]
async fn test_subnet_matcher_no_match() {
    let repo = Arc::new(MockClientSubnetRepository::new());
    repo.add_subnet("192.168.1.0/24", 1);

    let matcher = SubnetMatcherService::new(repo);
    matcher.refresh().await.unwrap();

    let ip: IpAddr = "10.0.0.1".parse().unwrap();
    let result = matcher.find_group_for_ip(ip).await;

    assert!(result.is_none());
}

#[tokio::test]
async fn test_subnet_matcher_multiple_subnets() {
    let repo = Arc::new(MockClientSubnetRepository::new());
    repo.add_subnet("192.168.1.0/24", 1);
    repo.add_subnet("10.0.0.0/8", 2);
    repo.add_subnet("172.16.0.0/12", 3);

    let matcher = SubnetMatcherService::new(repo);
    matcher.refresh().await.unwrap();

    let ip1: IpAddr = "192.168.1.50".parse().unwrap();
    let ip2: IpAddr = "10.5.10.20".parse().unwrap();
    let ip3: IpAddr = "172.20.0.1".parse().unwrap();

    assert_eq!(matcher.find_group_for_ip(ip1).await, Some(1));
    assert_eq!(matcher.find_group_for_ip(ip2).await, Some(2));
    assert_eq!(matcher.find_group_for_ip(ip3).await, Some(3));
}

#[tokio::test]
async fn test_subnet_matcher_most_specific_wins() {
    let repo = Arc::new(MockClientSubnetRepository::new());
    repo.add_subnet("192.168.0.0/16", 1);
    repo.add_subnet("192.168.1.0/24", 2);
    repo.add_subnet("192.168.1.100/32", 3);

    let matcher = SubnetMatcherService::new(repo);
    matcher.refresh().await.unwrap();

    // Most specific match (/32)
    let ip_host: IpAddr = "192.168.1.100".parse().unwrap();
    assert_eq!(matcher.find_group_for_ip(ip_host).await, Some(3));

    // Match /24
    let ip_narrow: IpAddr = "192.168.1.50".parse().unwrap();
    assert_eq!(matcher.find_group_for_ip(ip_narrow).await, Some(2));

    // Match /16
    let ip_broad: IpAddr = "192.168.2.1".parse().unwrap();
    assert_eq!(matcher.find_group_for_ip(ip_broad).await, Some(1));
}

#[tokio::test]
async fn test_subnet_matcher_cache_refresh() {
    let repo = Arc::new(MockClientSubnetRepository::new());
    repo.add_subnet("192.168.1.0/24", 1);

    let matcher = SubnetMatcherService::new(repo.clone());
    matcher.refresh().await.unwrap();

    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    assert_eq!(matcher.find_group_for_ip(ip).await, Some(1));

    // Add new subnet
    repo.add_subnet("10.0.0.0/8", 2);

    // Should not be in cache yet
    let ip2: IpAddr = "10.0.0.1".parse().unwrap();
    assert_eq!(matcher.find_group_for_ip(ip2).await, None);

    // After refresh, should find it
    matcher.refresh().await.unwrap();
    assert_eq!(matcher.find_group_for_ip(ip2).await, Some(2));
}

#[tokio::test]
async fn test_subnet_matcher_ipv6_support() {
    let repo = Arc::new(MockClientSubnetRepository::new());
    repo.add_subnet("2001:db8::/32", 1);

    let matcher = SubnetMatcherService::new(repo);
    matcher.refresh().await.unwrap();

    let ip_match: IpAddr = "2001:db8::1".parse().unwrap();
    let ip_no_match: IpAddr = "2001:db9::1".parse().unwrap();

    assert_eq!(matcher.find_group_for_ip(ip_match).await, Some(1));
    assert_eq!(matcher.find_group_for_ip(ip_no_match).await, None);
}

#[tokio::test]
async fn test_subnet_matcher_mixed_ipv4_ipv6() {
    let repo = Arc::new(MockClientSubnetRepository::new());
    repo.add_subnet("192.168.1.0/24", 1);
    repo.add_subnet("2001:db8::/32", 2);

    let matcher = SubnetMatcherService::new(repo);
    matcher.refresh().await.unwrap();

    let ip_v4: IpAddr = "192.168.1.100".parse().unwrap();
    let ip_v6: IpAddr = "2001:db8::1".parse().unwrap();

    assert_eq!(matcher.find_group_for_ip(ip_v4).await, Some(1));
    assert_eq!(matcher.find_group_for_ip(ip_v6).await, Some(2));
}
