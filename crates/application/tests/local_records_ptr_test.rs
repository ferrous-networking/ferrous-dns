use async_trait::async_trait;
use ferrous_dns_application::ports::{ConfigRepository, PtrRecordRegistry};
use ferrous_dns_application::use_cases::{
    CreateLocalRecordUseCase, DeleteLocalRecordUseCase, UpdateLocalRecordUseCase,
};
use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::RwLock;

// ── Mock ConfigRepository ────────────────────────────────────────────────────

struct MockConfigRepository {
    should_fail: bool,
}

impl MockConfigRepository {
    fn ok() -> Arc<Self> {
        Arc::new(Self { should_fail: false })
    }

    fn failing() -> Arc<Self> {
        Arc::new(Self { should_fail: true })
    }
}

#[async_trait]
impl ConfigRepository for MockConfigRepository {
    async fn save_local_records(&self, _config: &Config) -> Result<(), DomainError> {
        if self.should_fail {
            Err(DomainError::IoError("disk full".to_string()))
        } else {
            Ok(())
        }
    }
}

// ── Mock PtrRecordRegistry ───────────────────────────────────────────────────

#[derive(Default)]
struct MockPtrRegistry {
    registered: Mutex<Vec<(IpAddr, String, u32)>>,
    unregistered: Mutex<Vec<IpAddr>>,
}

impl MockPtrRegistry {
    fn new_arc() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

impl PtrRecordRegistry for MockPtrRegistry {
    fn register(&self, ip: IpAddr, fqdn: Arc<str>, ttl: u32) {
        self.registered
            .lock()
            .unwrap()
            .push((ip, fqdn.to_string(), ttl));
    }

    fn unregister(&self, ip: IpAddr) {
        self.unregistered.lock().unwrap().push(ip);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn default_config() -> Arc<RwLock<Config>> {
    Arc::new(RwLock::new(Config::default()))
}

fn config_with_record(ip: &str) -> Arc<RwLock<Config>> {
    let mut config = Config::default();
    config.dns.local_records.push(LocalDnsRecord {
        hostname: "host".to_string(),
        domain: Some("local".to_string()),
        ip: ip.to_string(),
        record_type: "A".to_string(),
        ttl: Some(300),
    });
    Arc::new(RwLock::new(config))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_create_local_record_registers_ptr_in_registry() {
    let registry = MockPtrRegistry::new_arc();
    let use_case = CreateLocalRecordUseCase::new(default_config(), MockConfigRepository::ok())
        .with_ptr_registry(Some(registry.clone() as Arc<dyn PtrRecordRegistry>));

    let result = use_case
        .execute(
            "nas".to_string(),
            Some("local".to_string()),
            "10.0.10.5".to_string(),
            "A".to_string(),
            Some(300),
        )
        .await;

    assert!(result.is_ok());
    let registered = registry.registered.lock().unwrap();
    assert_eq!(registered.len(), 1);
    assert_eq!(registered[0].0, "10.0.10.5".parse::<IpAddr>().unwrap());
    assert_eq!(registered[0].1, "nas.local");
    assert_eq!(registered[0].2, 300);
}

#[tokio::test]
async fn test_create_local_record_without_registry_succeeds() {
    let use_case = CreateLocalRecordUseCase::new(default_config(), MockConfigRepository::ok());

    let result = use_case
        .execute(
            "host".to_string(),
            None,
            "10.0.10.1".to_string(),
            "A".to_string(),
            None,
        )
        .await;

    assert!(result.is_ok());
}

#[tokio::test]
async fn test_delete_local_record_unregisters_ptr_in_registry() {
    let registry = MockPtrRegistry::new_arc();
    let use_case =
        DeleteLocalRecordUseCase::new(config_with_record("10.0.10.1"), MockConfigRepository::ok())
            .with_ptr_registry(Some(registry.clone() as Arc<dyn PtrRecordRegistry>));

    let result = use_case.execute(0).await;

    assert!(result.is_ok());
    let unregistered = registry.unregistered.lock().unwrap();
    assert_eq!(unregistered.len(), 1);
    assert_eq!(unregistered[0], "10.0.10.1".parse::<IpAddr>().unwrap());
}

#[tokio::test]
async fn test_update_local_record_swaps_ptr_in_registry() {
    let registry = MockPtrRegistry::new_arc();
    let use_case =
        UpdateLocalRecordUseCase::new(config_with_record("10.0.10.1"), MockConfigRepository::ok())
            .with_ptr_registry(Some(registry.clone() as Arc<dyn PtrRecordRegistry>));

    let result = use_case
        .execute(
            0,
            "newhost".to_string(),
            Some("local".to_string()),
            "10.0.10.9".to_string(),
            "A".to_string(),
            Some(600),
        )
        .await;

    assert!(result.is_ok());
    let unregistered = registry.unregistered.lock().unwrap();
    let registered = registry.registered.lock().unwrap();
    assert_eq!(unregistered[0], "10.0.10.1".parse::<IpAddr>().unwrap());
    assert_eq!(registered[0].0, "10.0.10.9".parse::<IpAddr>().unwrap());
    assert_eq!(registered[0].1, "newhost.local");
}

#[tokio::test]
async fn test_create_local_record_does_not_register_on_save_failure() {
    let registry = MockPtrRegistry::new_arc();
    let use_case = CreateLocalRecordUseCase::new(default_config(), MockConfigRepository::failing())
        .with_ptr_registry(Some(registry.clone() as Arc<dyn PtrRecordRegistry>));

    let result = use_case
        .execute(
            "nas".to_string(),
            Some("local".to_string()),
            "10.0.10.5".to_string(),
            "A".to_string(),
            Some(300),
        )
        .await;

    assert!(result.is_err());
    let registered = registry.registered.lock().unwrap();
    assert!(
        registered.is_empty(),
        "register must NOT be called on rollback path"
    );
}
