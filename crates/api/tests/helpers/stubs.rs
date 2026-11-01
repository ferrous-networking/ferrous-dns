use ferrous_dns_application::ports::{
    BlockFilterEnginePort, BlockedServiceRepository, ConfigFilePersistence, ConfigRepository,
    CustomServiceRepository, FilterDecision, MalwareExemptionPort, SafeSearchConfigRepository,
    SafeSearchEnginePort, ScheduleProfileRepository, ServiceCatalogPort,
};
use ferrous_dns_domain::{
    BlockedService, Config, CustomService, DomainError, SafeSearchConfig, SafeSearchEngine,
    ScheduleAction, ScheduleProfile, ServiceDefinition, TimeSlot, YouTubeMode,
};
use std::net::IpAddr;

pub struct NullBlockFilterEngine;

#[async_trait::async_trait]
impl BlockFilterEnginePort for NullBlockFilterEngine {
    fn resolve_group(&self, _ip: IpAddr) -> i64 {
        1
    }
    fn check(&self, _domain: &str, _group_id: i64) -> FilterDecision {
        FilterDecision::Allow
    }
    async fn reload(&self) -> Result<(), DomainError> {
        Ok(())
    }
    async fn load_client_groups(&self) -> Result<(), DomainError> {
        Ok(())
    }
    fn compiled_domain_count(&self) -> usize {
        0
    }
    fn explain(&self, _domain: &str, _group_id: i64) -> ferrous_dns_domain::FilterExplanation {
        unimplemented!()
    }
    fn match_candidate(
        &self,
        _domains: &[String],
        _list_lines: &[String],
        _regexes: &[String],
    ) -> Result<Vec<bool>, DomainError> {
        unimplemented!()
    }
    fn store_cname_decision(&self, _domain: &str, _group_id: i64, _ttl_secs: u64) {}
    fn is_blocking_enabled(&self) -> bool {
        true
    }
    fn set_blocking_enabled(&self, _enabled: bool) {}
}

pub struct NullBlockedServiceRepository;

#[async_trait::async_trait]
impl BlockedServiceRepository for NullBlockedServiceRepository {
    async fn block_service(
        &self,
        _service_id: &str,
        _group_id: i64,
    ) -> Result<BlockedService, DomainError> {
        unimplemented!()
    }
    async fn unblock_service(&self, _service_id: &str, _group_id: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_blocked_for_group(
        &self,
        _group_id: i64,
    ) -> Result<Vec<BlockedService>, DomainError> {
        Ok(vec![])
    }
    async fn get_all_blocked(&self) -> Result<Vec<BlockedService>, DomainError> {
        Ok(vec![])
    }
    async fn delete_all_for_service(&self, _service_id: &str) -> Result<u64, DomainError> {
        Ok(0)
    }
}

pub struct NullCustomServiceRepository;

#[async_trait::async_trait]
impl CustomServiceRepository for NullCustomServiceRepository {
    async fn create(
        &self,
        _service_id: &str,
        _name: &str,
        _category_name: &str,
        _domains: &[String],
    ) -> Result<CustomService, DomainError> {
        unimplemented!()
    }
    async fn get_by_service_id(
        &self,
        _service_id: &str,
    ) -> Result<Option<CustomService>, DomainError> {
        Ok(None)
    }
    async fn get_all(&self) -> Result<Vec<CustomService>, DomainError> {
        Ok(vec![])
    }
    async fn update(
        &self,
        _service_id: &str,
        _name: Option<String>,
        _category_name: Option<String>,
        _domains: Option<Vec<String>>,
    ) -> Result<CustomService, DomainError> {
        unimplemented!()
    }
    async fn delete(&self, _service_id: &str) -> Result<(), DomainError> {
        Ok(())
    }
}

pub struct NullServiceCatalog;

impl ServiceCatalogPort for NullServiceCatalog {
    fn get_by_id(&self, _id: &str) -> Option<ServiceDefinition> {
        None
    }
    fn all(&self) -> Vec<ServiceDefinition> {
        vec![]
    }
    fn normalized_rules_for(&self, _service_id: &str) -> Vec<String> {
        vec![]
    }
    fn reload_custom(&self, _custom: Vec<ServiceDefinition>) {}
}

pub struct NullConfigRepository;

#[async_trait::async_trait]
impl ConfigRepository for NullConfigRepository {
    async fn save_local_records(&self, _config: &Config) -> Result<(), DomainError> {
        Ok(())
    }
}

pub struct NullConfigFilePersistence;

impl ConfigFilePersistence for NullConfigFilePersistence {
    fn load_config_from_file(&self, _path: &str) -> Result<Config, DomainError> {
        Ok(Config::default())
    }

    fn save_config_to_file(&self, _config: &Config, _path: &str) -> Result<(), DomainError> {
        Ok(())
    }
}

pub struct NullSafeSearchConfigRepository;

#[async_trait::async_trait]
impl SafeSearchConfigRepository for NullSafeSearchConfigRepository {
    async fn get_all(&self) -> Result<Vec<SafeSearchConfig>, DomainError> {
        Ok(vec![])
    }
    async fn get_by_group(&self, _group_id: i64) -> Result<Vec<SafeSearchConfig>, DomainError> {
        Ok(vec![])
    }
    async fn upsert(
        &self,
        _group_id: i64,
        _engine: SafeSearchEngine,
        _enabled: bool,
        _youtube_mode: YouTubeMode,
    ) -> Result<SafeSearchConfig, DomainError> {
        unimplemented!()
    }
    async fn delete_by_group(&self, _group_id: i64) -> Result<(), DomainError> {
        Ok(())
    }
}

pub struct NullSafeSearchEnginePort;

#[async_trait::async_trait]
impl SafeSearchEnginePort for NullSafeSearchEnginePort {
    fn cname_for(&self, _domain: &str, _group_id: i64) -> Option<&'static str> {
        None
    }
    async fn reload(&self) -> Result<(), DomainError> {
        Ok(())
    }
}

pub struct NullMalwareExemptions;

#[async_trait::async_trait]
impl MalwareExemptionPort for NullMalwareExemptions {
    fn is_exempt(&self, _group_id: i64) -> bool {
        false
    }
    async fn reload(&self) -> Result<(), DomainError> {
        Ok(())
    }
}

pub struct NullScheduleProfileRepository;

#[async_trait::async_trait]
impl ScheduleProfileRepository for NullScheduleProfileRepository {
    async fn create(
        &self,
        _name: String,
        _tz: chrono_tz::Tz,
        _comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError> {
        unimplemented!()
    }
    async fn get_by_id(&self, _id: i64) -> Result<Option<ScheduleProfile>, DomainError> {
        Ok(None)
    }
    async fn get_all(&self) -> Result<Vec<ScheduleProfile>, DomainError> {
        Ok(vec![])
    }
    async fn update(
        &self,
        _id: i64,
        _name: Option<String>,
        _tz: Option<chrono_tz::Tz>,
        _comment: Option<String>,
    ) -> Result<ScheduleProfile, DomainError> {
        unimplemented!()
    }
    async fn delete(&self, _id: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_slots(&self, _profile_id: i64) -> Result<Vec<TimeSlot>, DomainError> {
        Ok(vec![])
    }
    async fn add_slot(
        &self,
        _pid: i64,
        _days: u8,
        _start: chrono::NaiveTime,
        _end: chrono::NaiveTime,
        _action: ScheduleAction,
    ) -> Result<TimeSlot, DomainError> {
        unimplemented!()
    }
    async fn delete_slot(&self, _slot_id: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn assign_to_group(&self, _group_id: i64, _profile_id: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn unassign_from_group(&self, _group_id: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_group_assignment(&self, _group_id: i64) -> Result<Option<i64>, DomainError> {
        Ok(None)
    }
    async fn get_all_group_assignments(&self) -> Result<Vec<(i64, i64)>, DomainError> {
        Ok(vec![])
    }
}
