#![allow(dead_code)]

use ferrous_dns_api::BackupUseCases;
use ferrous_dns_application::ports::{
    BlocklistSourceCreator, BlocklistSourceRepository, ConfigFilePersistence, ConfigRepository,
    GroupCreator, GroupRepository, LocalRecordCreator,
};
use ferrous_dns_application::use_cases::{
    CreateBlocklistSourceUseCase, CreateGroupUseCase, CreateLocalRecordUseCase,
    ExportConfigUseCase, ImportConfigUseCase,
};
use ferrous_dns_domain::{BlocklistSource, Client, Config, DomainError, Group};
use std::sync::Arc;
use tokio::sync::RwLock;

struct NullGroupRepository;

#[async_trait::async_trait]
impl GroupRepository for NullGroupRepository {
    async fn create(&self, _name: String, _comment: Option<String>) -> Result<Group, DomainError> {
        Err(DomainError::IoError("test stub".to_string()))
    }
    async fn get_by_id(&self, _id: i64) -> Result<Option<Group>, DomainError> {
        Ok(None)
    }
    async fn get_by_name(&self, _name: &str) -> Result<Option<Group>, DomainError> {
        Ok(None)
    }
    async fn get_all(&self) -> Result<Vec<Group>, DomainError> {
        Ok(vec![])
    }
    async fn get_all_with_client_counts(&self) -> Result<Vec<(Group, u64)>, DomainError> {
        Ok(vec![])
    }
    async fn update(
        &self,
        _id: i64,
        _name: Option<String>,
        _enabled: Option<bool>,
        _comment: Option<String>,
    ) -> Result<Group, DomainError> {
        Err(DomainError::IoError("test stub".to_string()))
    }
    async fn delete(&self, _id: i64) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_clients_in_group(&self, _group_id: i64) -> Result<Vec<Client>, DomainError> {
        Ok(vec![])
    }
    async fn count_clients_in_group(&self, _group_id: i64) -> Result<u64, DomainError> {
        Ok(0)
    }
}

struct NullBlocklistSourceRepository;

#[async_trait::async_trait]
impl BlocklistSourceRepository for NullBlocklistSourceRepository {
    async fn create(
        &self,
        _name: String,
        _url: Option<String>,
        _group_ids: Vec<i64>,
        _comment: Option<String>,
        _enabled: bool,
    ) -> Result<BlocklistSource, DomainError> {
        Err(DomainError::IoError("test stub".to_string()))
    }
    async fn get_by_id(&self, _id: i64) -> Result<Option<BlocklistSource>, DomainError> {
        Ok(None)
    }
    async fn get_all(&self) -> Result<Vec<BlocklistSource>, DomainError> {
        Ok(vec![])
    }
    async fn update(
        &self,
        _id: i64,
        _name: Option<String>,
        _url: Option<Option<String>>,
        _group_ids: Option<Vec<i64>>,
        _comment: Option<String>,
        _enabled: Option<bool>,
    ) -> Result<BlocklistSource, DomainError> {
        Err(DomainError::IoError("test stub".to_string()))
    }
    async fn delete(&self, _id: i64) -> Result<(), DomainError> {
        Ok(())
    }
}

struct NullConfigFilePersistence;

impl ConfigFilePersistence for NullConfigFilePersistence {
    fn save_config_to_file(&self, _config: &Config, _path: &str) -> Result<(), String> {
        Ok(())
    }
}

struct NullConfigRepository;

#[async_trait::async_trait]
impl ConfigRepository for NullConfigRepository {
    async fn save_local_records(&self, _config: &Config) -> Result<(), DomainError> {
        Ok(())
    }
}

pub fn build_test_backup_use_cases(config: Arc<RwLock<Config>>) -> BackupUseCases {
    let group_repo: Arc<dyn GroupRepository> = Arc::new(NullGroupRepository);
    let blocklist_source_repo: Arc<dyn BlocklistSourceRepository> =
        Arc::new(NullBlocklistSourceRepository);

    let group_creator: Arc<dyn GroupCreator> =
        Arc::new(CreateGroupUseCase::new(group_repo.clone()));
    let blocklist_source_creator: Arc<dyn BlocklistSourceCreator> = Arc::new(
        CreateBlocklistSourceUseCase::new(blocklist_source_repo.clone(), group_repo.clone()),
    );
    let local_record_creator: Arc<dyn LocalRecordCreator> = Arc::new(
        CreateLocalRecordUseCase::new(config.clone(), Arc::new(NullConfigRepository)),
    );

    BackupUseCases {
        export: Arc::new(ExportConfigUseCase::new(
            config.clone(),
            group_repo,
            blocklist_source_repo,
        )),
        import: Arc::new(ImportConfigUseCase::new(
            config,
            Arc::new(NullConfigFilePersistence),
            None,
            group_creator,
            blocklist_source_creator,
            local_record_creator,
        )),
    }
}
