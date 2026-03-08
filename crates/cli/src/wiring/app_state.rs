use ferrous_dns_api::{
    AppState, AuthUseCases, BlockingUseCases, ClientUseCases, DnsUseCases, GroupUseCases,
    QueryUseCases, SafeSearchUseCases, ScheduleUseCases, ServiceUseCases,
};
use ferrous_dns_application::ports::{ConfigFilePersistence, UserProvider};
use ferrous_dns_application::use_cases::{
    ChangePasswordUseCase, CreateApiTokenUseCase, CreateLocalRecordUseCase, CreateUserUseCase,
    DeleteApiTokenUseCase, DeleteLocalRecordUseCase, DeleteUserUseCase, GetActiveSessionsUseCase,
    GetApiTokensUseCase, GetAuthStatusUseCase, GetUsersUseCase, LoginUseCase, LogoutUseCase,
    SetupPasswordUseCase, UpdateApiTokenUseCase, UpdateLocalRecordUseCase, ValidateApiTokenUseCase,
    ValidateSessionUseCase,
};
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::auth::{
    Argon2PasswordHasher, CompositeUserProvider, TomlAdminProvider,
};
use ferrous_dns_infrastructure::dns::UpstreamHealthAdapter;
use ferrous_dns_infrastructure::repositories::{SqliteConfigRepository, TomlConfigFilePersistence};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{DnsServices, Repositories, UseCases};

pub async fn build_app_state(
    use_cases: UseCases,
    repos: &Repositories,
    dns_services: &DnsServices,
    config: Arc<RwLock<Config>>,
    config_repo_pool: SqlitePool,
    config_path: Option<Arc<str>>,
) -> AppState {
    let config_repo: Arc<dyn ferrous_dns_application::ports::ConfigRepository> =
        Arc::new(SqliteConfigRepository::new(config_repo_pool));

    let auth_config = {
        let cfg = config.read().await;
        Arc::new(cfg.auth.clone())
    };

    let config_persistence: Arc<dyn ConfigFilePersistence> = Arc::new(TomlConfigFilePersistence);

    let password_hasher = Arc::new(Argon2PasswordHasher::new());

    let toml_admin = TomlAdminProvider::new(auth_config.admin.clone());
    let user_provider: Arc<dyn UserProvider> = Arc::new(CompositeUserProvider::new(
        toml_admin,
        repos.user.clone(),
        config.clone(),
        config_path
            .as_deref()
            .map(String::from)
            .or_else(Config::get_config_path),
        config_persistence.clone(),
    ));

    let auth = AuthUseCases {
        login: Arc::new(LoginUseCase::new(
            user_provider.clone(),
            repos.session.clone(),
            password_hasher.clone(),
            auth_config.clone(),
        )),
        logout: Arc::new(LogoutUseCase::new(repos.session.clone())),
        validate_session: Arc::new(ValidateSessionUseCase::new(repos.session.clone())),
        setup_password: Arc::new(SetupPasswordUseCase::new(
            user_provider.clone(),
            password_hasher.clone(),
            auth_config.admin.username.clone(),
        )),
        change_password: Arc::new(ChangePasswordUseCase::new(
            user_provider.clone(),
            password_hasher.clone(),
        )),
        get_auth_status: Arc::new(GetAuthStatusUseCase::new(config.clone())),
        get_active_sessions: Arc::new(GetActiveSessionsUseCase::new(repos.session.clone())),
        create_api_token: Arc::new(CreateApiTokenUseCase::new(repos.api_token.clone())),
        get_api_tokens: Arc::new(GetApiTokensUseCase::new(repos.api_token.clone())),
        update_api_token: Arc::new(UpdateApiTokenUseCase::new(repos.api_token.clone())),
        delete_api_token: Arc::new(DeleteApiTokenUseCase::new(repos.api_token.clone())),
        validate_api_token: Arc::new(ValidateApiTokenUseCase::new(repos.api_token.clone())),
        create_user: Arc::new(CreateUserUseCase::new(
            repos.user.clone(),
            user_provider.clone(),
            password_hasher,
        )),
        get_users: Arc::new(GetUsersUseCase::new(user_provider)),
        delete_user: Arc::new(DeleteUserUseCase::new(repos.user.clone())),
    };

    AppState {
        query: QueryUseCases {
            get_stats: use_cases.get_stats,
            get_queries: use_cases.get_queries,
            get_timeline: use_cases.get_timeline,
            get_query_rate: use_cases.get_query_rate,
            get_cache_stats: use_cases.get_cache_stats,
            get_top_blocked_domains: use_cases.get_top_blocked_domains,
            get_top_clients: use_cases.get_top_clients,
        },
        dns: DnsUseCases {
            cache: dns_services.cache.clone()
                as Arc<dyn ferrous_dns_application::ports::DnsCachePort>,
            create_local_record: Arc::new(
                CreateLocalRecordUseCase::new(config.clone(), config_repo.clone())
                    .with_ptr_registry(dns_services.ptr_registry.clone()),
            ),
            update_local_record: Arc::new(
                UpdateLocalRecordUseCase::new(config.clone(), config_repo.clone())
                    .with_ptr_registry(dns_services.ptr_registry.clone()),
            ),
            delete_local_record: Arc::new(
                DeleteLocalRecordUseCase::new(config.clone(), config_repo)
                    .with_ptr_registry(dns_services.ptr_registry.clone()),
            ),
            upstream_health: Arc::new(UpstreamHealthAdapter::new(
                dns_services.pool_manager.clone(),
                dns_services.health_checker.clone(),
            )),
        },
        groups: GroupUseCases {
            get_groups: use_cases.get_groups,
            create_group: use_cases.create_group,
            update_group: use_cases.update_group,
            delete_group: use_cases.delete_group,
            assign_client_group: use_cases.assign_client_group,
        },
        clients: ClientUseCases {
            get_clients: use_cases.get_clients,
            create_manual_client: use_cases.create_manual_client,
            update_client: use_cases.update_client,
            delete_client: use_cases.delete_client,
            get_client_subnets: use_cases.get_client_subnets,
            create_client_subnet: use_cases.create_client_subnet,
            delete_client_subnet: use_cases.delete_client_subnet,
            subnet_matcher: use_cases.subnet_matcher.clone(),
        },
        blocking: BlockingUseCases {
            get_blocklist: use_cases.get_blocklist,
            get_blocklist_sources: use_cases.get_blocklist_sources,
            create_blocklist_source: use_cases.create_blocklist_source,
            update_blocklist_source: use_cases.update_blocklist_source,
            delete_blocklist_source: use_cases.delete_blocklist_source,
            get_whitelist: use_cases.get_whitelist,
            get_whitelist_sources: use_cases.get_whitelist_sources,
            create_whitelist_source: use_cases.create_whitelist_source,
            update_whitelist_source: use_cases.update_whitelist_source,
            delete_whitelist_source: use_cases.delete_whitelist_source,
            get_managed_domains: use_cases.get_managed_domains,
            create_managed_domain: use_cases.create_managed_domain,
            update_managed_domain: use_cases.update_managed_domain,
            delete_managed_domain: use_cases.delete_managed_domain,
            get_regex_filters: use_cases.get_regex_filters,
            create_regex_filter: use_cases.create_regex_filter,
            update_regex_filter: use_cases.update_regex_filter,
            delete_regex_filter: use_cases.delete_regex_filter,
            get_block_filter_stats: use_cases.get_block_filter_stats,
        },
        services: ServiceUseCases {
            get_service_catalog: use_cases.get_service_catalog,
            get_blocked_services: use_cases.get_blocked_services,
            block_service: use_cases.block_service,
            unblock_service: use_cases.unblock_service,
            create_custom_service: use_cases.create_custom_service,
            get_custom_services: use_cases.get_custom_services,
            update_custom_service: use_cases.update_custom_service,
            delete_custom_service: use_cases.delete_custom_service,
        },
        safe_search: SafeSearchUseCases {
            get_configs: use_cases.get_safe_search_configs,
            toggle: use_cases.toggle_safe_search,
            delete_configs: use_cases.delete_safe_search_configs,
        },
        schedule: ScheduleUseCases {
            get_profiles: use_cases.get_schedule_profiles,
            create_profile: use_cases.create_schedule_profile,
            update_profile: use_cases.update_schedule_profile,
            delete_profile: use_cases.delete_schedule_profile,
            manage_slots: use_cases.manage_time_slots,
            assign_profile: use_cases.assign_schedule_profile,
        },
        auth,
        config,
        config_file_persistence: config_persistence,
        config_path,
    }
}
