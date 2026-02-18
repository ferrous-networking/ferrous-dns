use ferrous_dns_application::ports::WhitelistRepository;
use ferrous_dns_application::use_cases::whitelist::GetWhitelistUseCase;
use ferrous_dns_domain::whitelist::WhitelistedDomain;
use std::sync::Arc;

mod helpers;
use helpers::MockWhitelistRepository;

#[tokio::test]
async fn test_get_empty_whitelist() {
    let repository = Arc::new(MockWhitelistRepository::new());
    let use_case = GetWhitelistUseCase::new(repository);

    let result = use_case.execute().await;

    assert!(result.is_ok());
    let domains = result.unwrap();
    assert_eq!(domains.len(), 0);
}

#[tokio::test]
async fn test_get_whitelist_with_domains() {
    let repository = Arc::new(MockWhitelistRepository::with_whitelisted_domains(vec![
        "safe.example.com",
        "trusted.com",
        "allowed.net",
    ]));

    let use_case = GetWhitelistUseCase::new(repository);

    let result = use_case.execute().await;

    assert!(result.is_ok());
    let domains = result.unwrap();
    assert_eq!(domains.len(), 3);
}

#[tokio::test]
async fn test_get_whitelist_returns_all_domains() {
    let repository = Arc::new(MockWhitelistRepository::with_whitelisted_domains(vec![
        "domain1.com",
        "domain2.com",
        "domain3.com",
        "domain4.com",
        "domain5.com",
    ]));

    let use_case = GetWhitelistUseCase::new(repository);

    let result = use_case.execute().await;

    assert!(result.is_ok());
    let domains = result.unwrap();
    assert_eq!(domains.len(), 5);

    let domain_names: Vec<String> = domains.iter().map(|d| d.domain.clone()).collect();
    assert!(domain_names.contains(&"domain1.com".to_string()));
    assert!(domain_names.contains(&"domain5.com".to_string()));
}

#[tokio::test]
async fn test_add_domain_to_empty_whitelist() {
    let repository = Arc::new(MockWhitelistRepository::new());

    let domain = WhitelistedDomain {
        domain: "safe.com".to_string(),
        id: None,
        added_at: None,
    };

    let result = repository.add_domain(&domain).await;
    assert!(result.is_ok());

    let all = repository.get_all().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].domain, "safe.com");
}

#[tokio::test]
async fn test_add_multiple_domains() {
    let repository = Arc::new(MockWhitelistRepository::new());

    let domains = vec![
        WhitelistedDomain {
            domain: "safe.com".to_string(),
            id: None,
            added_at: None,
        },
        WhitelistedDomain {
            domain: "trusted.com".to_string(),
            id: None,
            added_at: None,
        },
        WhitelistedDomain {
            domain: "allowed.com".to_string(),
            id: None,
            added_at: None,
        },
    ];

    for domain in domains {
        repository.add_domain(&domain).await.unwrap();
    }

    let all = repository.get_all().await.unwrap();
    assert_eq!(all.len(), 3);
}

#[tokio::test]
async fn test_remove_domain_from_whitelist() {
    let repository = Arc::new(MockWhitelistRepository::with_whitelisted_domains(vec![
        "safe.com",
        "trusted.com",
    ]));

    assert_eq!(repository.count().await, 2);

    let result = repository.remove_domain("safe.com").await;
    assert!(result.is_ok());

    assert_eq!(repository.count().await, 1);

    let all = repository.get_all().await.unwrap();
    assert!(!all.iter().any(|d| d.domain == "safe.com"));
    assert!(all.iter().any(|d| d.domain == "trusted.com"));
}

#[tokio::test]
async fn test_remove_nonexistent_domain() {
    let repository = Arc::new(MockWhitelistRepository::with_whitelisted_domains(vec![
        "safe.com",
    ]));

    let result = repository.remove_domain("nonexistent.com").await;
    assert!(result.is_ok());

    assert_eq!(repository.count().await, 1);
}

#[tokio::test]
async fn test_remove_all_domains() {
    let repository = Arc::new(MockWhitelistRepository::with_whitelisted_domains(vec![
        "domain1.com",
        "domain2.com",
        "domain3.com",
    ]));

    repository.remove_domain("domain1.com").await.unwrap();
    repository.remove_domain("domain2.com").await.unwrap();
    repository.remove_domain("domain3.com").await.unwrap();

    assert_eq!(repository.count().await, 0);
}

#[tokio::test]
async fn test_is_whitelisted_returns_true() {
    let repository = Arc::new(MockWhitelistRepository::with_whitelisted_domains(vec![
        "safe.com",
        "trusted.com",
    ]));

    assert!(repository.is_whitelisted("safe.com").await.unwrap());
    assert!(repository.is_whitelisted("trusted.com").await.unwrap());
}

#[tokio::test]
async fn test_is_whitelisted_returns_false() {
    let repository = Arc::new(MockWhitelistRepository::with_whitelisted_domains(vec![
        "safe.com",
    ]));

    assert!(!repository.is_whitelisted("ads.com").await.unwrap());
    assert!(!repository.is_whitelisted("unknown.com").await.unwrap());
}

#[tokio::test]
async fn test_is_whitelisted_empty_whitelist() {
    let repository = Arc::new(MockWhitelistRepository::new());

    assert!(!repository.is_whitelisted("any-domain.com").await.unwrap());
}

#[tokio::test]
async fn test_add_and_remove_workflow() {
    let repository = Arc::new(MockWhitelistRepository::new());

    assert_eq!(repository.count().await, 0);

    let domain = WhitelistedDomain {
        domain: "safe.com".to_string(),
        id: None,
        added_at: None,
    };
    repository.add_domain(&domain).await.unwrap();
    assert_eq!(repository.count().await, 1);
    assert!(repository.is_whitelisted("safe.com").await.unwrap());

    repository.remove_domain("safe.com").await.unwrap();
    assert_eq!(repository.count().await, 0);
    assert!(!repository.is_whitelisted("safe.com").await.unwrap());
}

#[tokio::test]
async fn test_clear_whitelist() {
    let repository = Arc::new(MockWhitelistRepository::with_whitelisted_domains(vec![
        "domain1.com",
        "domain2.com",
        "domain3.com",
    ]));

    assert_eq!(repository.count().await, 3);

    repository.clear().await;

    assert_eq!(repository.count().await, 0);
}

#[tokio::test]
async fn test_add_domains_after_clear() {
    let repository = Arc::new(MockWhitelistRepository::with_whitelisted_domains(vec![
        "old.com",
    ]));

    repository.clear().await;
    assert_eq!(repository.count().await, 0);

    repository
        .add_whitelisted_domains(vec!["new1.com", "new2.com"])
        .await;
    assert_eq!(repository.count().await, 2);

    assert!(!repository.is_whitelisted("old.com").await.unwrap());
    assert!(repository.is_whitelisted("new1.com").await.unwrap());
}

#[tokio::test]
async fn test_concurrent_reads() {
    let repository = Arc::new(MockWhitelistRepository::with_whitelisted_domains(vec![
        "safe.com",
        "trusted.com",
    ]));

    let repo1 = Arc::clone(&repository);
    let repo2 = Arc::clone(&repository);
    let repo3 = Arc::clone(&repository);

    let handle1 = tokio::spawn(async move { repo1.is_whitelisted("safe.com").await.unwrap() });

    let handle2 = tokio::spawn(async move { repo2.get_all().await.unwrap().len() });

    let handle3 = tokio::spawn(async move { repo3.is_whitelisted("trusted.com").await.unwrap() });

    let (wl1, count, wl2) = tokio::join!(handle1, handle2, handle3);

    assert!(wl1.unwrap());
    assert_eq!(count.unwrap(), 2);
    assert!(wl2.unwrap());
}
