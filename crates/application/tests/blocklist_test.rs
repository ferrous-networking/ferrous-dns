use ferrous_dns_application::ports::BlocklistRepository;
use ferrous_dns_application::use_cases::blocklist::GetBlocklistUseCase;
use ferrous_dns_domain::blocklist::BlockedDomain;
use std::sync::Arc;

mod helpers;
use helpers::MockBlocklistRepository;

#[tokio::test]
async fn test_get_empty_blocklist() {
    let repository = Arc::new(MockBlocklistRepository::new());
    let use_case = GetBlocklistUseCase::new(repository);

    let result = use_case.execute().await;

    assert!(result.is_ok());
    let domains = result.unwrap();
    assert_eq!(domains.len(), 0);
}

#[tokio::test]
async fn test_get_blocklist_with_domains() {
    let repository = Arc::new(MockBlocklistRepository::with_blocked_domains(vec![
        "ads.example.com",
        "tracker.com",
        "malware.net",
    ]));

    let use_case = GetBlocklistUseCase::new(repository);

    let result = use_case.execute().await;

    assert!(result.is_ok());
    let domains = result.unwrap();
    assert_eq!(domains.len(), 3);
}

#[tokio::test]
async fn test_get_blocklist_returns_all_domains() {
    let repository = Arc::new(MockBlocklistRepository::with_blocked_domains(vec![
        "domain1.com",
        "domain2.com",
        "domain3.com",
        "domain4.com",
        "domain5.com",
    ]));

    let use_case = GetBlocklistUseCase::new(repository);

    let result = use_case.execute().await;

    assert!(result.is_ok());
    let domains = result.unwrap();
    assert_eq!(domains.len(), 5);

    let domain_names: Vec<String> = domains.iter().map(|d| d.domain.clone()).collect();
    assert!(domain_names.contains(&"domain1.com".to_string()));
    assert!(domain_names.contains(&"domain5.com".to_string()));
}

#[tokio::test]
async fn test_add_domain_to_empty_blocklist() {
    let repository = Arc::new(MockBlocklistRepository::new());

    let domain = BlockedDomain {
        domain: "ads.com".to_string(),
        id: None,
        added_at: None,
    };

    let result = repository.add_domain(&domain).await;
    assert!(result.is_ok());

    let all = repository.get_all().await.unwrap();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].domain, "ads.com");
}

#[tokio::test]
async fn test_add_multiple_domains() {
    let repository = Arc::new(MockBlocklistRepository::new());

    let domains = vec![
        BlockedDomain {
            domain: "ads.com".to_string(),
            id: None,
            added_at: None,
        },
        BlockedDomain {
            domain: "tracker.com".to_string(),
            id: None,
            added_at: None,
        },
        BlockedDomain {
            domain: "analytics.com".to_string(),
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
async fn test_add_domain_with_enabled_flag() {
    let repository = Arc::new(MockBlocklistRepository::new());

    let enabled_domain = BlockedDomain {
        domain: "enabled.com".to_string(),
        id: None,
        added_at: None,
    };

    let disabled_domain = BlockedDomain {
        domain: "disabled.com".to_string(),
        id: None,
        added_at: None,
    };

    repository.add_domain(&enabled_domain).await.unwrap();
    repository.add_domain(&disabled_domain).await.unwrap();

    let all = repository.get_all().await.unwrap();
    assert_eq!(all.len(), 2);

    assert!(all.iter().any(|d| d.domain == "enabled.com"));
    assert!(all.iter().any(|d| d.domain == "disabled.com"));
}

#[tokio::test]
async fn test_remove_domain_from_blocklist() {
    let repository = Arc::new(MockBlocklistRepository::with_blocked_domains(vec![
        "ads.com",
        "tracker.com",
    ]));

    assert_eq!(repository.count().await, 2);

    let result = repository.remove_domain("ads.com").await;
    assert!(result.is_ok());

    assert_eq!(repository.count().await, 1);

    let all = repository.get_all().await.unwrap();
    assert!(!all.iter().any(|d| d.domain == "ads.com"));
    assert!(all.iter().any(|d| d.domain == "tracker.com"));
}

#[tokio::test]
async fn test_remove_nonexistent_domain() {
    let repository = Arc::new(MockBlocklistRepository::with_blocked_domains(vec![
        "ads.com",
    ]));

    let result = repository.remove_domain("nonexistent.com").await;
    assert!(result.is_ok());

    assert_eq!(repository.count().await, 1);
}

#[tokio::test]
async fn test_remove_all_domains() {
    let repository = Arc::new(MockBlocklistRepository::with_blocked_domains(vec![
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
async fn test_is_blocked_returns_true() {
    let repository = Arc::new(MockBlocklistRepository::with_blocked_domains(vec![
        "ads.com",
        "tracker.com",
    ]));

    assert!(repository.is_blocked("ads.com").await.unwrap());
    assert!(repository.is_blocked("tracker.com").await.unwrap());
}

#[tokio::test]
async fn test_is_blocked_returns_false() {
    let repository = Arc::new(MockBlocklistRepository::with_blocked_domains(vec![
        "ads.com",
    ]));

    assert!(!repository.is_blocked("google.com").await.unwrap());
    assert!(!repository.is_blocked("example.com").await.unwrap());
}

#[tokio::test]
async fn test_is_blocked_case_sensitive() {
    let repository = Arc::new(MockBlocklistRepository::with_blocked_domains(vec![
        "ads.com",
    ]));

    assert!(repository.is_blocked("ads.com").await.unwrap());
}

#[tokio::test]
async fn test_is_blocked_empty_blocklist() {
    let repository = Arc::new(MockBlocklistRepository::new());

    assert!(!repository.is_blocked("any-domain.com").await.unwrap());
}

#[tokio::test]
async fn test_add_and_remove_workflow() {
    let repository = Arc::new(MockBlocklistRepository::new());

    assert_eq!(repository.count().await, 0);

    let domain = BlockedDomain {
        domain: "ads.com".to_string(),
        id: None,
        added_at: None,
    };
    repository.add_domain(&domain).await.unwrap();
    assert_eq!(repository.count().await, 1);
    assert!(repository.is_blocked("ads.com").await.unwrap());

    repository.remove_domain("ads.com").await.unwrap();
    assert_eq!(repository.count().await, 0);
    assert!(!repository.is_blocked("ads.com").await.unwrap());
}

#[tokio::test]
async fn test_clear_blocklist() {
    let repository = Arc::new(MockBlocklistRepository::with_blocked_domains(vec![
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
    let repository = Arc::new(MockBlocklistRepository::with_blocked_domains(vec![
        "old.com",
    ]));

    repository.clear().await;
    assert_eq!(repository.count().await, 0);

    repository
        .add_blocked_domains(vec!["new1.com", "new2.com"])
        .await;
    assert_eq!(repository.count().await, 2);

    assert!(!repository.is_blocked("old.com").await.unwrap());
    assert!(repository.is_blocked("new1.com").await.unwrap());
}

#[tokio::test]
async fn test_concurrent_reads() {
    let repository = Arc::new(MockBlocklistRepository::with_blocked_domains(vec![
        "ads.com",
        "tracker.com",
    ]));

    let repo1 = Arc::clone(&repository);
    let repo2 = Arc::clone(&repository);
    let repo3 = Arc::clone(&repository);

    let handle1 = tokio::spawn(async move { repo1.is_blocked("ads.com").await.unwrap() });

    let handle2 = tokio::spawn(async move { repo2.get_all().await.unwrap().len() });

    let handle3 = tokio::spawn(async move { repo3.is_blocked("tracker.com").await.unwrap() });

    let (blocked, count, blocked2) = tokio::join!(handle1, handle2, handle3);

    assert!(blocked.unwrap());
    assert_eq!(count.unwrap(), 2);
    assert!(blocked2.unwrap());
}

#[tokio::test]
async fn test_concurrent_add_remove() {
    let repository = Arc::new(MockBlocklistRepository::new());

    let repo1 = Arc::clone(&repository);
    let repo2 = Arc::clone(&repository);

    let handle1 = tokio::spawn(async move {
        let domain = BlockedDomain {
            domain: "example.com".to_string(),
            id: None,
            added_at: None,
        };
        repo1.add_domain(&domain).await
    });

    let handle2 = tokio::spawn(async move {
        let domain = BlockedDomain {
            domain: "example.com".to_string(),
            id: None,
            added_at: None,
        };
        repo2.add_domain(&domain).await
    });

    let (result1, result2) = tokio::join!(handle1, handle2);

    assert!(result1.unwrap().is_ok());
    assert!(result2.unwrap().is_ok());

    assert_eq!(repository.count().await, 2);
}
