use ferrous_dns_application::use_cases::DeleteClientUseCase;
use ferrous_dns_domain::{Client, DomainError};
use std::sync::Arc;

mod helpers;
use helpers::MockClientRepository;

fn create_test_client(id: i64, ip: &str) -> Client {
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
    }
}

fn create_test_client_with_data(
    id: i64,
    ip: &str,
    mac: Option<&str>,
    hostname: Option<&str>,
    query_count: u64,
) -> Client {
    let now = chrono::Utc::now().to_rfc3339();
    Client {
        id: Some(id),
        ip_address: ip.parse().unwrap(),
        mac_address: mac.map(Arc::from),
        hostname: hostname.map(Arc::from),
        first_seen: Some(now.clone()),
        last_seen: Some(now.clone()),
        query_count,
        last_mac_update: mac.map(|_| chrono::Utc::now().timestamp()),
        last_hostname_update: hostname.map(|_| chrono::Utc::now().timestamp()),
        group_id: Some(1),
    }
}

#[tokio::test]
async fn test_delete_existing_client() {
    let client = create_test_client_with_data(
        1,
        "192.168.1.100",
        Some("aa:bb:cc:dd:ee:ff"),
        Some("test-device.local"),
        10,
    );

    let repository = Arc::new(MockClientRepository::with_clients(vec![client]).await);
    let use_case = DeleteClientUseCase::new(repository.clone());

    assert_eq!(repository.count().await, 1);

    let result = use_case.execute(1).await;

    assert!(result.is_ok());
    assert_eq!(repository.count().await, 0);
}

#[tokio::test]
async fn test_delete_nonexistent_client() {
    let repository = Arc::new(MockClientRepository::new());
    let use_case = DeleteClientUseCase::new(repository);

    let result = use_case.execute(999).await;

    assert!(result.is_err());
    assert!(matches!(result, Err(DomainError::ClientNotFound(_))));

    if let Err(DomainError::ClientNotFound(msg)) = result {
        assert!(msg.contains("999"));
    }
}

#[tokio::test]
async fn test_delete_client_from_multiple() {
    let clients = vec![
        create_test_client_with_data(1, "192.168.1.100", None, None, 5),
        create_test_client_with_data(2, "192.168.1.101", None, None, 3),
        create_test_client_with_data(3, "192.168.1.102", None, None, 8),
    ];

    let repository = Arc::new(MockClientRepository::with_clients(clients).await);
    let use_case = DeleteClientUseCase::new(repository.clone());

    assert_eq!(repository.count().await, 3);

    let result = use_case.execute(2).await;

    assert!(result.is_ok());
    assert_eq!(repository.count().await, 2);

    let remaining = repository.get_all_clients().await;
    assert!(!remaining.iter().any(|c| c.id == Some(2)));
    assert!(remaining.iter().any(|c| c.id == Some(1)));
    assert!(remaining.iter().any(|c| c.id == Some(3)));
}

#[tokio::test]
async fn test_delete_all_clients_sequentially() {
    let clients = vec![
        create_test_client(1, "192.168.1.100"),
        create_test_client(2, "192.168.1.101"),
    ];

    let repository = Arc::new(MockClientRepository::with_clients(clients).await);
    let use_case = DeleteClientUseCase::new(repository.clone());

    assert_eq!(repository.count().await, 2);

    use_case.execute(1).await.unwrap();
    assert_eq!(repository.count().await, 1);

    use_case.execute(2).await.unwrap();
    assert_eq!(repository.count().await, 0);
}

#[tokio::test]
async fn test_delete_client_idempotency() {
    let client = create_test_client(1, "192.168.1.100");

    let repository = Arc::new(MockClientRepository::with_clients(vec![client]).await);
    let use_case = DeleteClientUseCase::new(repository.clone());

    let result1 = use_case.execute(1).await;
    assert!(result1.is_ok());
    assert_eq!(repository.count().await, 0);

    let result2 = use_case.execute(1).await;

    assert!(result2.is_err());
    assert!(matches!(result2, Err(DomainError::ClientNotFound(_))));
}

#[tokio::test]
async fn test_delete_client_with_complete_data() {
    let mut client = create_test_client_with_data(
        42,
        "10.0.0.50",
        Some("11:22:33:44:55:66"),
        Some("my-awesome-device.local"),
        1000,
    );
    client.group_id = Some(5);

    let repository = Arc::new(MockClientRepository::with_clients(vec![client]).await);
    let use_case = DeleteClientUseCase::new(repository.clone());

    let result = use_case.execute(42).await;

    assert!(result.is_ok());
    assert_eq!(repository.count().await, 0);
}

#[tokio::test]
async fn test_delete_client_validates_existence_first() {
    let repository = Arc::new(MockClientRepository::new());
    let use_case = DeleteClientUseCase::new(repository);

    let result = use_case.execute(1).await;

    assert!(result.is_err());
    match result {
        Err(DomainError::ClientNotFound(msg)) => {
            assert!(msg.contains("1"));
            assert!(msg.contains("not found"));
        }
        _ => panic!("Expected ClientNotFound error"),
    }
}

#[tokio::test]
async fn test_delete_with_zero_id() {
    let repository = Arc::new(MockClientRepository::new());
    let use_case = DeleteClientUseCase::new(repository);

    let result = use_case.execute(0).await;

    assert!(result.is_err());
    assert!(matches!(result, Err(DomainError::ClientNotFound(_))));
}

#[tokio::test]
async fn test_delete_with_negative_id() {
    let repository = Arc::new(MockClientRepository::new());
    let use_case = DeleteClientUseCase::new(repository);

    let result = use_case.execute(-1).await;

    assert!(result.is_err());
    assert!(matches!(result, Err(DomainError::ClientNotFound(_))));
}

#[tokio::test]
async fn test_delete_with_very_large_id() {
    let repository = Arc::new(MockClientRepository::new());
    let use_case = DeleteClientUseCase::new(repository);

    let result = use_case.execute(i64::MAX).await;

    assert!(result.is_err());
    assert!(matches!(result, Err(DomainError::ClientNotFound(_))));
}

#[tokio::test]
async fn test_concurrent_deletes_different_clients() {
    let clients = vec![
        create_test_client(1, "192.168.1.1"),
        create_test_client(2, "192.168.1.2"),
        create_test_client(3, "192.168.1.3"),
    ];

    let repository = Arc::new(MockClientRepository::with_clients(clients).await);
    let use_case = Arc::new(DeleteClientUseCase::new(repository.clone()));

    let uc1 = Arc::clone(&use_case);
    let uc2 = Arc::clone(&use_case);
    let uc3 = Arc::clone(&use_case);

    let handle1 = tokio::spawn(async move { uc1.execute(1).await });
    let handle2 = tokio::spawn(async move { uc2.execute(2).await });
    let handle3 = tokio::spawn(async move { uc3.execute(3).await });

    let (result1, result2, result3) = tokio::join!(handle1, handle2, handle3);

    assert!(result1.unwrap().is_ok());
    assert!(result2.unwrap().is_ok());
    assert!(result3.unwrap().is_ok());
    assert_eq!(repository.count().await, 0);
}

#[tokio::test]
async fn test_concurrent_delete_same_client() {
    let client = create_test_client(1, "192.168.1.100");

    let repository = Arc::new(MockClientRepository::with_clients(vec![client]).await);
    let use_case = Arc::new(DeleteClientUseCase::new(repository.clone()));

    let uc1 = Arc::clone(&use_case);
    let uc2 = Arc::clone(&use_case);

    let handle1 = tokio::spawn(async move { uc1.execute(1).await });
    let handle2 = tokio::spawn(async move { uc2.execute(1).await });

    let (result1, result2) = tokio::join!(handle1, handle2);

    let results = [result1.unwrap(), result2.unwrap()];
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let failures = results.iter().filter(|r| r.is_err()).count();

    assert_eq!(successes, 1, "Exactly one delete should succeed");
    assert_eq!(failures, 1, "Exactly one delete should fail");
    assert_eq!(repository.count().await, 0);
}
