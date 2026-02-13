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
        last_mac_update: mac.map(|_| now.clone()),
        last_hostname_update: hostname.map(|_| now.clone()),
        group_id: Some(1),
    }
}

// ============================================================================
// Tests: Delete Client Use Case
// ============================================================================

#[tokio::test]
async fn test_delete_existing_client() {
    // Arrange
    let client = create_test_client_with_data(
        1,
        "192.168.1.100",
        Some("aa:bb:cc:dd:ee:ff"),
        Some("test-device.local"),
        10,
    );

    let repository = Arc::new(MockClientRepository::with_clients(vec![client]).await);
    let use_case = DeleteClientUseCase::new(repository.clone());

    // Verify client exists
    assert_eq!(repository.count().await, 1);

    // Act
    let result = use_case.execute(1).await;

    // Assert
    assert!(result.is_ok());
    assert_eq!(repository.count().await, 0);
}

#[tokio::test]
async fn test_delete_nonexistent_client() {
    // Arrange
    let repository = Arc::new(MockClientRepository::new());
    let use_case = DeleteClientUseCase::new(repository);

    // Act
    let result = use_case.execute(999).await;

    // Assert
    assert!(result.is_err());
    assert!(matches!(result, Err(DomainError::ClientNotFound(_))));

    if let Err(DomainError::ClientNotFound(msg)) = result {
        assert!(msg.contains("999"));
    }
}

#[tokio::test]
async fn test_delete_client_from_multiple() {
    // Arrange
    let clients = vec![
        create_test_client_with_data(1, "192.168.1.100", None, None, 5),
        create_test_client_with_data(2, "192.168.1.101", None, None, 3),
        create_test_client_with_data(3, "192.168.1.102", None, None, 8),
    ];

    let repository = Arc::new(MockClientRepository::with_clients(clients).await);
    let use_case = DeleteClientUseCase::new(repository.clone());

    // Verify 3 clients exist
    assert_eq!(repository.count().await, 3);

    // Act - delete client with ID 2
    let result = use_case.execute(2).await;

    // Assert
    assert!(result.is_ok());
    assert_eq!(repository.count().await, 2);

    // Verify the correct client was deleted
    let remaining = repository.get_all_clients().await;
    assert!(!remaining.iter().any(|c| c.id == Some(2)));
    assert!(remaining.iter().any(|c| c.id == Some(1)));
    assert!(remaining.iter().any(|c| c.id == Some(3)));
}

#[tokio::test]
async fn test_delete_all_clients_sequentially() {
    // Arrange
    let clients = vec![
        create_test_client(1, "192.168.1.100"),
        create_test_client(2, "192.168.1.101"),
    ];

    let repository = Arc::new(MockClientRepository::with_clients(clients).await);
    let use_case = DeleteClientUseCase::new(repository.clone());

    // Act & Assert
    assert_eq!(repository.count().await, 2);

    use_case.execute(1).await.unwrap();
    assert_eq!(repository.count().await, 1);

    use_case.execute(2).await.unwrap();
    assert_eq!(repository.count().await, 0);
}

#[tokio::test]
async fn test_delete_client_idempotency() {
    // Arrange
    let client = create_test_client(1, "192.168.1.100");

    let repository = Arc::new(MockClientRepository::with_clients(vec![client]).await);
    let use_case = DeleteClientUseCase::new(repository.clone());

    // Act - first delete should succeed
    let result1 = use_case.execute(1).await;
    assert!(result1.is_ok());
    assert_eq!(repository.count().await, 0);

    // Act - second delete should fail (client already deleted)
    let result2 = use_case.execute(1).await;

    // Assert
    assert!(result2.is_err());
    assert!(matches!(result2, Err(DomainError::ClientNotFound(_))));
}

#[tokio::test]
async fn test_delete_client_with_complete_data() {
    // Arrange - client with all fields populated
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

    // Act
    let result = use_case.execute(42).await;

    // Assert - should delete regardless of data completeness
    assert!(result.is_ok());
    assert_eq!(repository.count().await, 0);
}

#[tokio::test]
async fn test_delete_client_validates_existence_first() {
    // Arrange
    let repository = Arc::new(MockClientRepository::new());
    let use_case = DeleteClientUseCase::new(repository);

    // Act - try to delete from empty repository
    let result = use_case.execute(1).await;

    // Assert - should fail with ClientNotFound, not NotFound
    assert!(result.is_err());
    match result {
        Err(DomainError::ClientNotFound(msg)) => {
            assert!(msg.contains("1"));
            assert!(msg.contains("not found"));
        }
        _ => panic!("Expected ClientNotFound error"),
    }
}

// ============================================================================
// Tests: Edge Cases
// ============================================================================

#[tokio::test]
async fn test_delete_with_zero_id() {
    // Arrange
    let repository = Arc::new(MockClientRepository::new());
    let use_case = DeleteClientUseCase::new(repository);

    // Act
    let result = use_case.execute(0).await;

    // Assert
    assert!(result.is_err());
    assert!(matches!(result, Err(DomainError::ClientNotFound(_))));
}

#[tokio::test]
async fn test_delete_with_negative_id() {
    // Arrange
    let repository = Arc::new(MockClientRepository::new());
    let use_case = DeleteClientUseCase::new(repository);

    // Act
    let result = use_case.execute(-1).await;

    // Assert
    assert!(result.is_err());
    assert!(matches!(result, Err(DomainError::ClientNotFound(_))));
}

#[tokio::test]
async fn test_delete_with_very_large_id() {
    // Arrange
    let repository = Arc::new(MockClientRepository::new());
    let use_case = DeleteClientUseCase::new(repository);

    // Act
    let result = use_case.execute(i64::MAX).await;

    // Assert
    assert!(result.is_err());
    assert!(matches!(result, Err(DomainError::ClientNotFound(_))));
}

// ============================================================================
// Tests: Concurrent Operations
// ============================================================================

#[tokio::test]
async fn test_concurrent_deletes_different_clients() {
    // Arrange
    let clients = vec![
        create_test_client(1, "192.168.1.1"),
        create_test_client(2, "192.168.1.2"),
        create_test_client(3, "192.168.1.3"),
    ];

    let repository = Arc::new(MockClientRepository::with_clients(clients).await);
    let use_case = Arc::new(DeleteClientUseCase::new(repository.clone()));

    // Act - delete 3 clients concurrently
    let uc1 = Arc::clone(&use_case);
    let uc2 = Arc::clone(&use_case);
    let uc3 = Arc::clone(&use_case);

    let handle1 = tokio::spawn(async move { uc1.execute(1).await });
    let handle2 = tokio::spawn(async move { uc2.execute(2).await });
    let handle3 = tokio::spawn(async move { uc3.execute(3).await });

    let (result1, result2, result3) = tokio::join!(handle1, handle2, handle3);

    // Assert - all should succeed
    assert!(result1.unwrap().is_ok());
    assert!(result2.unwrap().is_ok());
    assert!(result3.unwrap().is_ok());
    assert_eq!(repository.count().await, 0);
}

#[tokio::test]
async fn test_concurrent_delete_same_client() {
    // Arrange
    let client = create_test_client(1, "192.168.1.100");

    let repository = Arc::new(MockClientRepository::with_clients(vec![client]).await);
    let use_case = Arc::new(DeleteClientUseCase::new(repository.clone()));

    // Act - try to delete same client concurrently
    let uc1 = Arc::clone(&use_case);
    let uc2 = Arc::clone(&use_case);

    let handle1 = tokio::spawn(async move { uc1.execute(1).await });
    let handle2 = tokio::spawn(async move { uc2.execute(1).await });

    let (result1, result2) = tokio::join!(handle1, handle2);

    // Assert - one should succeed, one should fail
    let results = [result1.unwrap(), result2.unwrap()];
    let successes = results.iter().filter(|r| r.is_ok()).count();
    let failures = results.iter().filter(|r| r.is_err()).count();

    assert_eq!(successes, 1, "Exactly one delete should succeed");
    assert_eq!(failures, 1, "Exactly one delete should fail");
    assert_eq!(repository.count().await, 0);
}
