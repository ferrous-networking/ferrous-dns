mod helpers;

use ferrous_dns_application::ports::{DohIdRepository, GroupRepository};
use ferrous_dns_application::use_cases::{
    CreateDohIdUseCase, DeleteDohIdUseCase, GetDohIdsUseCase, UpdateDohIdUseCase,
};
use ferrous_dns_domain::{DohId, DomainError};
use helpers::{MockDohIdRepository, MockGroupRepository};
use std::sync::Arc;

#[tokio::test]
async fn test_create_doh_id_generates_valid_uuid_v4_by_default() {
    let doh_repo = Arc::new(MockDohIdRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let uc = CreateDohIdUseCase::new(doh_repo, group_repo);

    let created = uc
        .execute(
            "  Alice's iPhone  ".to_string(),
            None,
            1,
            Some("Personal phone".to_string()),
        )
        .await
        .unwrap();

    assert_eq!(created.id, Some(1));
    assert_eq!(created.name.as_ref(), "Alice's iPhone");
    assert_eq!(created.group_id, 1);
    assert_eq!(created.comment.as_deref(), Some("Personal phone"));
    assert_eq!(created.client_id.len(), 36);
    assert!(DohId::validate_client_id(&created.client_id).is_ok());

    let parts: Vec<&str> = created.client_id.split('-').collect();
    assert_eq!(parts.len(), 5);
    assert!(parts[2].starts_with('4'));
    assert!(matches!(parts[3].as_bytes()[0], b'8' | b'9' | b'a' | b'b'));
}

#[tokio::test]
async fn test_create_doh_id_with_custom_client_id() {
    let doh_repo = Arc::new(MockDohIdRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let uc = CreateDohIdUseCase::new(doh_repo.clone(), group_repo);

    let created = uc
        .execute(
            "Kids iPad".to_string(),
            Some("kids-ipad-1".to_string()),
            1,
            None,
        )
        .await
        .unwrap();

    assert_eq!(created.client_id.as_ref(), "kids-ipad-1");
    let looked_up = doh_repo
        .get_by_client_id("kids-ipad-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(looked_up.name.as_ref(), "Kids iPad");
}

#[tokio::test]
async fn test_create_doh_id_rejects_invalid_inputs_and_missing_group() {
    let doh_repo = Arc::new(MockDohIdRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let uc = CreateDohIdUseCase::new(doh_repo, group_repo);

    assert!(matches!(
        uc.execute("   ".to_string(), None, 1, None).await,
        Err(DomainError::InvalidDohId(_))
    ));
    assert!(matches!(
        uc.execute("Phone".to_string(), Some("Bad_ID".to_string()), 1, None)
            .await,
        Err(DomainError::InvalidDohId(_))
    ));
    assert!(matches!(
        uc.execute("Phone".to_string(), None, 1, Some("x".repeat(501)),)
            .await,
        Err(DomainError::InvalidDohId(_))
    ));
    assert!(matches!(
        uc.execute("Phone".to_string(), None, 999, None).await,
        Err(DomainError::GroupNotFound(999))
    ));
}

#[tokio::test]
async fn test_create_doh_id_rejects_duplicates() {
    let doh_repo = Arc::new(MockDohIdRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let uc = CreateDohIdUseCase::new(doh_repo, group_repo);

    uc.execute(
        "Laptop".to_string(),
        Some("work-laptop".to_string()),
        1,
        None,
    )
    .await
    .unwrap();

    assert!(matches!(
        uc.execute("Laptop".to_string(), None, 1, None).await,
        Err(DomainError::DohIdConflict(_))
    ));
    assert!(matches!(
        uc.execute(
            "Other Laptop".to_string(),
            Some("work-laptop".to_string()),
            1,
            None,
        )
        .await,
        Err(DomainError::DohIdConflict(_))
    ));
}

#[tokio::test]
async fn test_update_get_and_delete_doh_id() {
    let doh_repo = Arc::new(MockDohIdRepository::new());
    let group_repo = Arc::new(MockGroupRepository::new());
    let kids_group = group_repo
        .create("Kids".to_string(), None, true, true)
        .await
        .unwrap();

    let create_uc = CreateDohIdUseCase::new(doh_repo.clone(), group_repo.clone());
    let get_uc = GetDohIdsUseCase::new(doh_repo.clone());
    let update_uc = UpdateDohIdUseCase::new(doh_repo.clone(), group_repo);
    let delete_uc = DeleteDohIdUseCase::new(doh_repo);

    let created = create_uc
        .execute(
            "Tablet".to_string(),
            Some("tablet-old".to_string()),
            1,
            Some("Initial comment".to_string()),
        )
        .await
        .unwrap();
    let id = created.id.unwrap();

    // Update keeping existing client_id and clearing comment.
    let updated = update_uc
        .execute(
            id,
            "Kids Tablet".to_string(),
            None,
            kids_group.id.unwrap(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(updated.name.as_ref(), "Kids Tablet");
    assert_eq!(updated.client_id.as_ref(), "tablet-old");
    assert_eq!(updated.group_id, kids_group.id.unwrap());
    assert!(updated.comment.is_none());

    // Update rotating client_id.
    let rotated = update_uc
        .execute(
            id,
            "Kids Tablet".to_string(),
            Some("tablet-new".to_string()),
            kids_group.id.unwrap(),
            Some("Rotated".to_string()),
        )
        .await
        .unwrap();
    assert_eq!(rotated.client_id.as_ref(), "tablet-new");
    assert_eq!(rotated.comment.as_deref(), Some("Rotated"));

    assert_eq!(get_uc.get_all().await.unwrap().len(), 1);
    assert!(get_uc.get_by_id(id).await.unwrap().is_some());

    // Not found on update/delete of unknown id.
    assert!(matches!(
        update_uc
            .execute(999, "Ghost".to_string(), None, 1, None)
            .await,
        Err(DomainError::DohIdNotFound(999))
    ));

    delete_uc.execute(id).await.unwrap();
    assert!(get_uc.get_by_id(id).await.unwrap().is_none());
    assert!(matches!(
        delete_uc.execute(id).await,
        Err(DomainError::DohIdNotFound(_))
    ));
}
