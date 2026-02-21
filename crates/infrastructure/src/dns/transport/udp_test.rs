use super::*;

fn addr() -> SocketAddr {
    "8.8.8.8:53".parse().unwrap()
}

#[test]
fn test_validate_response_id_matching_ids_ok() {
    let query = [0xAB, 0xCD, 0x01, 0x00];
    let response = [0xAB, 0xCD, 0x81, 0x80];
    assert!(validate_response_id(&query, &response, addr()).is_ok());
}

#[test]
fn test_validate_response_id_mismatch_returns_error() {
    let query = [0xAB, 0xCD, 0x01, 0x00];
    let response = [0x12, 0x34, 0x81, 0x80];
    let result = validate_response_id(&query, &response, addr());
    assert!(result.is_err(), "Mismatched DNS IDs must return an error");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("mismatch"),
        "Error message should mention mismatch: {}",
        err
    );
}

#[test]
fn test_validate_response_id_short_query_returns_error() {
    let query = [0xAB];
    let response = [0xAB, 0xCD, 0x81, 0x80];
    assert!(validate_response_id(&query, &response, addr()).is_err());
}

#[test]
fn test_validate_response_id_short_response_returns_error() {
    let query = [0xAB, 0xCD, 0x01, 0x00];
    let response = [0xAB];
    assert!(validate_response_id(&query, &response, addr()).is_err());
}
