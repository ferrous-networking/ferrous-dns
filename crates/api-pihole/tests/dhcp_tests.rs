mod helpers;

use axum::http::StatusCode;
use helpers::ftl::{assert_ftl_shape, DhcpLeases, ErrorReply};

#[tokio::test]
async fn leases_are_empty_as_on_a_pihole_without_dhcp() {
    let app = helpers::create_pihole_test_app(helpers::create_test_db().await).await;

    let (status, json) = helpers::send(app, "GET", "/dhcp/leases").await;

    assert_eq!(status, StatusCode::OK);
    assert!(assert_ftl_shape::<DhcpLeases>(&json).leases.is_empty());
}

#[tokio::test]
async fn deleting_a_lease_fails_as_with_dhcp_disabled() {
    // Live FTL 6.7.1 with DHCP off: 400, "Failed to delete DHCP lease",
    // hint "DHCP is not enabled".
    let app = helpers::create_pihole_test_app(helpers::create_test_db().await).await;

    let (status, json) = helpers::send(app, "DELETE", "/dhcp/leases/192.168.1.20").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let reply = assert_ftl_shape::<ErrorReply>(&json);
    assert_eq!(reply.error.key, "bad_request");
    assert_eq!(reply.error.message, "Failed to delete DHCP lease");
    assert_eq!(reply.error.hint.as_deref(), Some("DHCP is not enabled"));
}

#[tokio::test]
async fn deleting_a_lease_of_an_invalid_address_names_it() {
    let app = helpers::create_pihole_test_app(helpers::create_test_db().await).await;

    let (status, json) = helpers::send(app, "DELETE", "/dhcp/leases/not-an-ip").await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let reply = assert_ftl_shape::<ErrorReply>(&json);
    assert_eq!(reply.error.message, "The provided IP address is invalid");
    assert_eq!(reply.error.hint.as_deref(), Some("not-an-ip"));
}
