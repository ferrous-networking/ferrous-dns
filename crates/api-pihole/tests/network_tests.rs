mod helpers;

use axum::http::StatusCode;
use helpers::ftl::{
    assert_ftl_shape, NetworkDevices, NetworkGateway, NetworkInterfaces, NetworkRoutes,
};

async fn get(uri: &str) -> serde_json::Value {
    get_from(helpers::create_test_db().await, uri).await
}

async fn get_from(pool: sqlx::SqlitePool, uri: &str) -> serde_json::Value {
    let app = helpers::create_pihole_test_app(pool).await;
    let (status, json) = helpers::send(app, "GET", uri).await;
    assert_eq!(status, StatusCode::OK, "GET {uri}: {json}");
    json
}

/// A laptop seen on two addresses, its MAC once in upper case, and a printer
/// without a MAC address.
async fn seed_devices() -> sqlx::SqlitePool {
    let pool = helpers::create_test_db().await;
    for (ip, mac, hostname, queries, last_seen) in [
        (
            "192.168.1.10",
            Some("AA:BB:CC:00:11:22"),
            Some("laptop"),
            5,
            "2026-10-01 10:00:00",
        ),
        (
            "192.168.1.11",
            Some("aa:bb:cc:00:11:22"),
            None,
            2,
            "2026-10-01 12:00:00",
        ),
        (
            "192.168.1.20",
            None,
            Some("printer"),
            1,
            "2026-10-01 08:00:00",
        ),
    ] {
        sqlx::query(
            "INSERT INTO clients (ip_address, mac_address, hostname, query_count, first_seen, last_seen)
             VALUES (?, ?, ?, ?, '2026-09-01 00:00:00', ?)",
        )
        .bind(ip)
        .bind(mac)
        .bind(hostname)
        .bind(queries)
        .bind(last_seen)
        .execute(&pool)
        .await
        .expect("failed to insert client");
    }
    pool
}

#[tokio::test]
async fn devices_group_clients_by_hardware_address() {
    let json = get_from(seed_devices().await, "/network/devices").await;

    let devices = assert_ftl_shape::<NetworkDevices>(&json).devices;
    let hwaddrs: Vec<&str> = devices
        .iter()
        .map(|d| d.hwaddr.as_deref().unwrap_or_default())
        .collect();
    // Most recently active first; no MAC → FTL's ip-<address> mock address.
    assert_eq!(hwaddrs, ["aa:bb:cc:00:11:22", "ip-192.168.1.20"]);

    let laptop = &devices[0];
    assert_eq!(laptop.num_queries, 7);
    assert!(laptop.first_seen > 0 && laptop.last_query > laptop.first_seen);
    let ips: Vec<(&str, Option<&str>)> = laptop
        .ips
        .iter()
        .map(|ip| (ip.ip.as_str(), ip.name.as_deref()))
        .collect();
    assert_eq!(
        ips,
        [("192.168.1.11", None), ("192.168.1.10", Some("laptop"))],
        "most recently seen address first"
    );
    assert_eq!(devices[1].ips[0].name.as_deref(), Some("printer"));
}

#[tokio::test]
async fn devices_honour_max_devices_and_max_addresses() {
    let json = get_from(
        seed_devices().await,
        "/network/devices?max_devices=1&max_addresses=1",
    )
    .await;

    let devices = assert_ftl_shape::<NetworkDevices>(&json).devices;
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].ips.len(), 1);
}

#[tokio::test]
async fn gateway_matches_the_ftl_schema() {
    let gateway = assert_ftl_shape::<NetworkGateway>(&get("/network/gateway").await).gateway;

    for entry in gateway {
        assert!(matches!(entry.family.as_str(), "inet" | "inet6"));
    }
}

#[tokio::test]
async fn routes_match_the_ftl_schema() {
    let routes = assert_ftl_shape::<NetworkRoutes>(&get("/network/routes").await).routes;

    for route in routes {
        assert!(matches!(route.family.as_str(), "inet" | "inet6"));
        assert!(!route.dst.is_empty());
    }
}

#[tokio::test]
async fn interfaces_match_the_ftl_schema() {
    let interfaces =
        assert_ftl_shape::<NetworkInterfaces>(&get("/network/interfaces").await).interfaces;

    if std::path::Path::new("/sys/class/net/lo").exists() {
        let lo = interfaces
            .iter()
            .find(|i| i.name == "lo")
            .expect("lo is listed");
        assert_eq!(lo.link_type.as_deref(), Some("loopback"));
    }
}
