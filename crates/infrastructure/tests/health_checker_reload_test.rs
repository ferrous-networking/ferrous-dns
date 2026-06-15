use ferrous_dns_domain::DnsProtocol;
use ferrous_dns_infrastructure::dns::load_balancer::HealthChecker;
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn proto(s: &str) -> Arc<DnsProtocol> {
    Arc::new(s.parse::<DnsProtocol>().expect("valid protocol"))
}

/// The probe loop must read the live server set on every tick: a server added
/// after start (as happens on a hot pool reload) has to start being probed.
#[tokio::test]
async fn health_loop_picks_up_servers_added_after_start() {
    let checker = Arc::new(HealthChecker::new(1, 1));

    let server_a = proto("udp://127.0.0.1:1");
    let server_b = proto("udp://127.0.0.1:2");

    // Backing set the provider reads from; starts with only server A.
    let live: Arc<Mutex<Vec<Arc<DnsProtocol>>>> = Arc::new(Mutex::new(vec![server_a.clone()]));

    let provider_live = Arc::clone(&live);
    let run_checker = Arc::clone(&checker);
    tokio::spawn(async move {
        run_checker
            .run(move || provider_live.lock().unwrap().clone(), 1, 300)
            .await;
    });

    // After the first tick, only server A has been probed.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        checker.get_health_info(&server_a).is_some(),
        "server A should have been probed"
    );
    assert!(
        checker.get_health_info(&server_b).is_none(),
        "server B is not in the live set yet, must not be probed"
    );

    // Simulate a hot reload that adds server B.
    live.lock().unwrap().push(server_b.clone());

    // Next tick must pick it up.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        checker.get_health_info(&server_b).is_some(),
        "server B added after start should now be probed without a restart"
    );
}
