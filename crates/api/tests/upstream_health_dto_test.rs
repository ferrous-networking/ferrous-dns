use ferrous_dns_api::dto::upstream::UpstreamGroupResponse;
use ferrous_dns_application::ports::{
    AggregateStatus, IpFamily, ResolvedEndpointHealth, UpstreamGroupHealth, UpstreamStatus,
};
use ferrous_dns_domain::UpstreamStrategy;
use serde_json::json;

fn endpoint(address: &str, family: IpFamily, no_route: bool) -> ResolvedEndpointHealth {
    ResolvedEndpointHealth {
        address: address.to_string(),
        family,
        status: if no_route {
            UpstreamStatus::Unhealthy
        } else {
            UpstreamStatus::Healthy
        },
        latency_ms: None,
        last_error: None,
        consecutive_failures: 0,
        no_route,
    }
}

#[test]
fn each_endpoint_says_whether_this_host_has_a_route_to_it() {
    let group = UpstreamGroupHealth {
        address: "tls://security.cloudflare-dns.com:853".to_string(),
        status: AggregateStatus::Healthy,
        resolved: vec![
            endpoint("1.1.1.2:853", IpFamily::Ipv4, false),
            endpoint("[2606:4700:4700::1112]:853", IpFamily::Ipv6, true),
        ],
        pool_name: "Encrypted".to_string(),
        strategy: UpstreamStrategy::Parallel,
    };

    let json = serde_json::to_value(UpstreamGroupResponse::from(group)).unwrap();

    assert_eq!(json["status"], json!("Healthy"));
    assert_eq!(json["resolved"][0]["no_route"], json!(false));
    assert_eq!(json["resolved"][1]["no_route"], json!(true));
    assert_eq!(json["resolved"][1]["family"], json!("ipv6"));
    assert_eq!(json["resolved"][1]["status"], json!("Unhealthy"));
}
