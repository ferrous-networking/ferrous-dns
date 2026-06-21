use ferrous_dns_domain::DomainError;

#[test]
fn spoofed_response_display_includes_server_and_reason() {
    let err = DomainError::SpoofedResponse {
        server: "8.8.8.8:53".into(),
        reason: "client cookie echo mismatch".into(),
    };
    let msg = err.to_string();
    assert!(msg.contains("8.8.8.8:53"), "missing server: {msg}");
    assert!(
        msg.contains("client cookie echo mismatch"),
        "missing reason: {msg}"
    );
}
