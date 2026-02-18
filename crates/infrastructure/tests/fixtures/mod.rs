#![allow(dead_code)]
#[allow(dead_code)]
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct DnsResponseFixture {
    pub domain: String,
    pub record_type: String,
    pub rcode: Option<String>,
    pub dnssec_status: Option<String>,
    pub answers: Vec<DnsAnswerFixture>,
    pub additional: Vec<DnsAnswerFixture>,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct DnsAnswerFixture {
    pub name: String,
    pub record_type: String,
    pub class: String,
    pub ttl: u32,
    pub priority: Option<u16>,
    pub data: String,
}

pub fn load_dns_fixtures() -> HashMap<String, DnsResponseFixture> {
    let mut fixtures = HashMap::new();

    fixtures.insert(
        "google_a_record".to_string(),
        DnsResponseFixture {
            domain: "google.com".to_string(),
            record_type: "A".to_string(),
            rcode: Some("NOERROR".to_string()),
            dnssec_status: None,
            answers: vec![DnsAnswerFixture {
                name: "google.com".to_string(),
                record_type: "A".to_string(),
                class: "IN".to_string(),
                ttl: 300,
                priority: None,
                data: "142.250.185.46".to_string(),
            }],
            additional: vec![],
            description: "Google A record response".to_string(),
        },
    );

    fixtures.insert(
        "cloudflare_aaaa_record".to_string(),
        DnsResponseFixture {
            domain: "cloudflare.com".to_string(),
            record_type: "AAAA".to_string(),
            rcode: Some("NOERROR".to_string()),
            dnssec_status: Some("secure".to_string()),
            answers: vec![DnsAnswerFixture {
                name: "cloudflare.com".to_string(),
                record_type: "AAAA".to_string(),
                class: "IN".to_string(),
                ttl: 300,
                priority: None,
                data: "2606:4700::6810:84e5".to_string(),
            }],
            additional: vec![],
            description: "Cloudflare AAAA record with DNSSEC".to_string(),
        },
    );

    fixtures.insert(
        "nxdomain_response".to_string(),
        DnsResponseFixture {
            domain: "nonexistent.invalid".to_string(),
            record_type: "A".to_string(),
            rcode: Some("NXDOMAIN".to_string()),
            dnssec_status: None,
            answers: vec![],
            additional: vec![],
            description: "NXDOMAIN response for non-existent domain".to_string(),
        },
    );

    fixtures
}

pub fn get_fixture(name: &str) -> Option<DnsResponseFixture> {
    let fixtures = load_dns_fixtures();
    fixtures.get(name).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_fixtures() {
        let fixtures = load_dns_fixtures();
        assert!(!fixtures.is_empty());
        assert!(fixtures.contains_key("google_a_record"));
    }

    #[test]
    fn test_get_fixture() {
        let fixture = get_fixture("google_a_record");
        assert!(fixture.is_some());

        let google = fixture.unwrap();
        assert_eq!(google.domain, "google.com");
        assert_eq!(google.record_type, "A");
        assert!(!google.answers.is_empty());
    }

    #[test]
    fn test_get_nonexistent_fixture() {
        let fixture = get_fixture("does_not_exist");
        assert!(fixture.is_none());
    }
}
