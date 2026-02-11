use std::fmt;

/// Categories for DNS record types following Clean Architecture principles
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordCategory {
    /// Basic DNS records (A, AAAA, CNAME, MX, TXT, PTR)
    Basic,
    /// Advanced DNS records (SRV, SOA, NS, NAPTR, SVCB, HTTPS, DNAME, ANAME)
    Advanced,
    /// DNSSEC-related records (DS, DNSKEY, RRSIG, NSEC, NSEC3, etc.)
    Dnssec,
    /// Security and cryptography records (CAA, TLSA, SSHFP, IPSECKEY, OPENPGPKEY)
    Security,
    /// Legacy/informational records (NULL, HINFO, WKS)
    Legacy,
    /// Protocol support (OPT for EDNS0)
    Protocol,
    /// Zone integrity (ZONEMD)
    Integrity,
}

impl RecordCategory {
    /// Returns a human-readable name for the category
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordCategory::Basic => "basic",
            RecordCategory::Advanced => "advanced",
            RecordCategory::Dnssec => "dnssec",
            RecordCategory::Security => "security",
            RecordCategory::Legacy => "legacy",
            RecordCategory::Protocol => "protocol",
            RecordCategory::Integrity => "integrity",
        }
    }

    /// Returns a descriptive label for the category
    pub fn label(&self) -> &'static str {
        match self {
            RecordCategory::Basic => "Basic DNS Records",
            RecordCategory::Advanced => "Advanced DNS Records",
            RecordCategory::Dnssec => "DNSSEC Records",
            RecordCategory::Security => "Security & Cryptography",
            RecordCategory::Legacy => "Legacy Records",
            RecordCategory::Protocol => "Protocol Support",
            RecordCategory::Integrity => "Zone Integrity",
        }
    }

    /// Get all categories
    pub fn all() -> &'static [RecordCategory] {
        &[
            RecordCategory::Basic,
            RecordCategory::Advanced,
            RecordCategory::Dnssec,
            RecordCategory::Security,
            RecordCategory::Legacy,
            RecordCategory::Protocol,
            RecordCategory::Integrity,
        ]
    }
}

impl fmt::Display for RecordCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_category_as_str() {
        assert_eq!(RecordCategory::Basic.as_str(), "basic");
        assert_eq!(RecordCategory::Dnssec.as_str(), "dnssec");
    }

    #[test]
    fn test_category_label() {
        assert_eq!(RecordCategory::Basic.label(), "Basic DNS Records");
        assert_eq!(RecordCategory::Security.label(), "Security & Cryptography");
    }

    #[test]
    fn test_category_all() {
        let all = RecordCategory::all();
        assert_eq!(all.len(), 7);
        assert!(all.contains(&RecordCategory::Basic));
        assert!(all.contains(&RecordCategory::Dnssec));
    }
}
