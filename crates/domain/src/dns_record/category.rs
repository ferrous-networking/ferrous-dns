use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordCategory {
    
    Basic,
    
    Advanced,
    
    Dnssec,
    
    Security,
    
    Legacy,
    
    Protocol,
    
    Integrity,
}

impl RecordCategory {
    
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
