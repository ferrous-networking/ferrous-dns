use super::RecordCategory;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    PTR,

    SRV,
    SOA,
    NS,
    NAPTR,
    DS,
    DNSKEY,
    SVCB,
    HTTPS,

    CAA,
    TLSA,
    SSHFP,
    DNAME,

    RRSIG,
    NSEC,
    NSEC3,
    NSEC3PARAM,

    CDS,
    CDNSKEY,

    OPT,

    NULL,
    HINFO,
    WKS,

    IPSECKEY,
    OPENPGPKEY,

    ZONEMD,

    ANAME,
}

impl RecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::PTR => "PTR",
            RecordType::SRV => "SRV",
            RecordType::SOA => "SOA",
            RecordType::NS => "NS",
            RecordType::NAPTR => "NAPTR",
            RecordType::DS => "DS",
            RecordType::DNSKEY => "DNSKEY",
            RecordType::SVCB => "SVCB",
            RecordType::HTTPS => "HTTPS",
            RecordType::CAA => "CAA",
            RecordType::TLSA => "TLSA",
            RecordType::SSHFP => "SSHFP",
            RecordType::DNAME => "DNAME",
            RecordType::RRSIG => "RRSIG",
            RecordType::NSEC => "NSEC",
            RecordType::NSEC3 => "NSEC3",
            RecordType::NSEC3PARAM => "NSEC3PARAM",
            RecordType::CDS => "CDS",
            RecordType::CDNSKEY => "CDNSKEY",
            RecordType::OPT => "OPT",
            RecordType::NULL => "NULL",
            RecordType::HINFO => "HINFO",
            RecordType::WKS => "WKS",
            RecordType::IPSECKEY => "IPSECKEY",
            RecordType::OPENPGPKEY => "OPENPGPKEY",
            RecordType::ZONEMD => "ZONEMD",
            RecordType::ANAME => "ANAME",
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::NULL => 10,
            RecordType::WKS => 11,
            RecordType::PTR => 12,
            RecordType::HINFO => 13,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::NAPTR => 35,
            RecordType::DS => 43,
            RecordType::SSHFP => 44,
            RecordType::IPSECKEY => 45,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::DNSKEY => 48,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::TLSA => 52,
            RecordType::CDS => 59,
            RecordType::CDNSKEY => 60,
            RecordType::OPENPGPKEY => 61,
            RecordType::SVCB => 64,
            RecordType::HTTPS => 65,
            RecordType::ZONEMD => 63,
            RecordType::CAA => 257,
            RecordType::ANAME => 32769,
            RecordType::DNAME => 39,
            RecordType::OPT => 41,
        }
    }

    pub fn from_u16(code: u16) -> Option<Self> {
        match code {
            1 => Some(RecordType::A),
            2 => Some(RecordType::NS),
            5 => Some(RecordType::CNAME),
            6 => Some(RecordType::SOA),
            10 => Some(RecordType::NULL),
            11 => Some(RecordType::WKS),
            12 => Some(RecordType::PTR),
            13 => Some(RecordType::HINFO),
            15 => Some(RecordType::MX),
            16 => Some(RecordType::TXT),
            28 => Some(RecordType::AAAA),
            33 => Some(RecordType::SRV),
            35 => Some(RecordType::NAPTR),
            39 => Some(RecordType::DNAME),
            41 => Some(RecordType::OPT),
            43 => Some(RecordType::DS),
            44 => Some(RecordType::SSHFP),
            45 => Some(RecordType::IPSECKEY),
            46 => Some(RecordType::RRSIG),
            47 => Some(RecordType::NSEC),
            48 => Some(RecordType::DNSKEY),
            50 => Some(RecordType::NSEC3),
            51 => Some(RecordType::NSEC3PARAM),
            52 => Some(RecordType::TLSA),
            59 => Some(RecordType::CDS),
            60 => Some(RecordType::CDNSKEY),
            61 => Some(RecordType::OPENPGPKEY),
            63 => Some(RecordType::ZONEMD),
            64 => Some(RecordType::SVCB),
            65 => Some(RecordType::HTTPS),
            257 => Some(RecordType::CAA),
            32769 => Some(RecordType::ANAME),
            _ => None,
        }
    }

    pub fn category(&self) -> RecordCategory {
        match self {
            RecordType::A
            | RecordType::AAAA
            | RecordType::CNAME
            | RecordType::MX
            | RecordType::TXT
            | RecordType::PTR => RecordCategory::Basic,

            RecordType::SRV
            | RecordType::SOA
            | RecordType::NS
            | RecordType::NAPTR
            | RecordType::SVCB
            | RecordType::HTTPS
            | RecordType::DNAME
            | RecordType::ANAME => RecordCategory::Advanced,

            RecordType::DS
            | RecordType::DNSKEY
            | RecordType::RRSIG
            | RecordType::NSEC
            | RecordType::NSEC3
            | RecordType::NSEC3PARAM
            | RecordType::CDS
            | RecordType::CDNSKEY => RecordCategory::Dnssec,

            RecordType::CAA
            | RecordType::TLSA
            | RecordType::SSHFP
            | RecordType::IPSECKEY
            | RecordType::OPENPGPKEY => RecordCategory::Security,

            RecordType::NULL | RecordType::HINFO | RecordType::WKS => RecordCategory::Legacy,

            RecordType::OPT => RecordCategory::Protocol,

            RecordType::ZONEMD => RecordCategory::Integrity,
        }
    }

    pub fn is_dnssec(&self) -> bool {
        matches!(self.category(), RecordCategory::Dnssec)
    }

    pub fn is_basic(&self) -> bool {
        matches!(self.category(), RecordCategory::Basic)
    }

    pub fn is_security_related(&self) -> bool {
        matches!(
            self.category(),
            RecordCategory::Security | RecordCategory::Dnssec
        )
    }

    pub fn is_modern(&self) -> bool {
        matches!(
            self,
            RecordType::SVCB | RecordType::HTTPS | RecordType::ZONEMD
        )
    }

    pub fn by_category(category: RecordCategory) -> Vec<RecordType> {
        use RecordType::*;
        match category {
            RecordCategory::Basic => vec![A, AAAA, CNAME, MX, TXT, PTR],
            RecordCategory::Advanced => vec![SRV, SOA, NS, NAPTR, SVCB, HTTPS, DNAME, ANAME],
            RecordCategory::Dnssec => {
                vec![DS, DNSKEY, RRSIG, NSEC, NSEC3, NSEC3PARAM, CDS, CDNSKEY]
            }
            RecordCategory::Security => vec![CAA, TLSA, SSHFP, IPSECKEY, OPENPGPKEY],
            RecordCategory::Legacy => vec![NULL, HINFO, WKS],
            RecordCategory::Protocol => vec![OPT],
            RecordCategory::Integrity => vec![ZONEMD],
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for RecordType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "CNAME" => Ok(RecordType::CNAME),
            "MX" => Ok(RecordType::MX),
            "TXT" => Ok(RecordType::TXT),
            "PTR" => Ok(RecordType::PTR),
            "SRV" => Ok(RecordType::SRV),
            "SOA" => Ok(RecordType::SOA),
            "NS" => Ok(RecordType::NS),
            "NAPTR" => Ok(RecordType::NAPTR),
            "DS" => Ok(RecordType::DS),
            "DNSKEY" => Ok(RecordType::DNSKEY),
            "SVCB" => Ok(RecordType::SVCB),
            "HTTPS" => Ok(RecordType::HTTPS),
            "CAA" => Ok(RecordType::CAA),
            "TLSA" => Ok(RecordType::TLSA),
            "SSHFP" => Ok(RecordType::SSHFP),
            "DNAME" => Ok(RecordType::DNAME),
            "RRSIG" => Ok(RecordType::RRSIG),
            "NSEC" => Ok(RecordType::NSEC),
            "NSEC3" => Ok(RecordType::NSEC3),
            "NSEC3PARAM" => Ok(RecordType::NSEC3PARAM),
            "CDS" => Ok(RecordType::CDS),
            "CDNSKEY" => Ok(RecordType::CDNSKEY),
            "OPT" => Ok(RecordType::OPT),
            "NULL" => Ok(RecordType::NULL),
            "HINFO" => Ok(RecordType::HINFO),
            "WKS" => Ok(RecordType::WKS),
            "IPSECKEY" => Ok(RecordType::IPSECKEY),
            "OPENPGPKEY" => Ok(RecordType::OPENPGPKEY),
            "ZONEMD" => Ok(RecordType::ZONEMD),
            "ANAME" => Ok(RecordType::ANAME),
            _ => Err(format!("Unknown record type: {}", s)),
        }
    }
}
