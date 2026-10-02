pub mod dnskey;
pub mod ds;

pub use dnskey::DnskeyRecord;
pub use ds::{DsDenial, DsLookup, DsRecord};

/// IANA mnemonic of a DNSSEC signature algorithm number, for log output.
pub fn algorithm_name(algorithm: u8) -> &'static str {
    match algorithm {
        5 => "RSA/SHA-1",
        7 => "RSA/SHA-1-NSEC3",
        8 => "RSA/SHA-256",
        10 => "RSA/SHA-512",
        13 => "ECDSA P-256/SHA-256",
        14 => "ECDSA P-384/SHA-384",
        15 => "Ed25519",
        16 => "Ed448",
        _ => "Unknown",
    }
}
