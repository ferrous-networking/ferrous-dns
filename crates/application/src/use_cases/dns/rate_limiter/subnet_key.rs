use std::net::IpAddr;

/// Compact register-sized key for subnet-based rate limiting.
///
/// Bit 63 distinguishes IPv4 (0) from IPv6 (1). The remaining 63 bits store
/// the masked network prefix, giving zero-allocation hashing and comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SubnetKey(u64);

impl SubnetKey {
    /// Creates a subnet key by masking `ip` with the configured prefix lengths.
    #[inline]
    pub(crate) fn from_ip(ip: IpAddr, v4_prefix: u8, v6_prefix: u8) -> Self {
        match ip {
            IpAddr::V4(v4) => {
                let bits = u32::from(v4);
                let shift = 32u8.saturating_sub(v4_prefix.min(32));
                let masked = (bits >> shift) as u64;
                Self(masked)
            }
            IpAddr::V6(v6) => {
                let bits = u128::from(v6);
                let prefix = v6_prefix.min(64) as u32;
                let shifted = (bits >> 64) as u64;
                let shift = 64u32.saturating_sub(prefix);
                let masked = shifted >> shift;
                Self(masked | (1u64 << 63))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn subnet_key_groups_ipv4_same_slash24() {
        let a = SubnetKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24, 56);
        let b = SubnetKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)), 24, 56);
        assert_eq!(a, b);
    }

    #[test]
    fn subnet_key_separates_different_subnets() {
        let a = SubnetKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24, 56);
        let b = SubnetKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 10)), 24, 56);
        assert_ne!(a, b);
    }

    #[test]
    fn subnet_key_ipv6_groups_same_prefix() {
        let a = SubnetKey::from_ip(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xab, 0xcd00, 0, 0, 0, 1)),
            24,
            56,
        );
        let b = SubnetKey::from_ip(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0xab, 0xcdff, 0, 0, 0, 9)),
            24,
            56,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn subnet_key_ipv4_and_ipv6_differ() {
        let v4 = SubnetKey::from_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 24, 56);
        let v6 = SubnetKey::from_ip(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 24, 56);
        assert_ne!(v4, v6);
    }
}
