use ferrous_dns_domain::DnsCookiesConfig;
use ring::hmac;
use std::net::IpAddr;

const CLIENT_COOKIE_LEN: usize = 8;
const SERVER_COOKIE_LEN: usize = 8;

pub(super) enum CookieVerdict {
    /// Cookie is present and HMAC-verified.
    Valid,
    /// Client sent only its 8-byte client cookie (bootstrapping handshake).
    /// The server should respond normally and include a fresh server cookie.
    NoCookie,
    /// Cookie data is malformed or HMAC verification failed.
    Invalid,
}

pub struct DnsCookieGuard {
    enabled: bool,
    require_valid: bool,
    current_secret: hmac::Key,
    pub(super) previous_secret: Option<hmac::Key>,
}

impl DnsCookieGuard {
    pub fn disabled() -> Self {
        // Safety: a zero key is never used for real verification since
        // `enabled` gates every call to `check`.
        let dummy = hmac::Key::new(hmac::HMAC_SHA256, &[0u8; 32]);
        Self {
            enabled: false,
            require_valid: false,
            current_secret: dummy,
            previous_secret: None,
        }
    }

    pub fn from_config(config: &DnsCookiesConfig, secret: [u8; 32]) -> Self {
        Self {
            enabled: config.enabled,
            require_valid: config.require_valid_cookie,
            current_secret: hmac::Key::new(hmac::HMAC_SHA256, &secret),
            previous_secret: None,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn requires_valid_cookie(&self) -> bool {
        self.require_valid
    }

    /// Evaluates the EDNS option-10 data sent by the client.
    ///
    /// - `opt_data` is the raw bytes of EDNS option code 10.
    /// - Returns `NoCookie` when the client sent only its 8-byte client
    ///   cookie (bootstrapping); `Valid` when the full 16-byte cookie passes
    ///   HMAC verification; `Invalid` otherwise.
    pub(super) fn check(&self, client_ip: IpAddr, opt_data: &[u8]) -> CookieVerdict {
        if !self.enabled {
            return CookieVerdict::NoCookie;
        }

        if opt_data.len() < CLIENT_COOKIE_LEN {
            // Malformed: less than a client cookie.
            return CookieVerdict::Invalid;
        }

        if opt_data.len() == CLIENT_COOKIE_LEN {
            // Only the client cookie present — normal bootstrapping.
            return CookieVerdict::NoCookie;
        }

        // Full cookie: client[0..8] + server[8..16] (at minimum).
        let client_cookie = &opt_data[..CLIENT_COOKIE_LEN];
        let server_cookie_received =
            &opt_data[CLIENT_COOKIE_LEN..CLIENT_COOKIE_LEN + SERVER_COOKIE_LEN];

        if self.verify_server_cookie(
            client_ip,
            client_cookie,
            server_cookie_received,
            &self.current_secret,
        ) {
            return CookieVerdict::Valid;
        }

        if let Some(ref prev) = self.previous_secret {
            if self.verify_server_cookie(client_ip, client_cookie, server_cookie_received, prev) {
                return CookieVerdict::Valid;
            }
        }

        CookieVerdict::Invalid
    }

    fn verify_server_cookie(
        &self,
        client_ip: IpAddr,
        client_cookie: &[u8],
        received: &[u8],
        key: &hmac::Key,
    ) -> bool {
        // Recompute the expected 8-byte server cookie and compare in constant
        // time. `hmac::verify` expects a full 32-byte HMAC tag and cannot be
        // used here — the stored server cookie is already truncated to 8 bytes.
        let expected = compute_server_cookie(key, client_ip, client_cookie);
        subtle_eq(&expected, received)
    }

    /// Generates the 8-byte server cookie to include in responses.
    pub fn generate_server_cookie(
        &self,
        client_ip: IpAddr,
        client_cookie: &[u8; CLIENT_COOKIE_LEN],
    ) -> [u8; SERVER_COOKIE_LEN] {
        compute_server_cookie(&self.current_secret, client_ip, client_cookie)
    }
}

/// Builds the HMAC input: IP bytes (4 or 16) followed by the client cookie (8 bytes).
///
/// The maximum size is 16 + 8 = 24 bytes, so a fixed-size stack buffer avoids
/// any heap allocation on the hot path.
fn build_hmac_input(client_ip: IpAddr, client_cookie: &[u8]) -> ([u8; 24], usize) {
    let mut buf = [0u8; 24];
    let ip_len = match client_ip {
        IpAddr::V4(v4) => {
            buf[..4].copy_from_slice(&v4.octets());
            4
        }
        IpAddr::V6(v6) => {
            buf[..16].copy_from_slice(&v6.octets());
            16
        }
    };
    buf[ip_len..ip_len + client_cookie.len()].copy_from_slice(client_cookie);
    (buf, ip_len + client_cookie.len())
}

fn compute_server_cookie(
    key: &hmac::Key,
    client_ip: IpAddr,
    client_cookie: &[u8],
) -> [u8; SERVER_COOKIE_LEN] {
    let (buf, len) = build_hmac_input(client_ip, client_cookie);
    let tag = hmac::sign(key, &buf[..len]);
    let bytes = tag.as_ref();
    let mut out = [0u8; SERVER_COOKIE_LEN];
    out.copy_from_slice(&bytes[..SERVER_COOKIE_LEN]);
    out
}

/// Constant-time equality for two byte slices of the same length.
fn subtle_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const CLIENT_IP_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    const CLIENT_IP_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    fn secret() -> [u8; 32] {
        [0x42u8; 32]
    }

    fn guard_enabled() -> DnsCookieGuard {
        let config = DnsCookiesConfig {
            enabled: true,
            require_valid_cookie: true,
            ..Default::default()
        };
        DnsCookieGuard::from_config(&config, secret())
    }

    fn valid_cookie_bytes(guard: &DnsCookieGuard, client_ip: IpAddr) -> Vec<u8> {
        let client_cookie = [0x01u8; 8];
        let server_cookie = guard.generate_server_cookie(client_ip, &client_cookie);
        let mut data = Vec::with_capacity(16);
        data.extend_from_slice(&client_cookie);
        data.extend_from_slice(&server_cookie);
        data
    }

    #[test]
    fn should_return_valid_when_hmac_matches() {
        let guard = guard_enabled();
        let opt_data = valid_cookie_bytes(&guard, CLIENT_IP_V4);
        assert!(matches!(
            guard.check(CLIENT_IP_V4, &opt_data),
            CookieVerdict::Valid
        ));
    }

    #[test]
    fn should_return_invalid_when_hmac_mismatches() {
        let guard = guard_enabled();
        let mut opt_data = valid_cookie_bytes(&guard, CLIENT_IP_V4);
        // Flip one bit in the server cookie portion.
        opt_data[8] ^= 0xFF;
        assert!(matches!(
            guard.check(CLIENT_IP_V4, &opt_data),
            CookieVerdict::Invalid
        ));
    }

    #[test]
    fn should_return_no_cookie_when_only_client_cookie_present() {
        let guard = guard_enabled();
        let opt_data = [0xABu8; 8].to_vec();
        assert!(matches!(
            guard.check(CLIENT_IP_V4, &opt_data),
            CookieVerdict::NoCookie
        ));
    }

    #[test]
    fn should_return_invalid_when_opt_data_malformed() {
        let guard = guard_enabled();
        let opt_data = [0x01u8; 3].to_vec(); // < 8 bytes
        assert!(matches!(
            guard.check(CLIENT_IP_V4, &opt_data),
            CookieVerdict::Invalid
        ));
    }

    #[test]
    fn should_accept_previous_secret_during_rotation() {
        let config = DnsCookiesConfig {
            enabled: true,
            require_valid_cookie: true,
            ..Default::default()
        };
        let old_secret = [0x11u8; 32];
        let new_secret = [0x22u8; 32];

        // Build a cookie with the old secret.
        let old_guard = DnsCookieGuard::from_config(&config, old_secret);
        let client_cookie = [0xCCu8; 8];
        let server_cookie_from_old = old_guard.generate_server_cookie(CLIENT_IP_V4, &client_cookie);
        let mut opt_data = Vec::with_capacity(16);
        opt_data.extend_from_slice(&client_cookie);
        opt_data.extend_from_slice(&server_cookie_from_old);

        // Create a new guard that has rotated to new_secret but retains old_secret.
        let mut new_guard = DnsCookieGuard::from_config(&config, new_secret);
        new_guard.previous_secret = Some(hmac::Key::new(hmac::HMAC_SHA256, &old_secret));

        assert!(matches!(
            new_guard.check(CLIENT_IP_V4, &opt_data),
            CookieVerdict::Valid
        ));
    }

    #[test]
    fn should_return_no_cookie_when_guard_disabled() {
        let guard = DnsCookieGuard::disabled();
        // Even a malformed input returns NoCookie when disabled.
        assert!(matches!(
            guard.check(CLIENT_IP_V4, &[]),
            CookieVerdict::NoCookie
        ));
        assert!(matches!(
            guard.check(CLIENT_IP_V4, &[1, 2, 3]),
            CookieVerdict::NoCookie
        ));
    }

    #[test]
    fn should_return_valid_for_ipv6_client() {
        let guard = guard_enabled();
        let opt_data = valid_cookie_bytes(&guard, CLIENT_IP_V6);
        assert!(matches!(
            guard.check(CLIENT_IP_V6, &opt_data),
            CookieVerdict::Valid
        ));
    }

    #[test]
    fn should_return_invalid_when_cookie_from_wrong_ip() {
        let guard = guard_enabled();
        let opt_data = valid_cookie_bytes(&guard, CLIENT_IP_V4);
        // Present the cookie to a different IP — HMAC should not verify.
        assert!(matches!(
            guard.check(CLIENT_IP_V6, &opt_data),
            CookieVerdict::Invalid
        ));
    }
}
