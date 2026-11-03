use arc_swap::{ArcSwap, Guard};
use ferrous_dns_domain::{ClientProtocol, DnsCookiesConfig};
use ring::hmac;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const CLIENT_COOKIE_LEN: usize = 8;
const SERVER_COOKIE_LEN: usize = 8;
/// Keeps the window keys apart from any other use of the secret.
const WINDOW_KEY_LABEL: &[u8] = b"ferrous-dns cookie window";

/// RFC 7873 DNS Cookie verifier and server-cookie generator.
///
/// With `secret_rotation_secs` set, each rotation window signs with its own
/// key, derived from the secret and the window's number on the Unix clock, so
/// servers sharing `server_secret` with synced clocks derive the same keys. A
/// cookie is accepted in the window that issued it and in the next one.
pub struct DnsCookieGuard {
    /// `[dns_cookies] enabled && require_valid_cookie`: refuse queries without a valid server cookie.
    strict: bool,
    /// Signs every cookie when rotation is off; derives the window keys otherwise.
    secret: hmac::Key,
    /// 0 when the secret never rotates.
    rotation_secs: u64,
    /// Unix time in seconds.
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    /// The keys of the last window a lookup saw, replaced by the first lookup
    /// in a new one. Lookups that race to replace them derive the same keys.
    keys: ArcSwap<WindowKeys>,
}

struct WindowKeys {
    window: u64,
    current: hmac::Key,
    /// `None` when rotation is off, or before the first window.
    previous: Option<hmac::Key>,
}

impl DnsCookieGuard {
    pub fn from_config(config: &DnsCookiesConfig, secret: [u8; 32]) -> Self {
        let secret = hmac::Key::new(hmac::HMAC_SHA256, &secret);
        let rotation_secs = config.secret_rotation_secs;
        let keys = window_keys(&secret, rotation_secs, window_at(unix_now(), rotation_secs));
        Self {
            strict: config.enabled && config.require_valid_cookie,
            secret,
            rotation_secs,
            clock: Box::new(unix_now),
            keys: ArcSwap::from_pointee(keys),
        }
    }

    /// Reads the time, in Unix seconds, from `clock` instead of the system clock.
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    pub(super) fn is_strict(&self) -> bool {
        self.strict
    }

    /// Whether a query over `protocol` must carry a valid server cookie: in
    /// strict mode, over UDP. A TCP, TLS or QUIC handshake already proves the
    /// client's address, which is all the cookie proves (RFC 7873 §5.2.3).
    /// `None`, a request from no listener, is held to the UDP rule.
    pub(super) fn requires_cookie(&self, protocol: Option<ClientProtocol>) -> bool {
        self.strict && !protocol.is_some_and(ClientProtocol::is_stream)
    }

    /// Whether EDNS option-10 data carries a server cookie this server issued to `client_ip`.
    ///
    /// A bare client cookie (bootstrapping) or malformed data is not valid: RFC 7873 §5.2.3
    /// requires strict servers to refuse both.
    pub(super) fn has_valid_cookie(&self, client_ip: IpAddr, opt_data: &[u8]) -> bool {
        let (Some(client_cookie), Some(received)) = (
            opt_data.get(..CLIENT_COOKIE_LEN),
            opt_data.get(CLIENT_COOKIE_LEN..CLIENT_COOKIE_LEN + SERVER_COOKIE_LEN),
        ) else {
            return false;
        };
        // `hmac::verify` needs the full 32-byte tag; the server cookie is truncated to 8 bytes.
        let is_signed_by = |key: &hmac::Key| {
            subtle_eq(
                &compute_server_cookie(key, client_ip, client_cookie),
                received,
            )
        };
        let keys = self.keys();
        is_signed_by(&keys.current) || keys.previous.as_ref().is_some_and(is_signed_by)
    }

    /// Generates the 8-byte server cookie to include in responses.
    pub fn generate_server_cookie(
        &self,
        client_ip: IpAddr,
        client_cookie: &[u8; CLIENT_COOKIE_LEN],
    ) -> [u8; SERVER_COOKIE_LEN] {
        compute_server_cookie(&self.keys().current, client_ip, client_cookie)
    }

    /// The keys of the current rotation window.
    fn keys(&self) -> Guard<Arc<WindowKeys>> {
        let keys = self.keys.load();
        if self.rotation_secs == 0 {
            return keys;
        }
        let window = window_at((self.clock)(), self.rotation_secs);
        if keys.window == window {
            return keys;
        }
        let fresh = Arc::new(window_keys(&self.secret, self.rotation_secs, window));
        self.keys.store(Arc::clone(&fresh));
        Guard::from_inner(fresh)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn window_at(unix_secs: u64, rotation_secs: u64) -> u64 {
    unix_secs.checked_div(rotation_secs).unwrap_or(0)
}

fn window_keys(secret: &hmac::Key, rotation_secs: u64, window: u64) -> WindowKeys {
    if rotation_secs == 0 {
        return WindowKeys {
            window,
            current: secret.clone(),
            previous: None,
        };
    }
    WindowKeys {
        window,
        current: window_key(secret, window),
        previous: window
            .checked_sub(1)
            .map(|previous| window_key(secret, previous)),
    }
}

/// `HMAC-SHA256(secret, label ‖ window)`, the key that signs `window`'s cookies.
fn window_key(secret: &hmac::Key, window: u64) -> hmac::Key {
    let mut input = [0u8; WINDOW_KEY_LABEL.len() + 8];
    input[..WINDOW_KEY_LABEL.len()].copy_from_slice(WINDOW_KEY_LABEL);
    input[WINDOW_KEY_LABEL.len()..].copy_from_slice(&window.to_be_bytes());
    hmac::Key::new(hmac::HMAC_SHA256, hmac::sign(secret, &input).as_ref())
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

    fn guard_enabled() -> DnsCookieGuard {
        let config = DnsCookiesConfig {
            enabled: true,
            require_valid_cookie: true,
            ..Default::default()
        };
        DnsCookieGuard::from_config(&config, [0x42u8; 32])
    }

    fn valid_cookie_bytes(guard: &DnsCookieGuard, client_ip: IpAddr) -> Vec<u8> {
        let client_cookie = [0x01u8; 8];
        let server_cookie = guard.generate_server_cookie(client_ip, &client_cookie);
        [client_cookie, server_cookie].concat()
    }

    #[test]
    fn accepts_cookie_when_hmac_matches() {
        let guard = guard_enabled();
        assert!(guard.has_valid_cookie(CLIENT_IP_V4, &valid_cookie_bytes(&guard, CLIENT_IP_V4)));
        assert!(guard.has_valid_cookie(CLIENT_IP_V6, &valid_cookie_bytes(&guard, CLIENT_IP_V6)));
    }

    #[test]
    fn rejects_cookie_when_hmac_mismatches() {
        let guard = guard_enabled();
        let mut opt_data = valid_cookie_bytes(&guard, CLIENT_IP_V4);
        opt_data[8] ^= 0xFF;
        assert!(!guard.has_valid_cookie(CLIENT_IP_V4, &opt_data));
    }

    #[test]
    fn rejects_bare_client_cookie_and_malformed_data() {
        let guard = guard_enabled();
        assert!(!guard.has_valid_cookie(CLIENT_IP_V4, &[0xABu8; 8]));
        assert!(!guard.has_valid_cookie(CLIENT_IP_V4, &[0x01u8; 3]));
        assert!(!guard.has_valid_cookie(CLIENT_IP_V4, &[]));
    }

    #[test]
    fn rejects_truncated_server_cookie() {
        let guard = guard_enabled();
        assert!(!guard.has_valid_cookie(CLIENT_IP_V4, &[0x01u8; 12]));
    }

    #[test]
    fn rejects_cookie_issued_to_another_ip() {
        let guard = guard_enabled();
        let opt_data = valid_cookie_bytes(&guard, CLIENT_IP_V4);
        assert!(!guard.has_valid_cookie(CLIENT_IP_V6, &opt_data));
    }

    #[test]
    fn strict_only_when_enabled_and_required() {
        let config = |enabled, require_valid_cookie| DnsCookiesConfig {
            enabled,
            require_valid_cookie,
            ..Default::default()
        };
        assert!(DnsCookieGuard::from_config(&config(true, true), [0; 32]).is_strict());
        assert!(!DnsCookieGuard::from_config(&config(true, false), [0; 32]).is_strict());
        assert!(!DnsCookieGuard::from_config(&config(false, true), [0; 32]).is_strict());
    }

    #[test]
    fn strict_mode_requires_a_cookie_over_udp_only() {
        let strict = guard_enabled();
        assert!(strict.requires_cookie(Some(ClientProtocol::Udp)));
        assert!(strict.requires_cookie(None));
        for protocol in [
            ClientProtocol::Tcp,
            ClientProtocol::Dot,
            ClientProtocol::Doh,
            ClientProtocol::Doq,
        ] {
            assert!(!strict.requires_cookie(Some(protocol)), "{protocol}");
        }

        let permissive = DnsCookieGuard::from_config(&DnsCookiesConfig::default(), [0; 32]);
        assert!(!permissive.requires_cookie(Some(ClientProtocol::Udp)));
    }
}
