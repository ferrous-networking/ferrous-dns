//! When the certificates the TLS listeners loaded at start expire.

use std::sync::OnceLock;

/// A listener that serves a certificate of its own. DoH has none: it is plain
/// HTTP, behind the web listener or a reverse proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsListener {
    Web,
    Dot,
    Doq,
}

impl TlsListener {
    pub const ALL: [TlsListener; 3] = [Self::Web, Self::Dot, Self::Doq];

    pub fn label(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Dot => "dot",
            Self::Doq => "doq",
        }
    }
}

/// Written once per listener, when it loads its certificate. Certificates are
/// read only at start, so this is what is served until the next restart, even
/// when a newer certificate is already on disk.
#[derive(Debug, Default)]
pub struct LoadedCertificates {
    not_after: [OnceLock<i64>; TlsListener::ALL.len()],
}

impl LoadedCertificates {
    /// Records the `notAfter`, in Unix seconds, of the certificate `listener`
    /// serves; a second record for the same listener is ignored.
    pub fn record(&self, listener: TlsListener, not_after: i64) {
        let _ = self.not_after[listener as usize].set(not_after);
    }

    pub fn not_after(&self, listener: TlsListener) -> Option<i64> {
        self.not_after[listener as usize].get().copied()
    }

    /// Every listener that loaded a certificate, in [`TlsListener::ALL`] order.
    pub fn expiries(&self) -> Vec<(TlsListener, i64)> {
        TlsListener::ALL
            .into_iter()
            .filter_map(|listener| Some((listener, self.not_after(listener)?)))
            .collect()
    }
}
